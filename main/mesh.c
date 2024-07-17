#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/cdefs.h>

#include "esp_attr.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_ieee802154.h"
#include "esp_ieee802154_types.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "portmacro.h"

#define MI_FRAME_TYPE_ID_REQ   (0b000 << 0)
#define MI_FRAME_TYPE_ID       (0b001 << 0)
#define MI_FRAME_TYPE_BLINK    (0b010 << 0)
#define MI_FRAME_TYPE_MASK     0x07

#define IEEE802154_FRAME_TYPE_BEACON    (0b000 << 0)
#define IEEE802154_FRAME_TYPE_DATA      (0b001 << 0)
#define IEEE802154_FRAME_TYPE_ACK       (0b010 << 0)
#define IEEE802154_FRAME_TYPE_CMD       (0b011 << 0)
#define IEEE802154_FRAME_TYPE_MASK      0x0007

#define IEEE802154_SEC_ENABLED          (1 << 3)
#define IEEE802154_FRAME_PENDING        (1 << 4)
#define IEEE802154_ACK_REQ              (1 << 5)
#define IEEE802154_PAN_ID_COMPRESSION   (1 << 6)

#define IEEE802154_DST_ADDR_MODE_NONE           (0b00 << 10)
#define IEEE802154_DST_ADDR_MODE_ONLY_SHORT     (0b10 << 10)
#define IEEE802154_DST_ADDR_MODE_ONLY_EXT       (0b11 << 10)
#define IEEE802154_DST_ADDR_MODE_MASK           0x0C00

#define IEEE802154_FRAME_VER_2003       (0b00 << 12)
#define IEEE802154_FRAME_VER_2006       (0b01 << 12)
#define IEEE802154_FRAME_VER_MASK       0x3000

#define IEEE802154_SRC_ADDR_MODE_NONE           (0b00 << 14)
#define IEEE802154_SRC_ADDR_MODE_ONLY_SHORT     (0b10 << 14)
#define IEEE802154_SRC_ADDR_MODE_ONLY_EXT       (0b11 << 14)
#define IEEE802154_SRC_ADDR_MODE_MASK           0xC000

#define IEEE802154_DST_PAN_ID_BROADCAST         0xFFFF
#define IEEE802154_DST_ADDR_BROADCAST           0xFFFF

#define MHR_SIZE 11
#define PAYLOAD_SIZE 114
#define FRAME_SIZE (MHR_SIZE + PAYLOAD_SIZE + 2)

typedef struct __attribute__((packed)) {
    struct __attribute__((packed)) {
        uint16_t frame_control;
        uint8_t  seq_num;
        uint16_t dst_pan_id;
        uint16_t dst_addr;
        uint16_t src_pan_id;
        uint16_t src_addr;
    } mhr;
    uint8_t  payload[PAYLOAD_SIZE];
    uint16_t fcs;
} ieee802154_frame_t;

#define CIRC_BUF_SIZE 255

typedef struct {
    uint16_t buf[CIRC_BUF_SIZE];
    uint8_t pos;
} circ_buf_t;

typedef struct {
    uint8_t mac_addr[8];
    bool isolated;
    union {
        uint16_t pan_id;
        uint16_t addr;
    };
} node_lookup_t;

#define LOOKUP_TABLE_SIZE 16

typedef struct {
    node_lookup_t records[LOOKUP_TABLE_SIZE];
    uint8_t len;
} lookup_table_t;

const static char *TAG = "MESH";

static uint16_t node_pan_id = 0x0000;
static uint16_t node_addr   = 0x0001;

static bool isolated = true;

static QueueHandle_t tx_queue = NULL;
static QueueHandle_t rx_queue = NULL;

static circ_buf_t rx_list = {
    .buf = { 0 },
    .pos = 0,
};

static circ_buf_t relay_list = {
    .buf = { 0 },
    .pos = 0,
};

static lookup_table_t lookup_table = {
    .len = 0,
};

static void circ_buf_push(circ_buf_t *cb, uint16_t v) {
    cb->buf[cb->pos] = v;
    cb->pos = (cb->pos + 1) % CIRC_BUF_SIZE;
}

static bool circ_buf_match(circ_buf_t *cb, uint16_t v) {
    for (size_t i = 0; i < CIRC_BUF_SIZE; i++) {
        size_t idx = (cb->pos - 1 - i + CIRC_BUF_SIZE) % CIRC_BUF_SIZE;
        if (cb->buf[idx] == 0) {
            break;
        }
        if (cb->buf[idx] == v) {
            return true;
        }
    }
    return false;
}

static int lookup_table_find_idx(uint8_t mac_addr[8]) {
    for (uint8_t i = 0; i < lookup_table.len; i++) {
        bool match = memcmp(lookup_table.records[i].mac_addr, mac_addr, 8) == 0;
        if (match) {
            return i;
        }
    }
    return -1;
}

static bool lookup_table_add(node_lookup_t *entry) {
    if (lookup_table.len == LOOKUP_TABLE_SIZE) {
        return false;
    }
    lookup_table.records[lookup_table.len] = *entry;
    lookup_table.len++;
    return true;
}

static void log_proto_state(esp_log_level_t level) {
    const char *state_str;

    switch (esp_ieee802154_get_state()) {
    case ESP_IEEE802154_RADIO_DISABLE:
        state_str = "disable";
        break;
    case ESP_IEEE802154_RADIO_IDLE:
        state_str = "idle";
        break;
    case ESP_IEEE802154_RADIO_SLEEP:
        state_str = "sleep";
        break;
    case ESP_IEEE802154_RADIO_RECEIVE:
        state_str = "receive";
        break;
    case ESP_IEEE802154_RADIO_TRANSMIT:
        state_str = "transmit";
        break;
    default:
        state_str = "unknown";
        break;
    }

    ESP_LOG_LEVEL(level, TAG, "IEEE 802.15.4 state: %s", state_str);
}

static void log_mac_addr(esp_log_level_t level) {
    uint8_t mac[8];
    esp_err_t result = esp_read_mac(mac, ESP_MAC_IEEE802154);

    if (result == ESP_OK) {
        ESP_LOG_LEVEL(level, TAG, "IEEE 802.15.4 MAC address: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                      mac[0], mac[1], mac[2], mac[3],
                      mac[4], mac[5], mac[6], mac[7]);
    } else {
        ESP_LOGE(TAG, "Failed to read the IEEE 802.15.4 MAC address, error: %s", esp_err_to_name(result));
    }
}

#define FRAME_LOG_FORMAT "%s\n"   \
    "|---------FRAME---------|\n" \
    "|Sequence Number: %s|\n"     \
    "|Destination PAN: %s|\n"     \
    "|Destination:     %s|\n"     \
    "|Source PAN:      %s|\n"     \
    "|Source:          %s|\n"     \
    "|-----------------------|"

static void log_frame(const char* msg, ieee802154_frame_t *frame, esp_log_level_t level) {
    char seq_num_str[7];
    char dst_addr_str[7];
    char src_addr_str[7];
    char dst_pan_id_str[7];
    char src_pan_id_str[7];

    snprintf(seq_num_str, 7, "%6" PRIu8, frame->mhr.seq_num);
    snprintf(dst_addr_str, 7, "0x%04X", frame->mhr.dst_addr);
    snprintf(src_addr_str, 7, "0x%04X", frame->mhr.src_addr);
    snprintf(dst_pan_id_str, 7, "0x%04X", frame->mhr.dst_pan_id);
    snprintf(src_pan_id_str, 7, "0x%04X", frame->mhr.src_pan_id);

    ESP_LOG_LEVEL(level, TAG, FRAME_LOG_FORMAT, msg, seq_num_str,
             dst_pan_id_str, dst_addr_str, src_pan_id_str, src_addr_str);
}

static uint16_t compute_frame_key(ieee802154_frame_t *frame) {
    return ((frame->mhr.src_addr & 0xFF) << 8) | frame->mhr.seq_num;
}

static void copy_data_frame(ieee802154_frame_t *dst, const ieee802154_frame_t *src) {
    dst->mhr.frame_control = IEEE802154_FRAME_VER_2006  |
                             IEEE802154_FRAME_TYPE_DATA |
                             IEEE802154_DST_ADDR_MODE_ONLY_SHORT |
                             IEEE802154_SRC_ADDR_MODE_ONLY_SHORT;

    dst->mhr.seq_num    = src->mhr.seq_num;
    dst->mhr.dst_pan_id = src->mhr.dst_pan_id;
    dst->mhr.dst_addr   = src->mhr.dst_addr;
    dst->mhr.src_pan_id = src->mhr.src_pan_id;
    dst->mhr.src_addr   = src->mhr.src_addr;

    memcpy(dst->payload, src->payload, PAYLOAD_SIZE);
}

static void send_data(const uint8_t *data, int len, uint16_t pan_id, uint16_t addr) {
    static uint8_t seq_num = 0;

    ieee802154_frame_t frame = {
        .mhr = {
            .frame_control = IEEE802154_FRAME_VER_2006  |
                             IEEE802154_FRAME_TYPE_DATA |
                             IEEE802154_DST_ADDR_MODE_ONLY_SHORT |
                             IEEE802154_SRC_ADDR_MODE_ONLY_SHORT,
            .seq_num    = seq_num++,
            .dst_pan_id = pan_id,
            .dst_addr   = addr,
            .src_pan_id = node_pan_id,
            .src_addr   = node_addr,
        },
        .fcs = 0,
    };

    int copy_len = (len > PAYLOAD_SIZE) ? PAYLOAD_SIZE : len;

    memcpy(frame.payload, data, copy_len);

    if (copy_len < PAYLOAD_SIZE) {
        memset(frame.payload + copy_len, 0, PAYLOAD_SIZE - copy_len);
    }

    BaseType_t task_woken = pdFALSE;

    xQueueSendToBackFromISR(tx_queue, &frame, &task_woken);

    if (task_woken) {
        portYIELD_FROM_ISR();
    }
}

void IRAM_ATTR esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_frame_info) {
    if (ack != NULL) {
        ESP_ERROR_CHECK(esp_ieee802154_receive_handle_done(ack));
    }
}

void IRAM_ATTR esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) {
    switch (error) {
    case ESP_IEEE802154_TX_ERR_NONE:
        ESP_DRAM_LOGE(TAG, "Transmit: unknown error");
        break;
    case ESP_IEEE802154_TX_ERR_CCA_BUSY:
        ESP_DRAM_LOGE(TAG, "Transmit: channel is busy");
        break;
    case ESP_IEEE802154_TX_ERR_ABORT:
        ESP_DRAM_LOGE(TAG, "Transmit: abort");
        break;
    case ESP_IEEE802154_TX_ERR_NO_ACK:
        ESP_DRAM_LOGE(TAG, "Transmit: no ack");
        break;
    case ESP_IEEE802154_TX_ERR_INVALID_ACK:
        ESP_DRAM_LOGE(TAG, "Transmit: invalid ack");
        break;
    case ESP_IEEE802154_TX_ERR_COEXIST:
        ESP_DRAM_LOGE(TAG, "Transmit: rejected by the coexist system");
        break;
    case ESP_IEEE802154_TX_ERR_SECURITY:
        ESP_DRAM_LOGE(TAG, "Transmit: invalid sec config");
        break;
    }
}

void IRAM_ATTR esp_ieee802154_receive_done(uint8_t *rx_frame, esp_ieee802154_frame_info_t *frame_info) {
    ieee802154_frame_t *frame = (ieee802154_frame_t *) (rx_frame + 1);

    BaseType_t task_woken = pdFALSE;

    xQueueSendToBackFromISR(rx_queue, frame, &task_woken);

    ESP_ERROR_CHECK(esp_ieee802154_receive_handle_done(rx_frame));

    if (task_woken) {
        portYIELD_FROM_ISR();
    }
}

_Noreturn static void tx_worker(void *params) {
    static ieee802154_frame_t frame;
    static uint8_t tx_frame[FRAME_SIZE+1];
    tx_frame[0] = FRAME_SIZE;

    while (true) {
        if (xQueueReceive(tx_queue, &frame, portMAX_DELAY)) {
            frame.fcs = 0;

            memcpy(tx_frame + 1, (uint8_t *) &frame, FRAME_SIZE);

            esp_ieee802154_transmit(tx_frame, false);
        }
    }
}

static void handle_frame(ieee802154_frame_t *frame) {
    static uint8_t resp[PAYLOAD_SIZE];
    uint8_t mi_frame_type = frame->payload[0] & MI_FRAME_TYPE_MASK;

    if (mi_frame_type == MI_FRAME_TYPE_ID_REQ) {
        if (!isolated) {
            return;
        }

        resp[0] = MI_FRAME_TYPE_ID;
        esp_read_mac(resp + 1, ESP_MAC_IEEE802154);
        send_data(resp, 9, IEEE802154_DST_PAN_ID_BROADCAST, IEEE802154_DST_ADDR_BROADCAST);
    }

    if (mi_frame_type == MI_FRAME_TYPE_ID) {
        node_lookup_t entry;

        if (frame->mhr.src_pan_id == node_pan_id) {
            entry.isolated = false;
            entry.addr     = frame->mhr.src_addr;
        } else {
            entry.isolated = true;
            entry.pan_id   = frame->mhr.src_pan_id;
        }

        memcpy(entry.mac_addr, frame->payload + 1, 8);

        int idx = lookup_table_find_idx(entry.mac_addr);

        if (idx >= 0) {
            lookup_table.records[idx] = entry;
        } else {
            lookup_table_add(&entry);
        }
    }
}

_Noreturn static void rx_worker(void *params) {
    static ieee802154_frame_t frame;
    static ieee802154_frame_t relay_frame;

    while (true) {
        if (xQueueReceive(rx_queue, &frame, portMAX_DELAY)) {
            bool target_domain = frame.mhr.dst_pan_id == node_pan_id ||
                                 frame.mhr.dst_pan_id == IEEE802154_DST_PAN_ID_BROADCAST;

            bool target_node = frame.mhr.dst_addr == node_addr ||
                               frame.mhr.dst_addr == IEEE802154_DST_ADDR_BROADCAST;

            uint16_t frame_key = compute_frame_key(&frame);
            uint16_t frame_type = frame.mhr.frame_control & IEEE802154_FRAME_TYPE_MASK;

            if (target_domain && target_node) {
                if (circ_buf_match(&rx_list, frame_key)) {
                    continue;
                }
                circ_buf_push(&rx_list, frame_key);

                // Handle frame
                log_frame("Received frame:", &frame, ESP_LOG_DEBUG);

                handle_frame(&frame);
            }

            if (
                target_domain &&
                frame.mhr.dst_addr != node_addr &&
                frame.mhr.src_addr != node_addr &&
                frame_type == IEEE802154_FRAME_TYPE_DATA
            ) {
                if (circ_buf_match(&relay_list, frame_key)) {
                    continue;
                }
                circ_buf_push(&relay_list, frame_key);

                // Relay frame
                log_frame("Relayed frame:", &frame, ESP_LOG_DEBUG);

                copy_data_frame(&relay_frame, &frame);
                xQueueSendToBack(tx_queue, &relay_frame, 0);
            }
        }
    }
}

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    memset(rx_list.buf,    0, sizeof(uint16_t) * CIRC_BUF_SIZE);
    memset(relay_list.buf, 0, sizeof(uint16_t) * CIRC_BUF_SIZE);

    ESP_ERROR_CHECK(esp_ieee802154_enable());
    ESP_ERROR_CHECK(esp_ieee802154_set_channel(26));
    ESP_ERROR_CHECK(esp_ieee802154_set_txpower(19));
    ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_ieee802154_set_coordinator(false));
    ESP_ERROR_CHECK(esp_ieee802154_set_pending_mode(ESP_IEEE802154_AUTO_PENDING_DISABLE));
    ESP_ERROR_CHECK(esp_ieee802154_set_cca_mode(ESP_IEEE802154_CCA_MODE_ED));
    ESP_ERROR_CHECK(esp_ieee802154_set_cca_threshold(-70));

    while (true) {
        esp_fill_random(&node_pan_id, sizeof(node_pan_id));

        // TODO: Check for PAN collisions
        break;
    }

    ESP_ERROR_CHECK(esp_ieee802154_set_panid(node_pan_id));
    ESP_ERROR_CHECK(esp_ieee802154_set_short_address(node_addr));

    ESP_ERROR_CHECK(esp_ieee802154_set_rx_when_idle(true));
    ESP_ERROR_CHECK(esp_ieee802154_receive());

    log_mac_addr(ESP_LOG_INFO);
    ESP_LOGI(TAG, "PAN ID: 0x%04X", node_pan_id);
    log_proto_state(ESP_LOG_INFO);

    tx_queue = xQueueCreate(8, FRAME_SIZE);
    rx_queue = xQueueCreate(8, FRAME_SIZE);

    xTaskCreate(tx_worker, "tx_worker", 8192, NULL, 5, NULL);
    xTaskCreate(rx_worker, "rx_worker", 8192, NULL, 5, NULL);

    fflush(stdout);
}
