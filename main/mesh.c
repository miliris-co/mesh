#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "esp_attr.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_ieee802154.h"
#include "esp_ieee802154_types.h"
#include "esp_random.h"
#include "esp_crc.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "portmacro.h"

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

#define IEEE820154_DST_PAN_ID_BROADCAST         0xFFFF
#define IEEE820154_DST_ADDR_BROADCAST           0xFFFF

#define MHR_SIZE 11
#define PAYLOAD_SIZE 96
#define FRAME_SIZE (MHR_SIZE + PAYLOAD_SIZE + 2)

typedef struct __attribute__((packed)) {
    struct __attribute__((packed)) {
        uint16_t frame_control;
        uint8_t seq_num;
        uint16_t dst_pan_id;
        uint16_t dst_addr;
        uint16_t src_pan_id;
        uint16_t src_addr;
    } mhr;
    uint8_t payload[PAYLOAD_SIZE];
    uint16_t fcs;
} ieee802154_frame_t;

const static char *TAG = "MESH";

static void get_proto_state(char *str, int len) {
    switch (esp_ieee802154_get_state()) {
    case ESP_IEEE802154_RADIO_DISABLE:
        strncpy(str, "disabled", len);
        break;
    case ESP_IEEE802154_RADIO_IDLE:
        strncpy(str, "idle", len);
        break;
    case ESP_IEEE802154_RADIO_SLEEP:
        strncpy(str, "sleep", len);
        break;
    case ESP_IEEE802154_RADIO_RECEIVE:
        strncpy(str, "receive", len);
        break;
    case ESP_IEEE802154_RADIO_TRANSMIT:
        strncpy(str, "transmit", len);
        break;
    }
}

static void log_proto_state() {
    char str[9];
    get_proto_state(str, 9);
    ESP_DRAM_LOGI(TAG, "IEEE 802.15.4 state: %s", str);
}

void calculate_crc(ieee802154_frame_t *frame) {
    static uint8_t buf[MHR_SIZE+PAYLOAD_SIZE];

    memcpy(buf, (uint8_t *) &frame->mhr, MHR_SIZE);
    memcpy(buf + MHR_SIZE, frame->payload, PAYLOAD_SIZE);

    uint16_t crc = 0x0000;

    crc = esp_crc16_le(crc, buf, MHR_SIZE+PAYLOAD_SIZE);

    frame->fcs = crc;
}

static void mesh_proto_worker(void *pvParams) {
    uint8_t seq_num = 0;

    while (true) {
        vTaskDelay(5000 / portTICK_PERIOD_MS);

        ieee802154_frame_t frame = {
            .mhr = {
                .frame_control = IEEE802154_FRAME_VER_2006 |
                                 IEEE802154_FRAME_TYPE_DATA |
                                 IEEE802154_DST_ADDR_MODE_ONLY_SHORT |
                                 IEEE802154_SRC_ADDR_MODE_ONLY_SHORT,
                .seq_num = seq_num++,
                .dst_pan_id = IEEE820154_DST_PAN_ID_BROADCAST,
                .dst_addr = IEEE820154_DST_ADDR_BROADCAST,
                .src_pan_id = *(uint16_t *) pvParams,
                .src_addr = 0x0001,
            },
            .payload = { 0 },
        };

        const char *msg = "Hello, World!";
        strncpy((char *) frame.payload, msg, PAYLOAD_SIZE);

        calculate_crc(&frame);

        static uint8_t tx_frame[FRAME_SIZE+1];
        tx_frame[0] = FRAME_SIZE;
        memcpy(tx_frame + 1, (uint8_t *) &frame, FRAME_SIZE);

        esp_ieee802154_transmit(tx_frame, true);
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

    char seq_num_str[4];
    snprintf(seq_num_str, 4, "%" PRIu8, frame->mhr.seq_num);

    ESP_DRAM_LOGI(TAG, "Frame received, seq_num: %s", seq_num_str);

    ESP_ERROR_CHECK(esp_ieee802154_receive_handle_done(rx_frame));
}

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    uint8_t mac[8];
    esp_err_t result = esp_read_mac(mac, ESP_MAC_IEEE802154);
    if (result == ESP_OK) {
        ESP_LOGI(TAG, "IEEE 802.15.4 MAC address: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3],
                 mac[4], mac[5], mac[6], mac[7]);
    } else {
        ESP_LOGE(TAG, "Failed to read the IEEE 802.15.4 MAC address, error: %s", esp_err_to_name(result));
    }

    ESP_ERROR_CHECK(esp_ieee802154_enable());
    ESP_ERROR_CHECK(esp_ieee802154_set_channel(26));
    ESP_ERROR_CHECK(esp_ieee802154_set_txpower(10));
    ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(true));

    uint16_t pan_id;

    while (true) {
        esp_fill_random(&pan_id, sizeof(pan_id));

        // TODO: Check for PAN collisions
        break;
    }

    ESP_LOGI(TAG, "PAN ID: %" PRIx16, pan_id);
    ESP_ERROR_CHECK(esp_ieee802154_set_panid(pan_id));

    ESP_ERROR_CHECK(esp_ieee802154_set_coordinator(true));
    ESP_ERROR_CHECK(esp_ieee802154_set_pending_mode(ESP_IEEE802154_AUTO_PENDING_DISABLE));
    ESP_ERROR_CHECK(esp_ieee802154_set_cca_mode(ESP_IEEE802154_CCA_MODE_ED));
    ESP_ERROR_CHECK(esp_ieee802154_set_cca_threshold(-75));
    ESP_ERROR_CHECK(esp_ieee802154_set_rx_when_idle(true));

    log_proto_state();

    xTaskCreate(mesh_proto_worker, "mesh_proto_worker", 20480, &pan_id, 5, NULL);

    fflush(stdout);
}

