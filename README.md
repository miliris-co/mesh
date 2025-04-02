# Mesh Protocol

An experiment to create my own IEEE 802.15.4 compatible wireless mesh protocol. 
It works, but it's not really compatible with 802.15.4, because the standard documentation 
is quite extensive and not easily accessible (newer versions are behind paywalls), so I took a lot of shortcuts. Another thing I figured out 
is that Espressif microcontrollers are very poorly documented when it comes to low-level stuff. 
It's probably better to go with an nRF microcontroller and build on top of an existing minimal 
IEEE 802.15.4 reference implementation, a good lesson for later.
