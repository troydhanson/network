Example of Linux raw packet sockets (`AF_PACKET`). See packet(7). Raw packet
sockets can read/write packets to the device, bypassing the network stack. 
They can also capture packets.

* rx       -  recvmsg-based capture 
* rx-dump  - recvmsg-based capture, writes pcap
* rx-ring3 - `PACKET_RX_RING`-based capture, uses `TPACKET_V3` (has bugs) 
