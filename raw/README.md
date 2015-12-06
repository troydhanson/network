Example of Linux raw packet sockets (`AF_PACKET`). See packet(7). Raw packet
sockets can read/write packets to the device, bypassing the network stack. 
They can also capture packets.

* rx       -  recvmsg-based capture 
* rx-dump  -  recvmsg-based capture, writes pcap
* rx-ring1 - `PACKET_RX_RING`-based capture, uses API version `TPACKET_V1`
* rx-ring2 - `PACKET_RX_RING`-based capture, uses API version `TPACKET_V2`
* rx-ring3 - `PACKET_RX_RING`-based capture, uses `TPACKET_V3` (has bugs) 

The difference between `TPACKET_V1` and `TPACKET_V2` is minimal. There was
a change to the `tpacket_hdr` structure to use explicit sized types. 

With `TPACKET_V3` a much more significant change was made. The ring slots
became variable-width (so short packets take less space). Polling became
at the block level instead of at the packet level. 

TODO
* fanout
