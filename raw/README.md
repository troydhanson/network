Example of Linux raw packet sockets (`AF_PACKET`). See packet(7). Raw packet
sockets can read/write packets to the device, bypassing the network stack. 
They can also capture packets.

* rx       -  recvmsg-based capture 
* rx-dump  -  recvmsg-based capture, writes pcap
* rx-fan   -  recvmsg-based load-balanced multi-process capture `PACKET_FANOUT`
* rx-ring1 - `PACKET_RX_RING`-based capture, uses API version `TPACKET_V1`
* rx-ring2 - `PACKET_RX_RING`-based capture, uses API version `TPACKET_V2`
* rx-ring3 - `PACKET_RX_RING`-based capture, uses API version `TPACKET_V3` 
* rx-tx    - recvfrom/sendto frame repeater

`PACKET_RX_RING` notes

The difference between `TPACKET_V1` and `TPACKET_V2` is minimal. There was
a change to the `tpacket_hdr` structure to use explicit sized types.  Also
the timestamps changed to have nanosecond resoltuion. In `TPACKET_V3` more 
significant changes was made. The ring slots became variable-width so short
packets take less space. Polling became block-level instead of packet-level. 

As a matter of personal taste Ring1/2 seem more elegant and they "just work". 
Ring3 seems to be more unpredictable- once in a while it drops a packet for 
no obvious reason, and does not always wake up the poll. Perhaps it is just
a bug in rx-ring3.

`PACKET_FANOUT` may be used with `PACKET_RX_RING`. This is not shown here.
