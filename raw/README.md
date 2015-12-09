Example of Linux raw packet sockets (`AF_PACKET`). See packet(7). Raw packet
sockets can read/write packets to the device, bypassing the network stack. 
They can also capture packets.

* rx       -  recvmsg-based capture 
* rx-dump  -  recvmsg-based capture, writes pcap
* rx-ring1 - `PACKET_RX_RING`-based capture, uses API version `TPACKET_V1`
* rx-ring2 - `PACKET_RX_RING`-based capture, uses API version `TPACKET_V2`
* rx-ring3 - `PACKET_RX_RING`-based capture, uses API version `TPACKET_V3` 
* rx-tx    - recvfrom/sendto frame repeater

The difference between `TPACKET_V1` and `TPACKET_V2` is minimal. There was
a change to the `tpacket_hdr` structure to use explicit sized types.  Also
the timestamps changed to have nanosecond resoltuion. In `TPACKET_V3` more 
significant changes was made. The ring slots became variable-width so short
packets take less space. Polling became block-level instead of packet-level. 

As a matter of taste Ring1/2 are more elegant and they seem to "just work". 
I find that Ring3 has more unpredictable behavior (once in a while it drops
a packet for no obvious reason, and does not always wake up the poll). Maybe 
it is an error in the rx-ring3 program. For my purposes I prefer Ring2.

TODO

* fanout
