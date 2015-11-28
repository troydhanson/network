Example of Linux AF_PACKET interface. See packet(7). Raw packet sockets
can read/write packets to the device, bypassing the network stack. They 
can also capture packets.

* rx      - recvmsg-based capture 
* rx-dump - recvmsg-based capture, writes faux pcap
