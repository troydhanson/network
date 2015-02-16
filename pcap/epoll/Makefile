OBJS= pcap-epoll
all: $(OBJS)
CFLAGS=-Iinclude
CFLAGS+=-g
LDFLAGS=-lpcap 

pcap-epoll: pcap-epoll.c 
	$(CC) $(CFLAGS) -c pcap-epoll.c
	$(CC) $(CFLAGS) -o $@ pcap-epoll.o $(LDFLAGS)

.PHONY: clean install

clean:
	rm -f $(OBJS) *.o

install:
	cp $(OBJS) /usr/local/bin
