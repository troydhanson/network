OBJS= pcap-record
all: $(OBJS)
CFLAGS=-Iinclude
CFLAGS+=-g
LDFLAGS=-lpcap 

pcap-record: pcap-record.c 
	$(CC) $(CFLAGS) -c pcap-record.c
	$(CC) $(CFLAGS) -o $@ pcap-record.o $(LDFLAGS)

.PHONY: clean install

clean:
	rm -f $(OBJS) *.o

install:
	cp $(OBJS) /usr/local/bin
