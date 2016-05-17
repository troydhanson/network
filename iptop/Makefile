OBJS= iptop
all: $(OBJS)
CFLAGS=-I./include
CFLAGS+=-g
LDFLAGS=-lpcap 

iptop.o: iptop.c iptop.h
	$(CC) -c $(CFLAGS) $<

tracker.o: tracker.c iptop.h
	$(CC) -c $(CFLAGS) $<

ip.o: ip.c iptop.h 
	$(CC) -c $(CFLAGS) $<

iptop: iptop.o tracker.o ip.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean install

clean:
	rm -f $(OBJS) *.o

install:
	cp $(OBJS) /usr/local/bin
