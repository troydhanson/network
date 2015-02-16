OBJS=mod-pcap cat-pcap
all: $(OBJS)

mod-pcap: mod-pcap.c
	$(CC) -o $@ $< 

cat-pcap: cat-pcap.c
	$(CC) -o $@ $< 

.PHONY: clean

clean:
	rm -f $(OBJS) *.o
