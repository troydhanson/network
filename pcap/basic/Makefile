PROGS=compile_filter decode_tcp_headers hardcoded_filter iface_stats \
      pkt_lengths pkt_lengths_file signal_driven_capture multi_mode \
      pkt_bloom cross_border
OBJS=$(patsubst %,%.o,$(PROGS))
all: $(OBJS) $(PROGS) 

#CFLAGS=-g -Wall
LDFLAGS=-lpcap

# static pattern rule: multiple targets 

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< 

$(PROGS): %: %.o
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

.PHONY: clean

clean:  
	rm -f $(PROGS) $(OBJS) 

