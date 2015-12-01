PROGS=rx rx-dump rx-ring3-buggy
OBJS=$(patsubst %,%.o,$(PROGS))
all: $(OBJS) $(PROGS) 

CFLAGS=-g -Wall

# static pattern rule: multiple targets 

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< 

$(PROGS): %: %.o
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

.PHONY: clean

clean:  
	rm -f $(PROGS) $(OBJS) 

