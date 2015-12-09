PROGS=rx rx-dump rx-fan rx-ring1 rx-ring2 rx-ring3 rx-tx
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

