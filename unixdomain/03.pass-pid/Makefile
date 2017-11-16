PROGS=send-easy send-hard recv-easy recv-hard
OBJS=$(patsubst %,%.o,$(PROGS))
all: $(OBJS) $(PROGS) 

# static pattern rule: multiple targets 

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< 

$(PROGS): %: %.o
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJS) $(PROGS)
