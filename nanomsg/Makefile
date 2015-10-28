PROGS=nano-push nano-pull
OBJS=$(patsubst %,%.o,$(PROGS))

CFLAGS = -g -Wall -Wextra
LDFLAGS= -lnanomsg

all: $(OBJS) $(PROGS) $(TEST_TARGET) 

# static pattern rule: multiple targets 

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< 

$(PROGS): %: %.o
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

.PHONY: clean

clean:	
	rm -f $(PROGS) $(OBJS) 
