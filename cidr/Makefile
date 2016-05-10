PROGS = $(patsubst %.c,%,$(wildcard *.c))
all: $(PROGS)

CFLAGS += -g
CFLAGS += -Wall 

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< 

$(PROGS): %: %.o
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

.PHONY: clean

clean:
	rm -f *.o $(PROGS)

