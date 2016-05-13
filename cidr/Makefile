PROGS = $(patsubst %.c,%,$(wildcard *.c))
all: $(PROGS)

CFLAGS += -g
CFLAGS += -Wall
CFLAGS += -O2

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< 

$(PROGS): %: %.o
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

.PHONY: clean tests

clean:
	rm -f *.o $(PROGS)
	make -C tests $@

tests:
	make -C tests
