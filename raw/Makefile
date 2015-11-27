OBJS= rx
all: $(OBJS)
CFLAGS=-Iinclude
CFLAGS+=-g
LDFLAGS=

rx: rx.c 
	$(CC) $(CFLAGS) -c rx.c
	$(CC) $(CFLAGS) -o $@ rx.o $(LDFLAGS)

.PHONY: clean install

clean:
	rm -f $(OBJS) *.o

install:
	cp $(OBJS) /usr/local/bin
