OBJS=sigio-server epoll-server
ALL: $(OBJS)

CFLAGS=-Wall
CFLAGS+=-g

sigio-server: sigio-server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sigio-server.o: sigio-server.c
	$(CC) -c $(CFLAGS) $<

epoll-server: epoll-server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

epoll-server.o: epoll-server.c
	$(CC) -c $(CFLAGS) $<

.PHONY: clean

clean:
	rm -f *.o $(OBJS)
