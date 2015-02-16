OBJS=tcp-server epoll-server
ALL: $(OBJS)

CFLAGS=-Wall
CFLAGS+=-g

tcp-server: tcp-server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tcp-server.o: tcp-server.c
	$(CC) -c $(CFLAGS) $<

epoll-server: epoll-server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

epoll-server.o: epoll-server.c
	$(CC) -c $(CFLAGS) $<

.PHONY: clean

clean:
	rm -f *.o $(OBJS)
