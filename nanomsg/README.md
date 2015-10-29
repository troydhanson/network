Examples of using [nanomsg](http://nanomsg.org)

* nano-pull.c: simple PULL receiver
* nano-push.c: simple PUSH publisher
* nano-epoll.c: poll nanomsg and OS-level sockets 

nano-pull binds a local port, and nano-push connects to it.
Many copies of nano-push can run at the same time. Only one
nano-pull can be effective at once (have the port bound).

OS and nano socket monitoring in one event loop

A program that manages OS file descriptors and nano sockets in
a single event loop (say, epoll) can use nano's socket option API
to get an underlying file descriptor.

A real program may also want to handle signals properly in the main loop.
We can convert signals into file descriptor events using signalfd. Then use
epoll. Or, we can convert file descriptor events into signals (signal-driven
I/O). Then use sigwaitinfo.

