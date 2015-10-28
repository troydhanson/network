Examples of using [nanomsg](http://nanomsg.org)

* nano-pull.c: simple PULL receiver
* nano-push.c: simple PUSH publisher
* nano-epoll.c: poll nanomsg and OS-level sockets 

Integrating nanomsg and OS descriptors into a select/poll loop
uses nanomsg's socket option API to get an OS descriptor first.
That descriptor can be used with select/poll. 

Once we have a set of descriptors (OS, and nanomsg-based) we
can build a main loop that waits for I/O readiness on any of them.

There are different ways to structure the main loop if we want
to wait for descriptor readiness or signal arrival at any time.
We can convert signals into file descriptor events using signalfd.
Or we can convert file descriptor events into signals (signal-driven I/O).
The former is compatible with epoll; the latter is compatible with sigwaitinfo.

