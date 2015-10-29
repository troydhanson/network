Examples of using [nanomsg](http://nanomsg.org)

* nano-pull.c: simple PULL receiver
* nano-push.c: simple PUSH publisher
* nano-epull.c: manage nano PULL socket and OS descriptors 

nano-pull binds a local port, and nano-push connects to it.
Many copies of nano-push can run at the same time. Only one
nano-pull can be effective at once since it binds the port.

nano-epull demonstrates usage of epoll with nano and OS 
descriptors in one event loop. It handles signals properly.
