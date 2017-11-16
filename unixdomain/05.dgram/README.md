# Unix domain datagram socket

This example uses a datagram socket instead of a stream socket. A datagram socket
is simpler: the server only binds it (it does not listen), and each received datagram
is read from the original descriptor. This is in contrast to a stream socket where
each connection spawns a new descriptor distinct from the listening descriptor.

## Passing peer credentials

Reading the peer's process ID via getsockopt with `SO_PEERCRED` (shown as the "easy
way" in ../03.pass-pid) does not work here with a datagram socket. From socket(7),

> SO_PEERCRED 
> Return the credentials of the foreign process connected to this
> socket.  This is possible only for connected AF_UNIX stream sockets and
> AF_UNIX stream and datagram socket pairs created using socketpair(2);

The send.c and recv.c example creates a datagram socket, not a stream socket,
and does so with socket rather than socketpair. 

However, it is still possible to explicitly pass PID credentials the "hard way"
(using ancillary data) over a unix domain datagram socket. This is shown
in send-pid.c and recv-pid.c.
