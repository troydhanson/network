# Obtaining PID of peer connected to a Unix domain socket

A program that listens on a Unix domain socket can accept obtain the client
credentials (pid,uid,gid) in two ways. 

## Easy way

The easy way is for the server to call getsockopt on an accepted client socket.

    getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)

as shown in recv-easy.c. 

    % ./recv-easy  # in window 1
    % ./send-easy  # in window 2

On window 1 you'll see messages like this:

    Credentials from SO_PEERCRED: pid=5829, euid=501, egid=501

The man page for socket(7) notes:

> The  returned  credentials are those that were in effect at the time of the
> call to connect(2)

## Hard way

The harder way uses ancillary data for the receiver to get the credentials.
One disadvantage of this approach, besides the complex code to deal with
ancillary data, is that the client has to provoke a read (by transmitting
a byte or closing its end of the socket), for the receiver to get something
on recvmsg()- since the credentials are attached to the read. Other than
that, there are no special requirements on the client. Credential passing
from the client perspective is automatic when the receiver requests it, as 
with the "easy way" above. 

    % ./recv-hard  # in window 1
    % ./send-hard  # in window 2

On window 1, messages like these are shown.

    Received credentials pid=6020, uid=501, gid=501

A client can optionally pass its credentials explicitly, and even modify them
if sufficiently privileged. Michael Kerrisk has an example of this
[here](http://man7.org/tlpi/code/online/dist/sockets/scm_cred_send.c.html).

