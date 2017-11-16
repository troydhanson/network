# Passing a file descriptor over a Unix domain socket

A program that listens on a Unix domain socket can accept special ancillary
data from a connected client, containing a file descriptor from the client.

The file descriptor typically takes on a new number in the receiver but refers
to the same open file description as it had in the sender.  This is described
in unix(7) under `SCM_RIGHTS`, and in this excerpt from "The Linux Programming
Interface" (TLPI), by Michael Kerrisk, section 61.13:

> 61.13.3 Passing File Descriptors
> Using sendmsg() and recvmsg(), we can pass ancillary data containing a file
> descriptor from one process to another process on the same host via a UNIX
> domain socket. Any type of file descriptor can be passed in this manner—for
> example, one obtained from a call to open() or pipe(). An example that is
> more relevant to sockets is that a master server could accept a client
> connection on a TCP listening socket and pass that descriptor to one of the
> members of a pool of server child processes (Section 60.4), which would then
> respond to the client request.  Although this technique is commonly referred
> to as passing a file descriptor, what is really being passed between the two
> processes is a reference to the same open file description (Figure 5-2, on
> page 95). The file descriptor number employed in the receiving process would
> typically be different from the number employed in the sender.

The client has to provoke a read (by transmitting a byte or closing its end of
the socket), for the receiver to get something on recvmsg()- since the passed
descriptor is "attached" to the returned data.

## Example

Two programs, recv-fd.c and send-fd.c, demonstrate descriptor passing. Run 
recv-fd in one terminal, and then run send-fd <file> in another terminal. The
sender program opens the <file> and passes its descriptor to the receiver.

    % make
    % ./recv-fd             # in window 1
    % ./send-fd /etc/hosts  # in window 2

On window 1, a message like this is shown:

    received 1 bytes: *
    Received fd 7
    reading fd 7...
    read 126 bytes: 127.0.0.1   localhost localhost.localdomain

[Example](http://man7.org/tlpi/code/online/dist/sockets/scm_rights_send.c.html)
code is also included with TLPI.

