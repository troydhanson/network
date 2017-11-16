# Autobind

The program autobind.c creates a UNIX domain socket in the abstract namespace
using the autobind feature.  This is a convenient way to generate a socket name
in the abstract namespace.  After creating it, we use getsockname to find the
name that was autobound. From unix(7): 

>  Autobind feature
>      If  a  bind(2)  call specifies addrlen as sizeof(sa_family_t), or the SO_PASSCRED socket option was
>      specified for a socket that was not explicitly bound to an address, then the socket is autobound to
>      an  abstract address.  The address consists of a null byte followed by 5 bytes in the character set
>      [0-9a-f].  Thus, there is a limit of 2^20 autobind addresses.  (From Linux 2.1.15, when  the  auto‐
>      bind  feature  was  added,  8 bytes were used, and the limit was thus 2^32 autobind addresses.  The
>      change to 5 bytes came in Linux 2.3.15.)

The length of the socket name must be explicitly handled in any client code
since the socket name starts with a null byte, and the bytes that come after it
(the rest of the socket name) may lack a null-terminator. The length, addrlen,
is from from getsockname, and according to unix(7), "the name of the socket is
contained in the first `(addrlen - sizeof(sa_family_t))` bytes of `sun_path`."

Example of running:

    % make
    %  ./autobind
    socket name in hex and ASCII (. for null byte):
    00 30 30 30 30 64                               .0000d     

Leave it running for this example.  To list the Unix domain sockets currently
in existence, use `ss -planx`.

    % ss -planx | grep autobind
    u_str  LISTEN   0     5     @0000d ... users:(("autobind",pid=10349,fd=3))

This directory contains a client that can connect to the autobound socket. Note
the name it was assigned (0000d in the run above) and substitute it below:

    % ./cli 0000d

The autobind process we left running should now print something like,

    received 13 bytes: hello, world!
    client: eof
