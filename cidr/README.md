# CIDR

An IPv4 CIDR expression is shorthand for a range of IP space. E.g.,

    192.168.128.0/20

can be understood as two parts in binary terms: a fixed prefix that extends for
20 bits, and the host part consisting of the remaining variable bits.

    ------- fixed --------/---variable--
    11000000 10101000 1000/0000 00000000
        |        |     |      
       192      168   128

A subnet or VLAN carrying this IP space could have 2^12 or 4096 hosts on it.
An all-zero or all-ones host may be reserved, so a few under 4096, actually.

Typically CIDR describes a part of a network such as a subnet. The syntax can
also be used with a full 32-bit IP address e.g. 192.168.144.19/20 to indicate
the netmask that goes with a particular host on a particular subnet.

## cidr-tool

This directory contains the source code for a CIDR calculator called cidr-tool.
To build it, run 'make' in this directory. Run `cidr-tool -h` to see its options.

## Operations

### Netmask to /N

To convert a netmask to a /N (CIDR length) count the set-bits in the netmask.
(The mask must have contiguous set bits followed by contiguous clear bits).

    ./cidr-tool 255.255.255.240
    /28

### /N to Netmask

To make a netmask from a /N (CIDR length) set the initial N bits of the netmask.

    ./cidr-tool /28
    255.255.255.240

### IP-in-CIDR test

To test whether an IP address is inside a CIDR of length /N, clear the low N
bits of the IP address. If the resulting IP and CIDR are equal in binary then
the IP is inside the CIDR.

#### Example

IPv4 routing requires that a host and its gateway are in the same subnet.

    GATEWAY=10.20.30.1
    ADDRESS=10.20.30.27
    NETMASK=255.255.255.224

    ./cidr-tool $NETMASK $ADDRESS $GATEWAY
    Addresses in same network

### Expansion

To expand a CIDR to the full set of IP addresses it represents, permute the
variable portion exhaustively. A CIDR of length /N has 2^(32-N) permutations.

    ./cidr-tool 192.168.128.0/20
    192.168.128.0
    ...
    192.168.143.255

### IP range to CIDR

An IP range such as 0.0.0.0 - 130.255.255.255 may expand to multiple CIDR
blocks.  To generate the list of blocks, fully expand the IP address list, sort
it, and start with the most specific CIDR mask possible that represents the
first item.  That is the IP itself with length /32. As each item in the list is
processed, expand the CIDR range so that it includes the new item unless the
resulting expansion would encompass addresses outside of the list. In that
case, start a new CIDR range instead.

    ./cidr-tool 0.0.0.0 130.255.255.255
    0.0.0.0/1
    128.0.0.0/7
    130.0.0.0/8


