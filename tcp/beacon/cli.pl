#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;
use Getopt::Long;

# simple pattern generator 
# open a TCP socket
# send <r> repetitions of a message <m> bytes long (random bytes)
# spaced by a <i> second interval
# afterward close the socket

sub usage {
  print "usage: $0 [-v] [-s <ip>] [-p <port>] [-i interval] [-m msglen] [-r repeat-count]\n";
  exit(-1);
}

our $server="127.0.0.1";
our $port = 1234;
our $verbose;
our $interval=0;
our $msglen = 10;
our $repeats=1;
our $help;
usage unless GetOptions("port=i"           => \$port,
                        "server=s"         => \$server,
                        "verbose+"         => \$verbose,
                        "msglen=i"         => \$msglen,
                        "interval=i"       => \$interval,
                        "repeat=i"         => \$repeats,
                        "help"             => \$help);
usage if $help;
usage unless $port;

my $sock = IO::Socket::INET->new( PeerPort => $port, PeerAddr => $server, 
                                  Proto => "tcp", ) or die "socket: $!\n";
while ($repeats--) {
   our $msg="";
   $msg .= pack "C", int(rand(256)) while (length($msg) < $msglen);
   $sock->send($msg) or die "connection terminated\n";
   sleep($interval);
}
$sock->close();

