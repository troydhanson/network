#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;
use Getopt::Long;

sub usage {
  print "usage: $0 [-v] [-s <ip>] -p <port> [<msg>]\n";
  exit(-1);
}

our $server="127.0.0.1";
our $port;
our $verbose;
our $help;
our $msg = "hello\n";
usage unless GetOptions("port=i"           => \$port,
                        "server=s"         => \$server,
                        "verbose+"         => \$verbose,
                        "help"             => \$help);
usage if $help;
usage unless $port;
$msg = shift @ARGV if @ARGV;
my $sock = IO::Socket::INET->new( PeerPort => $port, PeerAddr => $server, 
                                  Proto => "udp", ) or die "socket: $!\n";
$sock->send($msg);
