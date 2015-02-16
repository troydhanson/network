#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;
use Getopt::Long;

sub usage {
  print "usage: $0 [-v] -p <port>\n";
  exit(-1);
}

our $port;
our $verbose;
our $help;
our $msg;
our $max=2000;
usage unless GetOptions("port=i"           => \$port,
                        "verbose+"         => \$verbose,
                        "help"             => \$help);
usage if $help;
usage unless $port;

my $server = IO::Socket::INET->new(LocalPort => $port, Proto => "udp")
    or die "Couldn't listen on udp port $port : $@\n";

while ($server->recv($msg, $max)) {
  print STDERR $msg;
} 
