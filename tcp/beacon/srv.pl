#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;
use Getopt::Long;

# this is a Perl TCP server sink
# useful with cli.pl or as an example
# of a simple forking TCP server in Perl

sub usage {
  print "usage: $0 [-v] [-p <port>] [-f]\n";
  exit(-1);
}

our $port = 1234;
our $verbose=0;
our $help;
our $msg;
our $max=2000000;
usage unless GetOptions("port=i"           => \$port,
                        "verbose+"         => \$verbose,
                        "help"             => \$help);
usage if $help;
usage unless $port;
my $server = IO::Socket::INET->new(LocalPort => $port, Proto => "tcp", 
    Listen => 5, Reuse => 1)
    or die "Couldn't listen on tcp port $port : $@\n";

our $client;
$SIG{'CHLD'}="IGNORE";  # no zombies

while(1) {
  print STDERR "accepting...\n";
  $client =  $server->accept();
  last if (fork == 0); # child breaks out
  $client->close();
}

#
# child here
#
print STDERR "in child\n";
close STDIN;
$server->close();

while(1) {
  print STDERR "waiting for data...\n";
  last if not defined $client->recv($msg,$max);
  last if length($msg) == 0;
  print STDERR "received buffer of length " . length($msg) . "\n" if $verbose;
  print STDERR $msg if $verbose > 1;
}

print STDERR "disconnect\n";
$client->close();
