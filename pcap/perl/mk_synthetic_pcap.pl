#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use Net::Pcap qw(:datalink :functions);

# this example writes a pcap file having a given number of fake packets
# of a given length, whose content is drawn from a limited vocabulary
# which is randomly generated. The analogy is a limited communication
# protocol that each packet is constrained to. 
#
# This does not make TCP/IP pcap! We are generating pcap where the 
# records ("packets") are completely meaningless. Libpcap does make
# us specify the underlying link level protocol we're fabricating--
# here we're abusing DLT_NULL but that's just what I saw first.

#
# TODO maybe use a different link-layer type (DLT_ etc)

# 
# this uses the Perl binding for libpcap
# which can be installed on Ubuntu using
#    sudo apt-get install libnet-pcap-perl
# and whose documentation can be viewed by
#    perldoc Net::Pcap 
# 
#

sub usage {
  print "usage: $0 [--pktcnt=<num_packets>] [--len=n] [--nvocab=v] [--filename=f]\n";
  exit -1;
}

our $pktcnt=0;
our $len=10;
our $nvocab=0;
our $filename='output.pcap';
our $help;

usage unless GetOptions("pktcnt=i"  => \$pktcnt,
                        "len=i"  => \$len,
                        "nvocab=i"  => \$nvocab,
                        "filename=s"  => \$filename,
                        "help"   => \$help);
usage if $help;

my ($snaplen,$linktype) = (65535, DLT_NULL);
my $pcap = pcap_open_dead($linktype, $snaplen);
my $dump = pcap_dump_open($pcap, $filename);
die "error: ".pcap_geterr($pcap)."\n" unless defined $dump;

#########################################################################
# generate a number of vocabulary words.
# the fake packets we generate will cycle through the words
# in our generated vocabulary.
#########################################################################
sub genword {
  my $word = "";
  $word .= chr(65 + int(rand(26))) while length($word) < $len;
  return $word;
}
$nvocab = $pktcnt unless $nvocab;
my %vocab;
$vocab{genword()}=1 while (scalar keys %vocab) < $nvocab;

#########################################################################
# generate a bunch of fake packets. the DLT_NULL link type we're misusing
# apparently maps to the first four bytes of our packet content as judged
# from tcpdump -A 
#########################################################################
my (%hdr,$pkt); 
my ($i,$now) = (0,time);
my @words = sort keys %vocab;
while ($pktcnt) {
  %hdr = ( "len"=>$len, "caplen"=>$len, "tv_sec"=>$i+$now, "tv_usec"=>0);
  $pkt = "link" . $words[ $i % $nvocab ];
  pcap_dump($dump, \%hdr, $pkt);
  $pktcnt--; $i++;
}
