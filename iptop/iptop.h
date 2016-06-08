#ifndef __IPTOP_H__
#define __IPTOP_H__

#define _GNU_SOURCE
#include <errno.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include "abtop.h"

void cb(u_char *data, const struct pcap_pkthdr *hdr, const u_char *pkt);

struct iptop_conf {
  int verbose;
  char *prog;
  char *dev;
  char *filter;
  int pcap_fd;
  pcap_t *pcap;
  struct bpf_program fp;
  char err[PCAP_ERRBUF_SIZE];
  int snaplen;
  int ticks;
  int signal_fd;
  int epoll_fd;
  int capbuf;
  time_t now;
  int display_interval;
  UT_string *label;
  abtop_t *abtop;
};

#endif
