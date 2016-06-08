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
#include "iptop.h"

struct iptop_conf cfg = {
  .snaplen = 65535,
  .pcap_fd = -1,
  .dev = "eth0",
  .capbuf = (1024*1024),
  .display_interval = 2,
};


void usage() {
  fprintf(stderr,"usage: %s [-v] -f <bpf-filter>                \n"
                 "               -i <eth>        (read from interface)\n"
                 "               -B <cap-buf-sz> (capture buf size eg. 10m)\n"
                 "               -t <seconds>    (display interval)\n"
                 "\n",
          cfg.prog);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void periodic_work() {
  cfg.now = time(NULL);
  if ((cfg.now % cfg.display_interval) == 0) show_abtop_top(cfg.abtop);
}

int set_filter() {
  if (cfg.filter == NULL) return 0;

  int rc=-1;
  if ( (rc = pcap_compile(cfg.pcap, &cfg.fp, cfg.filter, 0, PCAP_NETMASK_UNKNOWN)) != 0) {
    fprintf(stderr, "error in filter expression: %s\n", cfg.err);
    goto done;
  }
  if ( (rc = pcap_setfilter(cfg.pcap, &cfg.fp)) != 0) {
    fprintf(stderr, "can't set filter expression: %s\n", cfg.err);
    goto done;
  }
  rc=0;

 done:
  return rc;
}

void do_stats(void) {
  struct pcap_stat ps;
  if (cfg.verbose == 0 ) return;
  if (pcap_stats(cfg.pcap,&ps)<0) {fprintf(stderr,"pcap_stat error\n"); return;}
  fprintf(stderr,"received : %u\n", ps.ps_recv);
  fprintf(stderr,"dropped: %u\n", ps.ps_drop);
}

int new_epoll(int events, int fd) {
  int rc;
  struct epoll_event ev;
  memset(&ev,0,sizeof(ev)); // placate valgrind
  ev.events = events;
  ev.data.fd= fd;
  if (cfg.verbose) fprintf(stderr,"adding fd %d to epoll\n", fd);
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

int handle_signal() {
  int rc=-1;
  struct signalfd_siginfo info;
  
  if (read(cfg.signal_fd, &info, sizeof(info)) != sizeof(info)) {
    fprintf(stderr,"failed to read signal fd buffer\n");
    goto done;
  }

  switch(info.ssi_signo) {
    case SIGALRM: 
      periodic_work();
      if ((++cfg.ticks % 10) == 0) do_stats();
      alarm(1); 
      break;
    default: 
      fprintf(stderr,"got signal %d\n", info.ssi_signo);  
      goto done;
      break;
  }

 rc = 0;

 done:
  return rc;
}

int get_pcap_data() {
  int rc=-1;

  if (pcap_dispatch(cfg.pcap, 10000,cb,NULL) < 0) {
    pcap_perror(cfg.pcap, "pcap error: "); 
    goto done;
  }
  rc = 0;

 done:
  return rc;
}

/* parse a suffixed number like 1m (one megabyte) */
int parse_kmg(char *str) {
  char *c;
  int i;
  if (sscanf(str,"%u",&i) != 1) {
    fprintf(stderr,"could not parse integer in %s\n",str);
    return -1;
  }
  for(c=str; *c != '\0'; c++) {
    switch(*c) {
      case '0': case '1': case '2': case '3': case '4': 
      case '5': case '6': case '7': case '8': case '9': 
         continue;
      case 'g': case 'G': i *= 1024; /* fall through */
      case 'm': case 'M': i *= 1024; /* fall through */
      case 'k': case 'K': i *= 1024; break;
      default:
       fprintf(stderr,"unknown suffix on integer in %s\n",str);
       return -1;
    }
  }
  return i;
}

int main(int argc, char *argv[]) {
  struct epoll_event ev;
  cfg.prog = argv[0];
  utstring_new(cfg.label);
  cfg.abtop = abtop_new(1000,10);
  cfg.now = time(NULL);
  int n,opt;

  while ( (opt=getopt(argc,argv,"vB:f:i:t:h")) != -1) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'f': cfg.filter=strdup(optarg); break; 
      case 'i': cfg.dev=strdup(optarg); break; 
      case 'B': cfg.capbuf=parse_kmg(optarg); break; 
      case 't': cfg.display_interval=atoi(optarg); break; 
      case 'h': default: usage(); break;
    }
  }

  if (cfg.capbuf == -1) goto done; // syntax error 

  /* block all signals. we take signals synchronously via signalfd */
  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* a few signals we'll accept via our signalfd */
  sigset_t sw;
  sigemptyset(&sw);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigaddset(&sw, sigs[n]);

  /* create the signalfd for receiving signals */
  cfg.signal_fd = signalfd(-1, &sw, 0);
  if (cfg.signal_fd == -1) {
    fprintf(stderr,"signalfd: %s\n", strerror(errno));
    goto done;
  }

  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* add descriptors of interest */
  if (new_epoll(EPOLLIN, cfg.signal_fd))   goto done; // signal socket

  /* open capture interface and get underlying descriptor */
  if ( (cfg.pcap = pcap_create(cfg.dev, cfg.err)) == NULL) {
    fprintf(stderr,"can't open %s: %s\n", cfg.dev, cfg.err); 
    goto done;
  }
  set_filter();
  if (pcap_set_promisc(cfg.pcap, 1))              {fprintf(stderr,"pcap_set_promisc failed\n"); goto done;}
  if (pcap_set_snaplen(cfg.pcap, cfg.snaplen))    {fprintf(stderr,"pcap_set_snaplen failed\n"); goto done;}
  if (pcap_set_buffer_size(cfg.pcap, cfg.capbuf)) {fprintf(stderr,"pcap_set_buf_size failed\n");goto done;}
  if (pcap_activate(cfg.pcap))                    {fprintf(stderr,"pcap_activate failed\n");    goto done; }
  cfg.pcap_fd = pcap_get_selectable_fd(cfg.pcap);
  if (cfg.pcap_fd == -1)                          {fprintf(stderr,"pcap_get_sel_fd failed\n");  goto done;}
  if (new_epoll(EPOLLIN, cfg.pcap_fd)) goto done;

  alarm(1);

  while (epoll_wait(cfg.epoll_fd, &ev, 1, -1) > 0) {
    if (cfg.verbose > 1)  fprintf(stderr,"epoll reports fd %d\n", ev.data.fd);
    if      (ev.data.fd == cfg.signal_fd)   { if (handle_signal() < 0) goto done; }
    else if (ev.data.fd == cfg.pcap_fd)     { if (get_pcap_data() < 0) goto done; }
  }

done:
  if (cfg.pcap) pcap_close(cfg.pcap);
  if (cfg.pcap_fd > 0) close(cfg.pcap_fd);
  utstring_free(cfg.label);
  abtop_free(cfg.abtop);
  return 0;
}
