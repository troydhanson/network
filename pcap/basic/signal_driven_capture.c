#define _GNU_SOURCE
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pcap.h>

struct {
  int verbose;
  char *dev;    /* capture interface */
  pcap_t *pcap;
  int pcap_fd;  /* selectable descriptor for capture */
} cfg;

char err[PCAP_ERRBUF_SIZE];
const int maxsz = 65535;

/* signals that we'll unblock during sigsuspend.
 * first is placeholder because SIGRTMIN may not be a compile-time define. */
int sigs[] = {0,SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage(char *prog) {
  fprintf(stderr, "usage: %s [-v] -i <interface>\n", prog);
  exit(-1);
}

void do_stats(void) {
  struct pcap_stat ps;
  if (pcap_stats(cfg.pcap,&ps)<0) {fprintf(stderr,"pcap_stat error\n"); return;}
  fprintf(stderr,"received : %u\n", ps.ps_recv);
  fprintf(stderr,"dropped: %u\n", ps.ps_drop);
}

void cb(u_char *data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  if (cfg.verbose) fprintf(stderr,"packet of length %d\n", hdr->len);
}

int main(int argc, char *argv[]) {
  sigs[0] = SIGRTMIN+0; /* we'll use this RT signal for I/O readiness */
  int opt, fd, fl, rc=-1, n;

  while ( (opt = getopt(argc, argv, "v+i:")) != -1) {
    switch (opt) {
      case 'v': cfg.verbose++; break;
      case 'i': cfg.dev=strdup(optarg); break;
      default: usage(argv[0]); break;
    }
  }
  if (!cfg.dev) { fprintf(stderr, "no device: %s\n", err); usage(argv[0]); }

  /* block all signals. we stay blocked always except in sigwaitinfo */
  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* open capture interface and get underlying descriptor */
  cfg.pcap = pcap_open_live(cfg.dev, maxsz, 1, 0, err);
  if (!cfg.pcap) {fprintf(stderr,"can't open %s: %s\n",cfg.dev,err); goto done;}
  cfg.pcap_fd = pcap_get_selectable_fd(cfg.pcap);
  if (cfg.pcap_fd<0) {fprintf(stderr,"can't get pcap descriptor\n"); goto done;}
  rc = pcap_setnonblock(cfg.pcap, 1, err);
  if (rc== -1) {fprintf(stderr,"can't set pcap nonblock: %s\n",err); goto done;}

  /* request signal SIGRTMIN to be sent to us when descriptor ready */
  fl = fcntl(cfg.pcap_fd, F_GETFL); 
  fl |= O_ASYNC;                            /* want a signal on fd ready */
  fcntl(cfg.pcap_fd, F_SETFL, fl);
  fcntl(cfg.pcap_fd, F_SETSIG, sigs[0]);    /* use this instead of SIGIO */
  fcntl(cfg.pcap_fd, F_SETOWN, getpid());   /* send it to our pid */

  /* a small set of signals we'll accept during sigwaitinfo */
  sigset_t sw;
  sigemptyset(&sw);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigaddset(&sw, sigs[n]);

  siginfo_t info;
  int signo,sigfd;
  alarm(10);

  while ( (signo = sigwaitinfo(&sw, &info)) > 0) {
    switch(signo) {

      case SIGALRM:
        do_stats();
        alarm(10);
        break;

      default:
        if(signo!=sigs[0]) {fprintf(stderr,"got signal %d\n",signo); goto done;}

        /* SIGRTMIN: capture descriptor is readable. dequeue packets */
        rc = pcap_dispatch(cfg.pcap,-1,cb,NULL);
        if (rc<0) { pcap_perror(cfg.pcap,"pcap error: "); goto done; }
        break;
    }
  }

 done:
  if (cfg.pcap) pcap_close(cfg.pcap);
  free(cfg.dev);
  return 0;
}
