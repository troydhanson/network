/* 
 * Use Linux AF_PACKET/SOCK_RAW with PACKET_RX_RING for rx.
 * 
 * see packet(7)
 *
 * also 
 *  sudo apt-get install linux-doc
 *  zcat /usr/share/doc/linux-doc/networking/packet_mmap.txt.gz
 *
 */

#include <errno.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

struct {
  int verbose;
  char *prog;
  char *dev;
  int ticks;
  int bufsz;
  int snaplen;
  int rx_fd;
  int signal_fd;
  int epoll_fd;
} cfg = {
  .snaplen = 65535,
  .dev = "eth0",
  .bufsz = 1024*1024*100, /* 100 mb */
  .rx_fd = -1,
  .signal_fd = -1,
  .epoll_fd = -1,
};

void usage() {
  fprintf(stderr,"usage: %s [-v] [options]\n"
                 " options:      -i <eth>        (read from interface)\n"
                 "               -B <cap-buf-sz> (capture buf size eg. 10m)\n"
                 "\n",
          cfg.prog);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

int get_interface(void) {
  int rc=-1, idx, family;
  struct ifaddrs *head, *ifa;

  rc = getifaddrs(&head);
  if (rc < 0) {
    fprintf(stderr, "getifaddrs: %s\n", strerror(errno));
    goto done;
  }

  for (ifa = head; ifa != NULL; ifa = ifa->ifa_next) {
     if (strcmp(ifa->ifa_name, cfg.dev)) continue;
     if (ifa->ifa_addr == NULL) continue;
     if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
  }

  freeifaddrs(head);
  rc = 0;

 done:
  return rc ? rc : idx;
}

int setup_rx(void) {
  int rc=-1;

  cfg.rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (cfg.rx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* set up promisc mode */
  struct packet_mreq m = {
    .mr_ifindex = 0, /* FIXME interface number */
    .mr_type = PACKET_MR_PROMISC,
  };
  rc = setsockopt(cfg.rx_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &m, sizeof(m));
  if (rc < 0) {
    fprintf(stderr,"setsockopt: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

void periodic_work() {
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
      cfg.ticks++;
      periodic_work();
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
  int n,opt;

  while ( (opt=getopt(argc,argv,"vB:f:i:h")) != -1) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'i': cfg.dev=strdup(optarg); break; 
      case 'B': cfg.bufsz=parse_kmg(optarg); break; 
      case 'h': default: usage(); break;
    }
  }

  if (cfg.bufsz == -1) goto done; // syntax error 

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

  /* set up the raw socket */
  if (setup_rx() < 0) goto done;

  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* add descriptors of interest */
  if (new_epoll(EPOLLIN, cfg.signal_fd))   goto done; // signal socket

  alarm(1);

  while (epoll_wait(cfg.epoll_fd, &ev, 1, -1) > 0) {
    if (cfg.verbose > 1)  fprintf(stderr,"epoll reports fd %d\n", ev.data.fd);
    if      (ev.data.fd == cfg.signal_fd)   { if (handle_signal() < 0) goto done; }
  }

done:
  if (cfg.rx_fd != -1) close(cfg.rx_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  return 0;
}
