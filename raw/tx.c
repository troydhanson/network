/* 
 * Use a Linux AF_PACKET socket to write packets, bypassing the network stack.
 * 
 * see packet(7)
 *
 * also see
 *  sudo apt-get install linux-doc
 *  zcat /usr/share/doc/linux-doc/networking/packet_mmap.txt.gz
 *
 */

#include <errno.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>

#define MAX_PKT 65536

struct {
  int verbose;
  char *prog;
  char *odev;
  int odev_ifindex;
  int snaplen;
  int ticks;
  int vlan;
  int tail;
  int tx_fd;
  int signal_fd;
  int epoll_fd;
  char pkt[MAX_PKT];
  /* mmap'd input file */
  char *file;
  char *buf;
  char *pos;
  size_t len;
  int file_fd;
} cfg = {
  .odev = "lo",
  .signal_fd = -1,
  .epoll_fd = -1,
  .file_fd = -1,
};

void usage() {
  fprintf(stderr,"usage: %s [-v] [options]\n"
                 " options:      -i <file>    (pcap file)\n"
                 "               -o <eth>     (output interface)\n"
                 "               -V <vlan>    (inject VLAN tag)\n"
                 "               -s <snaplen> (tx snaplen bytes)\n"
                 "               -D <de-tail> (trim n tail bytes)\n"
                 "       TODO:   -t           (tx @ relative time)\n"
                 "       TODO:   -r           (packet range, repeatable)\n"
                 "\n",
          cfg.prog);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

int open_pcapfile(void) {
  struct stat s;
  int rc=-1;

  /* source file */
  if ( (cfg.file_fd = open(cfg.file, O_RDONLY)) == -1) {
    fprintf(stderr,"can't open %s: %s\n", cfg.file, strerror(errno));
    goto done;
  }
  if (fstat(cfg.file_fd, &s) == -1) {
    fprintf(stderr,"can't stat %s: %s\n", cfg.file, strerror(errno));
    goto done;
  }
  if (!S_ISREG(s.st_mode)) {
    fprintf(stderr,"not a regular file: %s\n", cfg.file);
    goto done;
  }
  cfg.len = s.st_size;
  cfg.buf = mmap(0, cfg.len, PROT_READ, MAP_PRIVATE, cfg.file_fd, 0);
  if (cfg.buf == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", cfg.file, strerror(errno));
    goto done;
  }

  /* skip pcap global header */
  uint32_t *magic_number =  (uint32_t*)cfg.buf;
  uint16_t *version_major = (uint16_t*)((char*)magic_number  + sizeof(*magic_number));
  uint16_t *version_minor = (uint16_t*)((char*)version_major + sizeof(*version_major));
  uint32_t *thiszone =      (uint32_t*)((char*)version_minor + sizeof(*version_minor));
  uint32_t *sigfigs =       (uint32_t*)((char*)thiszone      + sizeof(*thiszone));
  uint32_t *snaplen =       (uint32_t*)((char*)sigfigs       + sizeof(*sigfigs));
  uint32_t *network =       (uint32_t*)((char*)snaplen       + sizeof(*snaplen));
  
  char *cur = ((char*)network) + sizeof(*network);

  /* first packet header at cur */
  cfg.pos = cur;

  rc = 0;
 done:
  return rc;
}

int setup_tx(void) {
  int rc=-1, ec;

  /* any link layer protocol packets (linux/if_ether.h) */
  int protocol = htons(ETH_P_ALL);

  /* create the packet socket */
  cfg.tx_fd = socket(AF_PACKET, SOCK_RAW, protocol);
  if (cfg.tx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* convert interface name to index (in ifr.ifr_ifindex) */
  struct ifreq ifr; 
  strncpy(ifr.ifr_name, cfg.odev, sizeof(ifr.ifr_name));
  ec = ioctl(cfg.tx_fd, SIOCGIFINDEX, &ifr);
  if (ec < 0) {
    fprintf(stderr,"failed to find interface %s\n", cfg.odev);
    goto done;
  }
  cfg.odev_ifindex = ifr.ifr_ifindex;

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

int handle_signal(void) {
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

/* inject four bytes to the ethernet frame with an 802.1q vlan tag.
 * note if this makes MTU exceeded it may result in sendto error */
#define VLAN_LEN 4
char buf[MAX_PKT];
char vlan_tag[VLAN_LEN] = {0x81, 0x00, 0x00, 0x00};
#define MACS_LEN (2*6)
char *inject_vlan(char *tx, uint32_t *nx) {
  if (((*nx) + 4) > MAX_PKT) return NULL;
  if ((*nx) <= MACS_LEN) return NULL;
  /* prepare 802.1q tag vlan portion in network order */
  uint16_t v = htons(cfg.vlan);
  memcpy(&vlan_tag[2], &v, sizeof(v));
  /* copy MAC's from original packet, inject 802.1q, copy packet */
  memcpy(buf,                   tx,            MACS_LEN);
  memcpy(buf+MACS_LEN,          vlan_tag,      VLAN_LEN);
  memcpy(buf+MACS_LEN+VLAN_LEN, tx + MACS_LEN, (*nx) - MACS_LEN);
  *nx += 4;
  return buf;
}

int tx_packet(char *buf, uint32_t len) {
  int rc = -1;
  struct sockaddr_ll addr_x;
  socklen_t addrlen = sizeof(addr_x);

  if (cfg.verbose) fprintf(stderr,"sending %u byte packet\n", len);

  /* per packet(7) only these five fields should be set on outgoing addr_x */
  memset(&addr_x, 0, sizeof(addr_x));
  addr_x.sll_family = AF_PACKET;
  memcpy(addr_x.sll_addr, cfg.pkt, 6); /* copy dst mac from packet */
  addr_x.sll_halen = 6;                /* MAC len */
  addr_x.sll_ifindex = cfg.odev_ifindex;

  /* the sll_protocol is the ethernet proto in network order */
  if (buf + 14 > cfg.buf + cfg.len) {
     fprintf(stderr, "packet too short\n");
     goto done;
  }
  memcpy(&addr_x.sll_protocol, &buf[12], sizeof(uint16_t));

  /* inject 802.1q tag if requested */
  if (cfg.vlan) buf = inject_vlan(buf,&len);
  if (buf == NULL) {
    fprintf(stderr, "vlan tag injection failed\n");
    goto done;
  }

  /* truncate outgoing packet if requested */
  if (cfg.snaplen && (len > cfg.snaplen)) len = cfg.snaplen;

  /* trim N bytes from frame end if requested. */
  if (cfg.tail && (len > cfg.tail)) len -= cfg.tail;

  ssize_t nt;
  nt = sendto(cfg.tx_fd, buf, len, 0, (struct sockaddr*)&addr_x, addrlen);
  if (nt != len) {
    fprintf(stderr,"sendto: %s\n", (nt < 0) ? strerror(errno) : "partial");
    goto done;
  }

  rc = 0;

 done:
  return rc;

}

int next_packet(void) {
  int rc=-1;
  char *p;
  uint32_t plen;

  /* individual packets: guint32 sec, uint32 usec, uint32 incl_len, uint32 orig_len */
  if ((cfg.pos - cfg.buf) >= cfg.len) return 0;  /* end of input packets */

  p = cfg.pos;
  int npkts = 1;  /* packets per batch; TODO make input argument */
  while (npkts--) {
     if (p + 4*sizeof(uint32_t) > cfg.buf + cfg.len) {
       fprintf(stderr,"pcap header truncation, exiting\n");
       goto done;
     }
     uint32_t *sec =      (uint32_t*)p;
     uint32_t *usec =     (uint32_t*)((char*)sec      + sizeof(*sec));
     uint32_t *incl_len = (uint32_t*)((char*)usec     + sizeof(*usec));
     uint32_t *orig_len = (uint32_t*)((char*)incl_len + sizeof(*incl_len));
     p = (char*)((char*)orig_len + sizeof(*orig_len));
     plen = *incl_len;

     tx_packet(p,plen);
     p += plen;
     cfg.pos = p;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  struct epoll_event ev;
  cfg.prog = argv[0];
  int n,opt;

  while ( (opt=getopt(argc,argv,"vi:o:hV:s:D:")) != -1) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'i': cfg.file=strdup(optarg); break; 
      case 'o': cfg.odev=strdup(optarg); break; 
      case 'V': cfg.vlan=atoi(optarg); break; 
      case 's': cfg.snaplen=atoi(optarg); break; 
      case 'D': cfg.tail=atoi(optarg); break; 
      case 'h': default: usage(); break;
    }
  }

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
  if (setup_tx() < 0) goto done;

  /* set up reading input file */
  if (open_pcapfile() < 0) goto done;

  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* add descriptors of interest */
  if (new_epoll(EPOLLIN, cfg.signal_fd)) goto done; // signals

  alarm(1);

  while (epoll_wait(cfg.epoll_fd, &ev, 1, -1) > 0) {
    if (cfg.verbose > 1)  fprintf(stderr,"epoll reports fd %d\n", ev.data.fd);
    if      (ev.data.fd == cfg.signal_fd)   { if (handle_signal() < 0) goto done; }
    if (next_packet() <=0 ) goto done;
  }

done:
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.buf && (cfg.buf != MAP_FAILED)) munmap(cfg.buf, cfg.len);
  if (cfg.file_fd != -1) close(cfg.file_fd);
  return 0;
}
