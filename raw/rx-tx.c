/* 
 * Use a Linux AF_PACKET socket to read/write packets, bypassing the network stack.
 * 
 * see packet(7)
 *
 * also see
 *  sudo apt-get install linux-doc
 *  zcat /usr/share/doc/linux-doc/networking/packet_mmap.txt.gz
 *
 */

/*
 * Use ethtool(8) to disable hardware defragmentation for best results.
 *
 * ethtool -K $IF tso off
 * ethtool -K $IF ufo off
 * ethtool -K $IF gso off
 * ethtool -K $IF gro off
 * ethtool -K $IF lro off
 *
 * The idea is to avoid generating new outgoing packets from reassembled
 * incoming fragments.  In other words, if the NIC defrags two IP datagrams,
 * and hands us one large, reassembled datagram, it may exceed MTU. That's
 * fine unless we attempt to transmit it that way; with a raw socket that
 * generates an error. (IP would fragment it for us, in comparison).
 *
 * TODO detect; query outbound MTU; warn if outbound packet exceeds it
 * 
 * Furthermore iptables can block any packet in/out on the rx and tx
 * interfaces; this prevents the kernel from acting on them while still
 * providing visibility of them to the raw socket.
*/
 
#include <errno.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/signalfd.h>
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

#define MAX_PKT 65536

struct {
  int verbose;
  char *prog;
  char *idev;
  char *odev;
  int odev_ifindex;
  int nopromisc;
  int snaplen;
  int ticks;
  int vlan;
  int tail;
  int rx_fd;
  int tx_fd;
  int signal_fd;
  int epoll_fd;
  char pkt[MAX_PKT];
} cfg = {
  .idev = "eth0",
  .odev = "lo",
  .rx_fd = -1,
  .signal_fd = -1,
  .epoll_fd = -1,
};

void usage() {
  fprintf(stderr,"usage: %s [-v] [options]\n"
                 " options:      -i <eth>     (input interface)\n"
                 "               -o <eth>     (output interface)\n"
                 "               -P           (non-promisc mode)\n"
                 "               -V <vlan>    (inject VLAN tag)\n"
                 "               -s <snaplen> (tx snaplen bytes)\n"
                 "               -D <de-tail> (trim n tail bytes)\n"
                 "\n",
          cfg.prog);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

int setup_rx(void) {
  int rc=-1, ec;

  /* any link layer protocol packets (linux/if_ether.h) */
  int protocol = htons(ETH_P_ALL);
  //int protocol = htons(ETH_P_8021Q); /* FIXME */

  /* create the packet socket */
  cfg.rx_fd = socket(AF_PACKET, SOCK_RAW, protocol);
  if (cfg.rx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* convert interface name to index (in ifr.ifr_ifindex) */
  struct ifreq ifr; 
  strncpy(ifr.ifr_name, cfg.idev, sizeof(ifr.ifr_name));
  ec = ioctl(cfg.rx_fd, SIOCGIFINDEX, &ifr);
  if (ec < 0) {
    fprintf(stderr,"failed to find interface %s\n", cfg.idev);
    goto done;
  }

  /* bind to receive the packets from just one interface */
  struct sockaddr_ll sl;
  memset(&sl, 0, sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_protocol = protocol;
  sl.sll_ifindex = ifr.ifr_ifindex;
  //sl.sll_hatype = PACKET_HOST; /* FIXME want 8021q */
  ec = bind(cfg.rx_fd, (struct sockaddr*)&sl, sizeof(sl));
  if (ec < 0) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  if (cfg.nopromisc) {
    rc = 0;
    goto done;
  }

  /* set promiscuous mode to get all packets. */
  struct packet_mreq m;
  memset(&m, 0, sizeof(m));
  m.mr_ifindex = ifr.ifr_ifindex;
  m.mr_type = PACKET_MR_PROMISC;
  ec = setsockopt(cfg.rx_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &m, sizeof(m));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_ADD_MEMBERSHIP: %s\n", strerror(errno));
    goto done;
  }

  
  /* enable ancillary data, providing packet length and snaplen, 802.1Q, etc */
  int on = 1;
  ec = setsockopt(cfg.rx_fd, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_AUXDATA: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

/*
 socket(PF_PACKET, SOCK_RAW, 768)        = 3
 ioctl(3, SIOCGIFINDEX, {ifr_name="tee", ifr_index=7}) = 0
 bind(3, {sa_family=AF_PACKET, proto=0x03, if7, pkttype=PACKET_HOST, addr(0)={4, }, 20) = 0
 getsockopt(3, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
 ioctl(3, SIOCGIFHWADDR, {ifr_name="tee", ifr_hwaddr=00:0a:cd:2b:0f:b6}) = 0
 setsockopt(3, SOL_SOCKET, SO_BROADCAST, [1], 4) = 0
*/

int setup_tx(void) {
  int rc=-1, ec;

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

  /* bind interface. doing this to imitate tcpreplay */
  struct sockaddr_ll sl;
  memset(&sl, 0, sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_protocol = protocol;
  sl.sll_hatype = PACKET_HOST; /* using PACKET_HOST like tcpreplay; packet(7) says not needed */
  sl.sll_ifindex = cfg.odev_ifindex;
  ec = bind(cfg.tx_fd, (struct sockaddr*)&sl, sizeof(sl));
  if (ec < 0) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* setsockopt SO_BROADCAST like tcpreplay. is this really necessary? */
  int one = 1;
  ec = setsockopt(cfg.tx_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  if (ec < 0) {
    fprintf(stderr,"setsockopt SO_BROADCAST: %s\n", strerror(errno));
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
char *inject_vlan(char *tx, ssize_t *nx) {
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

int handle_packet(void) {
  int rc=-1;
  ssize_t nr,nt,nx;

  struct tpacket_auxdata *pa; /* for PACKET_AUXDATA; see packet(7) */
  struct cmsghdr *cmsg;
  struct {
    struct cmsghdr h;
    struct tpacket_auxdata a;
  } u;

  /* we get the packet and metadata via recvmsg */
  struct msghdr msgh;
  memset(&msgh, 0, sizeof(msgh));

  /* ancillary data; we requested packet metadata (PACKET_AUXDATA) */
  msgh.msg_control = &u;
  msgh.msg_controllen = sizeof(u);

#if 0
  struct sockaddr_ll addr_r;
  socklen_t addrlen = sizeof(addr_r);

  nr = recvfrom(cfg.rx_fd, cfg.pkt, sizeof(cfg.pkt), 0, 
                (struct sockaddr*)&addr_r, &addrlen);
  if (nr <= 0) {
    fprintf(stderr,"recvfrom: %s\n", nr ? strerror(errno) : "eof");
    goto done;
  }
#endif

  struct iovec iov;
  iov.iov_base = cfg.pkt;
  iov.iov_len = MAX_PKT;
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;

  nr = recvmsg(cfg.rx_fd, &msgh, 0);
  if (nr <= 0) {
    fprintf(stderr,"recvmsg: %s\n", nr ? strerror(errno) : "eof");
    goto done;
  }

  if (cfg.verbose) fprintf(stderr,"received %lu bytes of message data\n", (long)nr);
  if (cfg.verbose) fprintf(stderr,"received %lu bytes of control data\n", (long)msgh.msg_controllen);
  cmsg = CMSG_FIRSTHDR(&msgh);
  if (cmsg == NULL) {
    fprintf(stderr,"ancillary data missing from packet\n");
    goto done;
  }
  pa = (struct tpacket_auxdata*)CMSG_DATA(cmsg);
  if (cfg.verbose) fprintf(stderr, " packet length  %u\n", pa->tp_len);
  if (cfg.verbose) fprintf(stderr, " packet snaplen %u\n", pa->tp_snaplen);
  int losing = (pa->tp_status & TP_STATUS_LOSING) ? 1 : 0; 
  if (losing) fprintf(stderr, " warning; losing\n");
  int has_vlan = (pa->tp_status & TP_STATUS_VLAN_VALID) ? 1 : 0; 
  if (cfg.verbose) fprintf(stderr, " packet has vlan %c\n", has_vlan ? 'Y' : 'N');
  if (has_vlan) {
    uint16_t vlan_tci = pa->tp_vlan_tci;
    //uint16_t tci = ntohs(vlan_tci);
    uint16_t tci = vlan_tci;
    uint16_t vid = tci & 0xfff; // vlan VID is in the low 12 bits of the TCI
    if (cfg.verbose) fprintf(stderr, " packet vlan %d\n", vid);
    cfg.vlan = vid;
  }

  /* inject 802.1q tag if requested */
  char *tx = cfg.pkt;
  nx = nr;
  if (cfg.vlan) tx = inject_vlan(tx,&nx);
  if (tx == NULL) {
    fprintf(stderr, "vlan tag injection failed\n");
    goto done;
  }

  /* truncate outgoing packet if requested */
  if (cfg.snaplen && (nx > cfg.snaplen)) nx = cfg.snaplen;

  /* trim N bytes from frame end if requested. */
  if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

  nt = sendto(cfg.tx_fd, tx, nx, 0, NULL, 0);
  if (nt != nx) {
    fprintf(stderr,"sendto: %s\n", (nt < 0) ? strerror(errno) : "partial");
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  struct epoll_event ev;
  cfg.prog = argv[0];
  int n,opt;

  while ( (opt=getopt(argc,argv,"vi:o:hPV:s:D:")) != -1) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'i': cfg.idev=strdup(optarg); break; 
      case 'o': cfg.odev=strdup(optarg); break; 
      case 'P': cfg.nopromisc=1; break; 
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
  if (setup_rx() < 0) goto done;
  if (setup_tx() < 0) goto done;

  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* add descriptors of interest */
  if (new_epoll(EPOLLIN, cfg.signal_fd)) goto done; // signals
  if (new_epoll(EPOLLIN, cfg.rx_fd)) goto done;     // packets

  alarm(1);

  while (epoll_wait(cfg.epoll_fd, &ev, 1, -1) > 0) {
    if (cfg.verbose > 1)  fprintf(stderr,"epoll reports fd %d\n", ev.data.fd);
    if      (ev.data.fd == cfg.signal_fd)   { if (handle_signal() < 0) goto done; }
    else if (ev.data.fd == cfg.rx_fd)       { if (handle_packet() < 0) goto done; }
  }

done:
  if (cfg.rx_fd != -1) close(cfg.rx_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  return 0;
}
