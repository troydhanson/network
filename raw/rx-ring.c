/* 
 * Read packets using a AF_PACKET socket with PACKET_RX_RING
 * 
 * see packet(7)
 *
 * Ring setup and handling modeled on the PACKET_V3 example in
 * linux-doc /usr/share/doc/linux-doc/networking/packet_mmap.txt.gz
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
#include <sys/ioctl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

/* the ring includes an mmap'd region comprised of blocks. the iovec
 * point to these blocks. these blocks are the units of polling. a 
 * block is filled with packet frames and status bits. the ring of blocks
 * is shared between the kernel which populates it and this application. 
 * the application returns a block to the kernel by setting a bit flag. 
 * because the ring head is always where the next awaited packet goes,
 * it suffices to poll and then read this slot (check its status bit). */
struct ring {
  struct iovec *rd;
  uint8_t *map;
  struct tpacket_req3 req;
};

struct {
  int verbose;
  time_t now;
  char *prog;
  char *dev;
  char *out;
  int ticks;
  int rx_fd;
  int signal_fd;
  int epoll_fd;
  int out_fd;
  struct ring ring;
  unsigned ring_block_sz; /* see comments in initialization below */
  unsigned ring_block_nr;
  unsigned ring_frame_sz; /* with TPACKET_V3, frame sizes vary; must be a max?*/
} cfg = {
  .dev = "eth0",
  .out = "test.pcap",
  .rx_fd = -1,
  .signal_fd = -1,
  .epoll_fd = -1,
  .out_fd = -1,
  .ring_block_sz = 1 << 22, /*4 mb; want powers of two due to kernel allocator*/
  .ring_block_nr = 64,
  .ring_frame_sz = 1 << 11, /* 2048 bytes (expect MTU of 1500 plus a header */
};

void usage() {
  fprintf(stderr,"usage: %s [-v] [options]\n"
       " options: \n"
       " -i <eth>         -interface name\n"
       " -o <file.pcap>   -output file\n"
       " -B <num-blocks>  -packet ring num-blocks e.g. 64\n"
       " -S <block-size>  -packet ring block size log2 (e.g. 22 = 4mb)\n"
       " -F <frame-size>  -max frame (packet + header) size (e.g. 2048)\n"
       "\n", cfg.prog);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

int setup_rx(void) {
  int rc=-1, ec;

  /* any link layer protocol packets (linux/if_ether.h) */
  int protocol = htons(ETH_P_ALL);

  /* create the packet socket */
  cfg.rx_fd = socket(AF_PACKET, SOCK_RAW, protocol);
  if (cfg.rx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* convert interface name to index (in ifr.ifr_ifindex) */
  struct ifreq ifr; 
  strncpy(ifr.ifr_name, cfg.dev, sizeof(ifr.ifr_name));
  ec = ioctl(cfg.rx_fd, SIOCGIFINDEX, &ifr);
  if (ec < 0) {
    fprintf(stderr,"failed to find interface %s\n", cfg.dev);
    goto done;
  }
  
  /* PACKET_RX_RING comes in multiple versions. TPACKET_V3 is used here */
  int v = TPACKET_V3;
  ec = setsockopt(cfg.rx_fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_VERSION: %s\n", strerror(errno));
    goto done;
  }

  /* PACKET_RX_RING */
  memset(&cfg.ring.req, 0, sizeof(cfg.ring.req));
  cfg.ring.req.tp_block_size = cfg.ring_block_sz;
  cfg.ring.req.tp_frame_size = cfg.ring_frame_sz;
  cfg.ring.req.tp_block_nr = cfg.ring_block_nr;
  /* num frames (packets+headers) if every frame is max frame size. with
   * TPACKET_V3 frame sizes vary, so many more than this can fit in ring */
  cfg.ring.req.tp_frame_nr = (cfg.ring_block_sz * cfg.ring_block_nr) /
                             cfg.ring_frame_sz;
  cfg.ring.req.tp_retire_blk_tov = 60; /* timeout on block poll ? */
  cfg.ring.req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;  /* ? */
  if (cfg.verbose) {
    fprintf(stderr, "setting up PACKET_RX_RING:\n"
                   " (%u blocks * %u bytes per block) = %u bytes\n",
                   cfg.ring_block_nr, cfg.ring_block_sz,
                   cfg.ring_block_nr * cfg.ring_block_sz);
  }
  ec = setsockopt(cfg.rx_fd, SOL_PACKET, PACKET_RX_RING, &cfg.ring.req, 
                   sizeof(cfg.ring.req)); 
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_RX_RING: %s\n", strerror(errno));
    goto done;
  }

  /* map the ring buffer that we'll share with kernel */
  /* malloc something */

  /* bind to receive the packets from just one interface */
  struct sockaddr_ll sl;
  memset(&sl, 0, sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_protocol = protocol;
  sl.sll_ifindex = ifr.ifr_ifindex;
  ec = bind(cfg.rx_fd, (struct sockaddr*)&sl, sizeof(sl));
  if (ec < 0) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
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

  rc = 0;

 done:
  return rc;
}

void periodic_work() {
  cfg.now = time(NULL);
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

/* dump a single packet. our timestamp has 1sec resolution */
void dump(char *buf, size_t len) {
  unsigned len32 = (unsigned)len;
  unsigned zero = 0;
  unsigned now = (unsigned)cfg.now;

  write(cfg.out_fd, &now, sizeof(uint32_t));  /* ts_sec */
  write(cfg.out_fd, &zero, sizeof(uint32_t)); /* ts_usec */
  write(cfg.out_fd, &len32, sizeof(uint32_t)); /* caplen */
  write(cfg.out_fd, &len32, sizeof(uint32_t)); /* len */

  write(cfg.out_fd, buf, len); /* packet content */
}

int handle_packet(void) {
  int rc=-1;

  // dump(buf,nr);

  rc = 0;

 //done:
  return rc;
}

const uint8_t pcap_glb_hdr[] = {
 0xd4, 0xc3, 0xb2, 0xa1,  /* magic number */
 0x02, 0x00, 0x04, 0x00,  /* version major, version minor */
 0x00, 0x00, 0x00, 0x00,  /* this zone */
 0x00, 0x00, 0x00, 0x00,  /* sigfigs  */
 0xff, 0xff, 0x00, 0x00,  /* snaplen  */
 0x01, 0x00, 0x00, 0x00   /* network  */
};

int main(int argc, char *argv[]) {
  struct epoll_event ev;
  cfg.prog = argv[0];
  int n,opt;
  cfg.now=time(NULL);

  while ( (opt=getopt(argc,argv,"vi:o:B:S:F:h")) != -1) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'i': cfg.dev=strdup(optarg); break; 
      case 'o': cfg.out=strdup(optarg); break; 
      case 'B': cfg.ring_block_nr=atoi(optarg); break; 
      case 'S': cfg.ring_block_sz = 1 << (unsigned)atoi(optarg); break;
      case 'F': cfg.ring_frame_sz=atoi(optarg); break; 
      case 'h': default: usage(); break;
    }
  }

  cfg.out_fd = open(cfg.out,O_TRUNC|O_CREAT|O_WRONLY, 0644);
  if (cfg.out_fd < 0) {
    fprintf(stderr,"open: %s\n", strerror(errno));
    goto done;
  }
  write(cfg.out_fd, pcap_glb_hdr, sizeof(pcap_glb_hdr));

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
  if (cfg.out_fd != -1) {
    fprintf(stderr,"wrote %s\n", cfg.out);
    close(cfg.out_fd);
  }
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  /* FIXME munmap the ring and associated malloc */
  return 0;
}
