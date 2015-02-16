/* demonstrate usage of epoll-based pcap application */

#define _GNU_SOURCE
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pcap.h>
#include <time.h>

#define default_file_pat "%Y%m%d%H%M%S.pcap"

struct {
  int verbose;
  char *prog;
  char *dev;
  char *file_pat;
  char *dir;
  int rotate_sec;
  int maxsz_mb;
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
  /* savefile mapping */
  char *sv_addr;
  size_t sv_len;
  int    sv_fd;  
  time_t sv_ts;  /* time reflected in name of savefile */
  int    sv_seq; /* sequence number of save file within ts second */
  off_t  sv_cur; /* next write offset within save file */
} cfg = {
  .snaplen = 65535,
  .pcap_fd = -1,
  .dev = "eth0",
  .capbuf = (1024*1024),
  .file_pat = "%Y%m%d%H%M%S",
  .rotate_sec = 10,
  .maxsz_mb = 10,
  .dir = ".",
};

void usage() {
  fprintf(stderr,"usage: %s [-v] -f <bpf-filter>                \n"
                 "               -i <eth>        (read from interface)\n"
                 "               -B <cap-buf-sz> (capture buf size eg. 10m)\n"
                 "               -G <rotate-sec> (in sec)\n"
                 "               -C <file-size>  (in mb)\n"
                 "               -w <file-pat>   (eg. %s)\n"
                 "               -d <dir>        \n"
                 "\n",
          cfg.prog, default_file_pat);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

int periodic_work() {
  int rc=-1;
  /* test rotation interval */
  if (cfg.sv_addr && (cfg.sv_ts + cfg.rotate_sec < cfg.now)) {
    if (reopen_savefile()) goto done;
  }
  rc = 0;

 done:
  return rc;
}

void cb(u_char *data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  //if (cfg.verbose) fprintf(stderr,"packet of length %d\n", hdr->len);
  if (cfg.sv_addr == NULL) return;
  /* check if enough space remains in the mapped output area before writing */
  if (cfg.sv_cur + ((sizeof(uint32_t) * 4) + hdr->caplen) >= cfg.maxsz_mb*(1024*1024)) {
    if (reopen_savefile()) pcap_breakloop(cfg.pcap);
  }
  /* write packet header and packet. */
  memcpy(&cfg.sv_addr[cfg.sv_cur], &hdr->ts.tv_sec,  sizeof(uint32_t)); cfg.sv_cur += sizeof(uint32_t);
  memcpy(&cfg.sv_addr[cfg.sv_cur], &hdr->ts.tv_usec, sizeof(uint32_t)); cfg.sv_cur += sizeof(uint32_t);
  memcpy(&cfg.sv_addr[cfg.sv_cur], &hdr->caplen,     sizeof(uint32_t)); cfg.sv_cur += sizeof(uint32_t);
  memcpy(&cfg.sv_addr[cfg.sv_cur], &hdr->len,        sizeof(uint32_t)); cfg.sv_cur += sizeof(uint32_t);
  memcpy(&cfg.sv_addr[cfg.sv_cur], pkt, hdr->caplen);                   cfg.sv_cur += hdr->caplen;
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
      cfg.now = time(NULL);
      if (periodic_work()) goto done;
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
  int rc=-1, pc;

  pc = pcap_dispatch(cfg.pcap, 10000, cb, NULL);
  /* test for a pcap lib error, or a pcap_breakloop in the cb */
  if (pc == -1) { pcap_perror(cfg.pcap, "pcap error: "); goto done; }
  if (pc == -2) { fprintf(stderr, "ending capture\n"); goto done; }
  rc = 0;

 done:
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

int close_savefile() {
  int rc=-1;
  if (munmap(cfg.sv_addr, cfg.sv_len))  { fprintf(stderr,"munmap: %s\n", strerror(errno)); goto done; }
  if (ftruncate(cfg.sv_fd, cfg.sv_cur)) { fprintf(stderr,"ftruncate: %s\n", strerror(errno)); goto done; }
  if (close(cfg.sv_fd))                 { fprintf(stderr,"close: %s\n", strerror(errno)); goto done; }
  rc = 0;
 done:
  return rc;
}

#define FILE_MAX 250  /* better than FILENAME_MAX or PATH_MAX */
int reopen_savefile() {
  char filepath[FILE_MAX];
  char filename[FILE_MAX];
  struct stat s;
  char *buf=NULL;
  int fd=-1,rc=-1;
  uint32_t plen;

  /* close out current savefile, if we have one */
  if (cfg.sv_addr) {
    if (close_savefile()) goto done;
    cfg.sv_addr= NULL;
    cfg.sv_len = 0;
    cfg.sv_cur = 0;
    cfg.sv_fd  =-1;
    cfg.sv_seq = (cfg.sv_ts == cfg.now) ? (cfg.sv_seq+1) : 0;
  }

  /* format filename with strftime */
  cfg.sv_ts = cfg.now;
  if (strftime(filename, sizeof(filename), cfg.file_pat, localtime(&cfg.now)) == 0) {
    fprintf(stderr,"strftime: error in file pattern\n");
    goto done; 
  }
  snprintf(filepath, sizeof(filepath), "%s/%s%.2u.pcap", cfg.dir, filename, cfg.sv_seq);
  if (cfg.verbose) fprintf(stderr,"opening %s\n", filepath);

  /* map file into memory */
  if ( (cfg.sv_fd = open(filepath, O_RDWR|O_CREAT|O_EXCL, 0644)) == -1) { fprintf(stderr, "open %s: %s\n", filepath, strerror(errno)); goto done; }
  cfg.sv_len = cfg.maxsz_mb*(1024*1024);
  if (ftruncate(cfg.sv_fd, cfg.sv_len)) { fprintf(stderr, "ftruncate %s: %s\n", filepath, strerror(errno)); goto done; }
  cfg.sv_addr = mmap(0, cfg.sv_len, PROT_READ|PROT_WRITE, MAP_SHARED, cfg.sv_fd, 0);
  if (cfg.sv_addr == MAP_FAILED) { fprintf(stderr, "mmap %s: %s\n", filepath, strerror(errno)); goto done; }

  /* set up global header. */
  memcpy(&cfg.sv_addr[cfg.sv_cur], pcap_glb_hdr, sizeof(pcap_glb_hdr));
  cfg.sv_cur += sizeof(pcap_glb_hdr);

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
  time(&cfg.now);

  while ( (opt=getopt(argc,argv,"vB:f:i:hC:G:w:d:")) != -1) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'f': cfg.filter=strdup(optarg); break; 
      case 'i': cfg.dev=strdup(optarg); break; 
      case 'B': cfg.capbuf=parse_kmg(optarg); break; 
      case 'G': cfg.rotate_sec=atoi(optarg); break; 
      case 'C': cfg.maxsz_mb=atoi(optarg); break; 
      case 'w': cfg.file_pat=strdup(optarg); break; 
      case 'd': cfg.dir=strdup(optarg); break; 
      case 'h': default: usage(); break;
    }
  }

  if (cfg.capbuf == -1) goto done; // syntax error 
  if (reopen_savefile()) goto done;

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
  if (cfg.sv_addr) close_savefile();
  if (cfg.pcap) pcap_close(cfg.pcap);
  if (cfg.pcap_fd > 0) close(cfg.pcap_fd);
  return 0;
}
