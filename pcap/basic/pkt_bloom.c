#include <stdio.h>
#include <setjmp.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap.h>

char err[PCAP_ERRBUF_SIZE];
const int maxsz = 65535;
char *bf=NULL;
sig_atomic_t done = 0;
char *file = "bloom.dat";
int n=22;
jmp_buf env;

void usage(char *prog) {
  fprintf(stderr,"usage: %s [-i interface] [-f file] [-n log2-bloom-size] "
                 "[-t seconds]\n", prog);
  exit(-1);
}

void alarm_handler(int signo) {
  done=1;
  longjmp(env,1);
}

unsigned hash_ber(const char *in, size_t len) {
  unsigned hashv = 0;
  while (len--)  hashv = ((hashv) * 33) + *in++;
  return hashv;
}
unsigned hash_fnv(const char *in, size_t len) {
  unsigned hashv = 2166136261UL;
  while(len--) hashv = (hashv * 16777619) ^ *in++;
  return hashv;
}
#define MASK(u,n) ( u & ((1UL << n) - 1))
#define NUM_HASHES 2
void get_hashv(const char *in, size_t len, unsigned *out) {
  assert(NUM_HASHES==2);
  out[0] = MASK(hash_ber(in,len),n);
  out[1] = MASK(hash_fnv(in,len),n);
}

/* standard bit vector macros */
#define BIT_TEST(c,i)  ((c[(i)/8] &   (1 << ((i) % 8))) ? 1 : 0)
#define BIT_SET(c,i)    (c[(i)/8] |=  (1 << ((i) % 8)))
#define BIT_CLEAR(c,i)  (c[(i)/8] &= ~(1 << ((i) % 8)))
/* number of bytes needed to store 2^n bits */
#define byte_len(n) (((1UL << n) / 8) + (((1UL << n) % 8) ? 1 : 0))
/* number of bytes needed to store n bits */
#define bytes_nbits(n) ((n/8) + ((n % 8) ? 1 : 0))
/* number of bits in 2^n bits */
#define num_bits(n) (1UL << n)
char *bf_new(unsigned n) {
  char *bf = calloc(1,byte_len(n));
  return bf;
}
void bf_insert(char *bf, const char *data, size_t len) {
  unsigned i, hashv[NUM_HASHES];
  get_hashv(data,len,hashv);
  for(i=0;i<NUM_HASHES;i++) BIT_SET(bf,hashv[i]);
}
void bf_info(char *bf, FILE *f) {
  unsigned i, on=0;
  for(i=0; i<num_bits(n); i++) 
    if (BIT_TEST(bf,i)) on++;

  fprintf(f, "%.2f%% saturation (%lu bits)\n", on*100.0/num_bits(n), num_bits(n));
}
 
void cb(u_char *data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  //printf("packet of length %d\n", hdr->len);
  bf_insert(bf, pkt, hdr->caplen);
}

int main(int argc, char *argv[]) {
  pcap_t *p=NULL;
  int rc=-1;
  char *dev="eth0";

  int opt, timer=60;
 
  while ( (opt = getopt(argc, argv, "n:i:hf:t:v+")) != -1) {
    switch (opt) {
      case 'n': n = atoi(optarg); break;
      case 'i': dev = strdup(optarg); break;
      case 'f': file = strdup(optarg); break;
      case 't': timer = atoi(optarg); break;
      case 'h': default: usage(argv[0]);  break;
    }
  }

  int fd  = open(file,O_WRONLY|O_TRUNC|O_CREAT,0666);
  if (fd < 0) {
    fprintf(stderr, "can't open %s: %s\n", file, strerror(errno));
    goto done;
  }
  signal(SIGALRM, alarm_handler);

  if (!dev) dev = pcap_lookupdev(err);
  if (dev == NULL) {
    fprintf(stderr, "no device: %s\n", err);
    goto done;
  }

  p = pcap_open_live(dev, maxsz, 1, 0, err);
  if (p == NULL) {
    fprintf(stderr, "can't open %s: %s\n", dev, err);
    goto done;
  }

  alarm(timer);
  bf = bf_new(n);

  setjmp(env);
  if (!done) rc = pcap_loop(p, 0, cb, NULL);

  fprintf(stderr, "writing %s\n", file);
  if (write(fd, bf, byte_len(n)) != byte_len(n)) {
    fprintf(stderr, "write: %s\n", strerror(errno));
    goto done;
  }
  close(fd);
  bf_info(bf,stderr);

  rc = 0;

 done:
  if (bf) free(bf);
  return rc;
}

