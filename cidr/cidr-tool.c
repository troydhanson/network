#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* 
 *  cidr-util 
 *  a CIDR calculator 
 *  by Troy D. Hanson
 */

#define MODE_UNKNOWN        0
#define MODE_MASK_TO_N      1
#define MODE_N_TO_MASK      2
#define MODE_IN_SAME_NET    3
#define MODE_CIDR_EXPAND    4
#define MODE_RANGE_TO_CIDRS 5

/* standard bit vector macros */
#define BIT_TEST(c,i)  ((c[(i)/8] &   (1 << ((i) % 8))) ? 1 : 0)
#define BIT_SET(c,i)    (c[(i)/8] |=  (1 << ((i) % 8)))
#define BIT_CLEAR(c,i)  (c[(i)/8] &= ~(1 << ((i) % 8)))

struct {
  char *prog;
  int mode;
  int verbose;

  /* mode specific */
  int slash_n;
} CF;

void usage() {
  fprintf(stderr,"usage: %s [-v] <file>\n", CF.prog);
  exit(-1);
}

/* netmask is an IP with contiguous set bits then contiguous clear bits */
int is_netmask(char *w) {
  unsigned a, b, c, d, j;
  int rc = -1, sc;
  union {
    uint32_t i;
    uint8_t c[4];
  } addr, tmp;

  sc = sscanf(w, "%u.%u.%u.%u", &a, &b, &c, &d);
  if (sc != 4) goto done;
 
  struct in_addr ia;
  if (inet_aton(w, &ia) == 0) goto done;

  /* addr.i in network order. we want to convert it to little endian (which may
   * or may not be the same as host byte order, so we explicitly reverse it
   * instead of ntohl). we want it in little endian because our bit tests below
   * treat the MSB of the first byte as preceding the LSB of the second byte.
   */
  addr.i = ia.s_addr; 
  tmp.i = addr.i;
  addr.c[0] = tmp.c[3];
  addr.c[1] = tmp.c[2];
  addr.c[2] = tmp.c[1];
  addr.c[3] = tmp.c[0];

  /* addr.i is now little endian, meaning that c[0] is the least significant
   * octet. we verify that the address consists of a run of clear bits then a
   * run of set bits. Either run can have zero length.
    */

  int in_clear=1;

  for(j=0; j < 32; j++) {
    if (BIT_TEST(addr.c, j)) {
      CF.slash_n++;
      in_clear = 0;
    } else {
      if (in_clear) continue;
      goto done;  /* invalid; a clear bit in set region */
    }
  }

  rc = 0;

 done:
  return !rc;
}

/* slash followed by one or two digits <= 32 */
int is_slash_n(char *w) {
  unsigned n;
  int rc = -1, sc;

  sc = sscanf(w, "/%u", &n);
  if (sc < 1) goto done;
  if (n > 32) goto done;
  CF.slash_n = n;

  rc = 0;

 done:
  return !rc;
}

/* IP followed by a /N */
int is_cidr(char *w) {
  unsigned a, b, c, d, n;
  int rc = -1, sc;

  sc = sscanf(w, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &n);
  if (sc != 5) goto done;

  if ((a > 255) || (b > 255) || (c > 255) || (d > 255)) goto done;
  if (n > 32) goto done;

  rc = 0;

 done:
  return !rc;
}

/* four octets as dotted quad */
int is_ip(char *w) {
  unsigned a, b, c, d;
  int rc = -1, sc;

  sc = sscanf(w, "%u.%u.%u.%u", &a, &b, &c, &d);
  if (sc != 4) goto done;

  if ((a > 255) || (b > 255) || (c > 255) || (d > 255)) goto done;

  rc = 0;

 done:
  return !rc;
}

int infer_mode(int argc, char **argv) {
  int rc = -1;

  /* one argument? should be netmask or /N or cidr */
  if (argc == 1) {
    if      (is_netmask(*argv)) CF.mode = MODE_MASK_TO_N;
    else if (is_slash_n(*argv)) CF.mode = MODE_N_TO_MASK;
    else if (is_cidr(*argv))    CF.mode = MODE_CIDR_EXPAND;
    else goto done;
  }

  /* two arguments? should be start-ip end-ip */
  if (argc == 2) {
    if (is_ip(argv[0]) && is_ip(argv[1])) CF.mode = MODE_RANGE_TO_CIDRS;
    else goto done;
  }

  /* three+ arguments? should be netmask|/N ip1 ... */
  if (argc >= 3) {
    if      (is_netmask(*argv)) CF.mode = MODE_IN_SAME_NET;
    else if (is_slash_n(*argv)) CF.mode = MODE_IN_SAME_NET;
    else goto done;
  }
  
  rc = 0;
 
 done:
  return rc;
}

int generate_result(int argc, char *argv[]) {
  int rc = -1;
  uint32_t i=0,n=0,c=0,network=0;

  switch (CF.mode) {
    case MODE_MASK_TO_N:
      printf("/%u\n", CF.slash_n);
      break;
    case MODE_N_TO_MASK:
      while(n++ < CF.slash_n) i = (i >> 1U) | 0x80000000;
      struct in_addr ia = {.s_addr = htonl(i)};
      printf("%s\n", inet_ntoa(ia));
      break;
    case MODE_IN_SAME_NET:
      while(n++ < CF.slash_n) i = (i >> 1U) | 0x80000000;
      /* elide consumed argv/argc from slash_n */
      assert(argc);
      argc--;
      argv++;
      while(c < argc) {
        struct in_addr ia;
        if (inet_aton( argv[c], &ia) == 0) goto done;
        if (c++ == 0) network = i & ntohl(ia.s_addr);
        if ((i & ntohl(ia.s_addr)) != network) {
          printf("Addresses in different networks\n");
          rc = 0;
          goto done;
        }
      }
      printf("Addresses in same network\n");
      break;
    default:
      goto done;
      break;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  int opt, rc=-1, sc;

  CF.prog = argv[0];

  while ( (opt = getopt(argc,argv,"vh")) > 0) {
    switch(opt) {
      case 'v': CF.verbose++; break;
      case 'h': default: usage(argv[0]); break;
    }
  }

  assert(argc >= optind);
  argv += optind;
  argc -= optind;

  if (CF.mode == MODE_UNKNOWN) {
    sc = infer_mode(argc, argv);
    if (sc < 0) goto done;
  }

  sc = generate_result(argc,argv);
  if (sc < 0) goto done;

  rc = 0;
 
 done:
  if (rc < 0) usage();
  return rc;
}

