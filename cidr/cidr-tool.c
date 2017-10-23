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
  int mode;
  int verbose;

  /* mode specific */
  int slash_n;
  uint32_t cidr;
} CF;

void usage() {
  fprintf(stderr,"usage: cidr-tool <operation>\n\n");
  fprintf(stderr," operations:\n\n");
  fprintf(stderr,"  <netmask>                  (netmask to /N)\n");
  fprintf(stderr,"  /N                         (/N to netmask)\n");
  fprintf(stderr,"  <netmask>|/N <IP> <IP> ... (test if IPs in same network)\n");
  fprintf(stderr,"  <CIDR/N>                   (print IP's in CIDR)\n");
  fprintf(stderr,"  <start-IP> <end-IP>        (make CIDR ranges from IP range)\n");
  fprintf(stderr,"\n");
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

  CF.cidr = (a << 24) | (b << 16) | (c << 8) | d;
  CF.slash_n = n;

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

void print_cidr(uint32_t cidr, uint32_t n) {
  uint64_t mask = ~((1UL << (32-n)) - 1);
  struct in_addr ia = {.s_addr = htonl(cidr & mask)};
  printf("%s/%u\n", inet_ntoa(ia), n);
}

uint32_t min_cidr(uint32_t cidr, uint32_t n) {
  uint64_t mask = ~((1UL << (32-n)) - 1);
  return cidr & mask;
}

uint32_t max_cidr(uint32_t cidr, uint32_t n) {
  uint64_t mask = ~((1UL << (32-n)) - 1);
  return (cidr & mask) | ~mask;
}

int in_cidr(uint32_t ip, uint32_t cidr, uint32_t n) {
  uint64_t mask = ~((1UL << (32-n)) - 1);
  return ((cidr & mask) == (ip & mask)) ? 1 : 0;
}

/* attempt to widen CIDR/n by one or more bits (shrinking /N)
 * until it encompasses ip; succeed only if the new CIDR range
 * is inside of bounds ip_A (min) and ip_B (max) inclusive. 
 *
 * returns 0 on failure, or the new /N on success 
 *
 */
uint32_t widen_cidr(uint32_t cidr, uint32_t n, uint32_t ip,
                    uint32_t ip_A, uint32_t ip_B) {
  int rc = -1;

  while(n > 1) {
    n--;
    if (!in_cidr(ip, cidr, n)) continue;
    if (min_cidr(cidr, n) < ip_A) goto done;
    if (max_cidr(cidr, n) > ip_B) goto done;
    rc = 0;
    break;
  }

 done:
  return (rc < 0) ? 0 : n;
}

int generate_result(int argc, char *argv[]) {
  uint32_t n=0,c=0,network=0,m;
  uint64_t mask;
  int rc = -1;

  switch (CF.mode) {
    case MODE_MASK_TO_N:
      printf("/%u\n", CF.slash_n);
      break;
    case MODE_N_TO_MASK:
      mask = ~((1UL << (32-CF.slash_n)) - 1);
      struct in_addr ia = {.s_addr = htonl(mask)};
      printf("%s\n", inet_ntoa(ia));
      break;
    case MODE_IN_SAME_NET:
      mask = ~((1UL << (32-CF.slash_n)) - 1);
      assert(argc);
      argc--;
      argv++;
      while(c < argc) {
        struct in_addr ia;
        if (inet_aton( argv[c], &ia) == 0) goto done;
        if (c++ == 0) network = mask & ntohl(ia.s_addr);
        if ((mask & ntohl(ia.s_addr)) != network) {
          printf("Addresses in different networks\n");
          rc = 0;
          goto done;
        }
      }
      printf("Addresses in same network\n");
      break;
    case MODE_CIDR_EXPAND:
      mask = ~((1UL << (32-CF.slash_n)) - 1);
      uint32_t num_host_bits = 32 - CF.slash_n;
      uint64_t num_permutations = 1U << num_host_bits;
      uint64_t h = 0;
      while(h < num_permutations) {
        uint32_t ip = (CF.cidr & mask) | h++;
        struct in_addr ia = {.s_addr = htonl(ip)};
        printf("%s\n", inet_ntoa(ia));
      }
      break;
    case MODE_RANGE_TO_CIDRS:
      if (argc != 2) goto done;
      struct in_addr a, b;
      uint64_t ip_A, ip_B, ip; /* prevents rollover */
      uint32_t cidr;
      if (inet_aton(argv[0], &a) == 0) goto done;
      if (inet_aton(argv[1], &b) == 0) goto done;
      ip_A = ntohl(a.s_addr);
      ip_B = ntohl(b.s_addr);
      if (ip_A > ip_B) goto done;
      cidr = ip_A;
      n = 32;
      for(ip = ip_A; ip <= ip_B; ip++) {
        if (in_cidr(ip, cidr, n)) continue;
        m = widen_cidr(cidr, n, ip, ip_A, ip_B);
        if (m == 0) {
          print_cidr(cidr, n); /* close prior range */
          cidr = ip;           /* start a new range */
          n = 32;
        } else n = m;
      }
      print_cidr(cidr, n);
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

