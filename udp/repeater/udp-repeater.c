#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/* udp-repeater
 *
 * example of use
 *
 *   udp-repeater -p 6180 -s destination1.net -s destination2.net
 *
 * This causes udp-repeater to listen on the local matchine (port 6180,
 * and you can specify a particular local IP address with the -l flag).
 * Whenever a UDP datagram is received, it is re-sent to each destination
 * (specified with the -s flag) on the same port as we received it on.
 *
 * To test it, run udp-repeater with appropriate arguments, set up a sink
 * to receive the datagrams somewhere, like:
 *
 *   destination1% nc -l -u 6180
 *
 * then generate some UDP datagrams to the repeater, e.g., 
 *
 *   somewhere% echo hi | nc -4 -u repeater-host 6180
 *
 * you sould see the udp datagram repeated on destination1.
 *
 * NOTE: when using nc to generate traffic, if you omit the -4 flag 
 *       and use a name (such as localhost) instead of an IPv4 address
 *       nc will use an IPv6 UDP datagram, which udp-repeater does not
 *       currently accept. 
 *
*/

#define BUFSZ 2000
char buf[BUFSZ];
char *ip;
int port;
int verbose;
char *prog;

#define MAX_DESTS 20
int ndests = 0;
struct sockaddr_in dest[MAX_DESTS];

void usage() {
  fprintf(stderr, "usage: %s [-v] [-l <listen-address>] -p <listen-port> "
                  "-s <destination-host> [-s <destination-host>]\n", prog);
  exit(-1);
}

void add_destination(char *host) {
  if (!port) {
    fprintf(stderr, "specify -p <port> before destination addresses\n");
    exit(-1);
  }
  if (ndests >= MAX_DESTS) {
    fprintf(stderr, "too many UDP destinations\n");
    exit(-1);
  }
  dest[ndests].sin_family = AF_INET;
  dest[ndests].sin_port = htons(port);

  struct hostent *h = gethostbyname(host);
  if (!h || !h->h_length) {
    fprintf(stderr, "could not resolve %s: %s\n", host, hstrerror(h_errno));
    exit(-1);
  }

  memcpy(&dest[ndests].sin_addr, h->h_addr, h->h_length);
  if (dest[ndests].sin_addr.s_addr == INADDR_NONE) {
    fprintf(stderr, "invalid IP address for %s\n", host);
    exit(-1);
  }

  if (verbose) fprintf(stderr,"repeat-to %s (%s):%d\n", host,
    inet_ntoa(dest[ndests].sin_addr), port);

  ndests++;
}
 
int main(int argc, char *argv[]) {
  prog = argv[0];
  int i, rc, sc, opt;

  while ( (opt = getopt(argc, argv, "v+l:p:s:")) != -1) {
    switch (opt) {
      case 'v': verbose++; break;
      case 'l': ip = strdup(optarg); break;
      case 'p': port = atoi(optarg); break;
      case 's': add_destination(optarg); break;
      default: usage(); break;
    }
  }

  if (!port) usage();
  if (!ndests) usage();

  in_addr_t listen_addr;
  if (ip) {
    if ( (listen_addr = inet_addr(ip)) == INADDR_NONE) {
      fprintf(stderr,"invalid listener IP address: %s\n", ip);
      exit(-1);
    }
  } else {
    listen_addr = htonl(INADDR_ANY);
    ip = "all-local-addresses";
  }
  if (verbose) fprintf(stderr, "local address: %s:%d\n", ip, port);

  /**********************************************************
   * create two IPv4/UDP sockets, for listener and repeater
   *********************************************************/
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  int rd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1 || rd == -1) { fprintf(stderr,"socket error\n"); exit(-1); }

  /**********************************************************
   * internet socket address structure: our address and port
   *********************************************************/
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = listen_addr;
  sin.sin_port = htons(port);

  /**********************************************************
   * bind socket to address and port we'd like to receive on
   *********************************************************/
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    fprintf(stderr, "bind to %s:%d failed: %s\n", ip, port, strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * uses recvfrom to get data along with client address/port
   *********************************************************/
  do {
    struct sockaddr_in cin;
    socklen_t cin_sz = sizeof(cin);
    rc = recvfrom(fd,buf,BUFSZ,0,(struct sockaddr*)&cin,&cin_sz);
    if (rc==-1) fprintf(stderr,"recvfrom: %s\n", strerror(errno));
    else {
      int len = rc;
      if (verbose>0) fprintf(stderr, "received %d bytes from %s:%d\n", len, 
          inet_ntoa(cin.sin_addr), (int)ntohs(cin.sin_port));
      if (verbose>1) fprintf(stderr, "%.*s\n", len, buf);
      for(i=0; i < ndests; i++) {
        struct sockaddr_in *d = &dest[i];
        if (verbose) fprintf(stderr, "sending %d bytes to %s:%d\n", len,
          inet_ntoa(d->sin_addr), (int)ntohs(d->sin_port));
        sc = sendto(rd, buf, len, 0, (struct sockaddr*)d, sizeof(*d));
        if (sc != len) {
          fprintf(stderr, "sendto %s: %s\n", inet_ntoa(d->sin_addr),
            (sc<0)?strerror(errno):"partial write");
          exit(-1);
        }
      }
    }
  } while (rc >= 0);
}
