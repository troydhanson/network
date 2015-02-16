#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSZ 200

char *multicast_ipv6_addr = "ff02::1"; /* an IPv6 multicast address */
int port = 3048;             /* no significance */

int main(int argc, char *argv[]) {

  char buf[BUFSZ];
  int rc;

  /**********************************************************
   * create an IPv6/UDP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd == -1) {
    printf("socket: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * internet socket address structure: our address and port
   *********************************************************/
  struct sockaddr_in6 sin6;
  memset(&sin6,0,sizeof(sin6));
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(port);

  /**********************************************************
   * bind socket to address and port we'd like to receive on
   *********************************************************/
  if (bind(fd, (struct sockaddr*)&sin6, sizeof(sin6)) == -1) {
    printf("bind: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * join the multicast group we want to receive on 
   *********************************************************/
  if (inet_pton(AF_INET6, multicast_ipv6_addr, &sin6.sin6_addr) < 1) {
    fprintf(stderr,"inet_pton: error\n");
    exit(-1);
  }
  struct ipv6_mreq mreq6;
  memset(&mreq6, 0, sizeof(mreq6));
  memcpy(&mreq6.ipv6mr_multiaddr, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
  mreq6.ipv6mr_interface = 0; // TODO hmm loopback
  // TODO IPV6_MULTICAST_LOOP
  // TODO IPV6_MULTICAST_HOPS
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) < 0) {
    printf("setsockopt: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * there is no listen/accept for UDP; read is all we need
   *********************************************************/
  do {
    rc = read(fd,buf,BUFSZ);
    if (rc==-1) printf("read: %s\n", strerror(errno));
    else printf("received %d bytes: %.*s\n", rc, rc, buf);
  } while (rc >= 0);
}
