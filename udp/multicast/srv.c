#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSZ 200

char *group = "239.0.0.1";   /* an IP in multicast range */
int port = 3048;             /* no significance */

int main(int argc, char *argv[]) {

  char buf[BUFSZ];
  int rc;

  /**********************************************************
   * create an IPv4/UDP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    printf("socket: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * internet socket address structure: our address and port
   *********************************************************/
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  sin.sin_port = htons(port);

  /**********************************************************
   * bind socket to address and port we'd like to receive on
   *********************************************************/
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    printf("bind: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * join the multicast group we want to receive on 
   *********************************************************/
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(group); // Multicast IP
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);// any interface
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
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
