#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int port = 3048;             /* no significance */
char *multicast_ipv6_addr = "ff02::1";

int main(int argc, char *argv[]) {

  char *buf = "hello, world!";
  int buflen = strlen(buf), rc;

  /**********************************************************
   * create an IPv4/UDP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd == -1) {
    printf("socket: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * internet socket address structure, for the remote side
   *********************************************************/
  struct sockaddr_in6 sin6;
  memset(&sin6,0,sizeof(sin6));
  if (inet_pton(AF_INET6, multicast_ipv6_addr, &sin6.sin6_addr) < 1) {
    fprintf(stderr,"inet_pton: error\n");
    exit(-1);
  }
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(port);

  /**********************************************************
   * don't use connect() for IPv6 multicast, use sendto
   *********************************************************/
  rc = sendto(fd,buf,buflen,0,(struct sockaddr*)&sin6,sizeof(sin6));
  if ( rc != buflen) {
    printf("sendto: %s\n", (rc<0)?strerror(errno):"incomplete");
    exit(-1);
  }
}
