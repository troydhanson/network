#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char *server = "::1";  /* loopback */
int port = 6180;             /* no significance */

int main(int argc, char *argv[]) {

  char *buf = "hello, world!";
  int buflen = strlen(buf), rc;

  /**********************************************************
   * create an IPv6/UDP socket, not yet bound to any address
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
  sin6.sin6_family = AF_INET6;
  rc = inet_pton(AF_INET6, server, &sin6.sin6_addr);
  if (rc < 1) {
    fprintf(stderr,"inet_pton: error\n");
    exit(-1);
  }
  sin6.sin6_port = htons(port);

  /**********************************************************
   * UDP is connectionless; connect only sets dest for writes
   *********************************************************/
  if (connect(fd, (struct sockaddr*)&sin6, sizeof(sin6)) == -1) {
    printf("connect: %s\n", strerror(errno));
    exit(-1);
  }

  if ( (rc=write(fd,buf,buflen)) != buflen) {
    printf("write: %s\n", (rc<0)?strerror(errno):"incomplete");
    exit(-1);
  }
}
