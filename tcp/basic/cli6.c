#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int port = 6180;             /* no significance */

int main(int argc, char *argv[]) {

  char *buf = "hello, world!";
  int buflen = strlen(buf), rc;

  /**********************************************************
   * create an IPv6/TCP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd == -1) {
    printf("socket: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * internet socket address structure, for the remote side
   *********************************************************/
  struct sockaddr_in6 sin;
  sin.sin6_family = AF_INET6;
  sin.sin6_addr = in6addr_loopback;
  sin.sin6_port = htons(port);

  /**********************************************************
   * Perform the 3 way handshake, (c)syn, (s)ack/syn, c(ack)
   *********************************************************/
  if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    printf("connect: %s\n", strerror(errno));
    exit(-1);
  }

  if ( (rc=write(fd,buf,buflen)) != buflen) {
    printf("write: %s\n", (rc<0)?strerror(errno):"incomplete");
    exit(-1);
  }
  return 0;
}
