#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSZ 200
int port = 6180;             /* no significance */

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
   * there is no listen/accept for UDP; read is all we need
   *********************************************************/
  do {
    rc = read(fd,buf,BUFSZ);
    if (rc==-1) printf("read: %s\n", strerror(errno));
    else printf("received %d bytes: %.*s\n", rc, rc, buf);
  } while (rc >= 0);
}
