#include <stdio.h>
#include <unistd.h>
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
   * create an IPv6/TCP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd == -1) {
    printf("socket: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * internet socket address structure: our address and port
   *********************************************************/
  struct sockaddr_in6 sin;
  memset(&sin,0,sizeof(sin));
  sin.sin6_family = AF_INET6;
  sin.sin6_port = htons(port);

  /**********************************************************
   * bind socket to address and port we'd like to receive on
   *********************************************************/
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    printf("bind: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * put socket into listening state 
   *********************************************************/
  if (listen(fd,1) == -1) {
    printf("listen: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * accept a connection, read til it closes, repeat
   *********************************************************/
  while (1) {
    struct sockaddr_in6 cin6;
    socklen_t sz = sizeof(cin6);
    int fa = accept(fd, (struct sockaddr*)&cin6, &sz);
    if (fa == -1) {
      printf("accept: %s\n", strerror(errno));
      continue;
    }
    if (sz==sizeof(struct sockaddr_in6)) {
      if (inet_ntop(AF_INET6, &cin6.sin6_addr, buf, sizeof(buf)))
        fprintf(stderr,"connection from %s\n", buf);
      else fprintf(stderr,"inet_ntop: %s\n", strerror(errno));
    }
    do {
      rc = read(fa,buf,BUFSZ);
      if (rc==-1) printf("read: %s\n", strerror(errno));
      else if (rc==0) printf("connection closed\n");
      else printf("received %d bytes: %.*s\n", rc, rc, buf);
    } while (rc > 0);
    close(fa);
  }
}
