#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char *server = "127.0.0.1";  /* loopback */
int port = 6180;             /* no significance */

int main(int argc, char *argv[]) {

  char *buf = "hello, world!";
  int buflen = strlen(buf), rc;

  /**********************************************************
   * create an IPv4/UDP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    printf("socket: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * internet socket address structure, for the remote side
   *********************************************************/
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr(server);
  sin.sin_port = htons(port);

  if (sin.sin_addr.s_addr == INADDR_NONE) {
    printf("invalid remote IP %s\n", server);
    exit(-1);
  }

  /**********************************************************
   * sendto is specific to UDP; alternative to connect+write
   *********************************************************/
  rc = sendto(fd,buf,buflen,0,(struct sockaddr*)&sin,sizeof(sin));
  if (rc != buflen) {
    printf("sendto: %s\n", (rc<0)?strerror(errno):"incomplete");
    exit(-1);
  }
}
