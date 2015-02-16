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
   * uses recvfrom to get data along with client address/port
   *********************************************************/
  do {
    struct sockaddr_in cin;
    socklen_t cin_sz = sizeof(cin);
    rc = recvfrom(fd,buf,BUFSZ,0,(struct sockaddr*)&cin,&cin_sz);
    if (rc==-1) printf("recvfrom: %s\n", strerror(errno));
    else {
      printf("received %d bytes from %s:%d: %.*s\n", rc, 
        inet_ntoa(cin.sin_addr), (int)ntohs(cin.sin_port), rc, buf);
    }
  } while (rc >= 0);
}
