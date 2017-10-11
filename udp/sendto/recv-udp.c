#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* receive udp packets
 *
 * usage: recv-udp [port]
 */

#define BUFSZ 200

int main(int argc, char *argv[]) {
  char buf[BUFSZ];
  int rc, port;

  /**********************************************************
   * defaults apply unless arguments given
   *********************************************************/
  port =   (argc > 1) ? atoi(argv[1]) : 6180;

  /**********************************************************
   * create an IPv4/UDP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
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
    fprintf(stderr,"bind: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * uses recvfrom to get data along with client address/port
   *********************************************************/
  do {
    struct sockaddr_in cin;
    socklen_t cin_sz = sizeof(cin);
    rc = recvfrom(fd, buf, BUFSZ, 0, (struct sockaddr*)&cin, &cin_sz);
    if (rc < 0) fprintf(stderr,"recvfrom: %s\n", strerror(errno));
    else fprintf(stderr,"received %d bytes from %s:%d: %.*s\n", rc, 
        inet_ntoa(cin.sin_addr), (int)ntohs(cin.sin_port), rc, buf);
  } while (rc >= 0);
}
