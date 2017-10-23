#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>

/* send a udp packet 
 *
 * usage: send-udp [host port msg count delay]
 */

int main(int argc, char *argv[]) {
  int port, count, delay, len, rc;
  char *host, *buf;

  /**********************************************************
   * defaults apply unless arguments given
   *********************************************************/
  host =   (argc > 1) ? argv[1]       : "localhost";
  port =   (argc > 2) ? atoi(argv[2]) : 6180;
  buf =    (argc > 3) ? argv[3]       : "hello, world!";
  count =  (argc > 4) ? atoi(argv[4]) : 1;
  delay =  (argc > 5) ? atoi(argv[5]) : 1;
  len = strlen(buf);

  /**********************************************************
   * lookup host name in dns
   *********************************************************/
  struct hostent *h = gethostbyname(host);
  if (h == NULL) {
    fprintf(stderr, "gethostbyname: %s\n", hstrerror(h_errno));
    exit(-1);
  }
  struct in_addr ia = *(struct in_addr*)h->h_addr;
  in_addr_t addr = ia.s_addr;
  fprintf(stderr, "%s resolves to %s\n", host, inet_ntoa(ia));

  /**********************************************************
   * create an IPv4/UDP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * internet socket address structure, for the remote side
   *********************************************************/
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = addr;
  sin.sin_port = htons(port);

  /**********************************************************
   * sendto is specific to UDP; alternative to connect+write
   *********************************************************/
  while (count--) {
    rc = sendto(fd,buf,len,0,(struct sockaddr*)&sin,sizeof(sin));
    if (rc < 0) {
      fprintf(stderr,"sendto: %s\n", strerror(errno));
      exit(-1);
    }
    sleep(delay);
  }
}
