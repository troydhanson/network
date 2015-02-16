#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Send multicast _on a specific network interface_.
   This overrides the kernel's default choice.

   You can run this program with a trailing argument 
   like "lo" to use loopback. Note that you may also
   need to "ifconfig lo multicast" to enable it.
*/

char *server = "239.0.0.1";  /* a multicast address */
int port = 3048;             /* no significance */
char *iface = "eth0";        /* interface to send on */

int main(int argc, char *argv[]) {

  if (argc > 1) iface = argv[1];

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
   * ask the kernel to use a specific interface for multicast
   *********************************************************/
  int l = strlen(iface);
  if (l+1 >IFNAMSIZ) {printf("interface too long\n"); exit(-1);}

  struct ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;
  memcpy(ifr.ifr_name, iface, l+1);

  /* does this interface support multicast? */
  if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {printf("ioctl: %s\n", strerror(errno)); exit(-1);} 
  if (!(ifr.ifr_flags & IFF_MULTICAST)) {printf("%s does not multicast\n",iface); exit(-1);}

  /* get the interface IP address */
  struct in_addr iface_addr;
  if (ioctl(fd, SIOCGIFADDR, &ifr)) {printf("ioctl: %s\n", strerror(errno)); exit(-1);} 
  iface_addr = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
  printf("iface %s has addr %s\n", iface, inet_ntoa(iface_addr));

  /* ask kernel to use its IP address for outgoing multicast */
  if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &iface_addr, sizeof(iface_addr))) {
    printf("setsockopt: %s\n", strerror(errno));
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
   * UDP is connectionless; connect only sets dest for writes
   *********************************************************/
  if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    printf("connect: %s\n", strerror(errno));
    exit(-1);
  }

  if ( (rc=write(fd,buf,buflen)) != buflen) {
    printf("write: %s\n", (rc<0)?strerror(errno):"incomplete");
    exit(-1);
  }
}
