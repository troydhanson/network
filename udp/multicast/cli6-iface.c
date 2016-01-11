#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

/*
 *  see ipv6(7) manual page for excellent overview
 */

/* Send multicast _on a specific network interface_.
   This overrides the kernel's default choice.

   You can run this program with a trailing argument 
   like "eth1" to use that interface. Note that you may also
   need to "ifconfig eth1 multicast" to enable it.
*/

int port = 3048;             /* no significance */
char *multicast_ipv6_addr = "ff02::1";
char *iface = "eth0";        /* interface to send on */

int main(int argc, char *argv[]) {

  char *buf = "hello, world!";
  int buflen = strlen(buf), rc;
  if (argc > 1) iface = argv[1];

  /**********************************************************
   * create an IPv4/UDP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
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
  memcpy(ifr.ifr_name, iface, l+1);
  if (ioctl(fd, SIOCGIFINDEX, &ifr)) {printf("ioctl: %s\n", strerror(errno)); exit(-1);} 
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifr.ifr_ifindex, sizeof(ifr.ifr_ifindex))) {
    fprintf(stderr, "setsockopt: %s\n", strerror(errno));
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
