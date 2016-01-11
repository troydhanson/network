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

  /* look for an IPv6 address on the given interface. ask
   * the kernel to send multicast on this fd from it. */
  struct in6_addr src6;
  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs(&ifaddr) == -1) {
    fprintf(stderr,"getifaddrs: %s\n", strerror(errno));
    exit(-1);
  }
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (strcmp(ifa->ifa_name, iface)) continue;
    if (ifa->ifa_addr == NULL) continue;
    if ((ifa->ifa_flags & IFF_MULTICAST) == 0) continue;
    if (ifa->ifa_addr->sa_family != AF_INET6) continue;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6*)ifa->ifa_addr;
    src6 = a6->sin6_addr; /* struct copy */
    break;
  }
  if (ifa == NULL) {
    fprintf(stderr,"no multicast AF_INET6 interface %s\n", iface);
    exit(-1);
  }
  freeifaddrs(ifaddr);

  /* for human benefit - show the IPv6 address we wound up finding */
  char p6[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &src6, p6, sizeof(p6));
  printf("requesting multicast origination from %s on %s\n", p6, iface);

  if (setsockopt(fd, IPPROTO_IPV6, IP_MULTICAST_IF, &src6, sizeof(src6))) {
    fprintf(stderr, "setsockopt: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * don't use connect() for IPv6 multicast, use sendto
   *********************************************************/
  rc = sendto(fd,buf,buflen,0,(struct sockaddr*)&sin6,sizeof(sin6));
  if ( rc != buflen) {
    printf("sendto: %s\n", (rc<0)?strerror(errno):"incomplete");
    exit(-1);
  }
}
