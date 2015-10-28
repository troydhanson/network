#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

/* example program that uses getifaddrs(3) to get interfaces, 
   getnameinfo to get IP address and ioctl to get MAC address. */

/* gets the MAC addr for the interface */
int get_if_mac(char *eth, char *mac) {
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) return -1;
  strncpy(ifr.ifr_name, eth, sizeof(ifr.ifr_name));
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) return -1;
  memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
  return 0;
}

/* get all interfaces, their IPv4/v6 addr, and MAC.
 * this is based on the example in getifaddrs(3) */

int main(int argc, char *argv[]) {
     struct ifaddrs *ifaddr, *ifa;
     int family, s;
     char host[NI_MAXHOST];

     if (getifaddrs(&ifaddr) == -1) {
         perror("getifaddrs");
         exit(EXIT_FAILURE);
     }

     for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

         /* get name of interface and its family */
         family = ifa->ifa_addr->sa_family;
         if (! ((family == AF_INET) || (family == AF_INET6))) continue; 
         printf("interface %s ", ifa->ifa_name);
         printf("family %s ", family==AF_INET?"AF_INET":"AF_INET6");

         /* use getnameinfo to get IPv4/v6 address of interface */
         s = getnameinfo(ifa->ifa_addr,
                     (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                           sizeof(struct sockaddr_in6),
                     host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
         if (s != 0) {
            printf("getnameinfo() failed: %s\n", gai_strerror(s));
            continue;
         }
         printf("address %s ", host);

         /* get MAC address */
         unsigned char mac[IFHWADDRLEN];
         if (get_if_mac(ifa->ifa_name, mac) != 0) {
           printf("no MAC info\n"); 
           continue;
         }
         assert(IFHWADDRLEN == 6);
         printf("MAC %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n", 
          (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
          (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5]);
      }

     freeifaddrs(ifaddr);
     exit(EXIT_SUCCESS);
}

