#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/* print the MAC address of eth0 (or other interface given as argument) */

int main(int argc, char *argv[]) {
  unsigned char mac[IFHWADDRLEN];
  struct ifreq ifr;
  char *eth = "eth0";
  if (argc > 1) eth = argv[1];

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) return -1;
  strncpy(ifr.ifr_name, eth, sizeof(ifr.ifr_name));
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) return -1;
  memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);

  assert(IFHWADDRLEN == 6);
  printf("%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n", 
   (unsigned)mac[0],
   (unsigned)mac[1],
   (unsigned)mac[2],
   (unsigned)mac[3],
   (unsigned)mac[4],
   (unsigned)mac[5]);
  return 0;
}
