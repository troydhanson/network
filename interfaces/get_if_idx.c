#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/* print the interface index of the device given as argument */

int main(int argc, char *argv[]) {
  struct ifreq ifr;
  char *eth = "eth0";
  if (argc > 1) eth = argv[1];

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) return -1;
  strncpy(ifr.ifr_name, eth, sizeof(ifr.ifr_name));

  /* get interface index of specified eth device */
  if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) return -1;
  printf("%s -> %d\n", eth, ifr.ifr_ifindex);

  return 0;
}
