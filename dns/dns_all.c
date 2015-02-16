#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* look up and print all the IP addresses of the given host */

int main(int argc, char*argv[]) {
  char *host = (argc > 1) ? argv[1] : "localhost";
  struct hostent *h=gethostbyname(host);
  if (h) {
    struct in_addr**ia = (struct in_addr**)h->h_addr_list;
    while (*ia) printf("%s\n", inet_ntoa(**(ia++)));
  }
  else printf("%s\n", hstrerror(h_errno));
}
