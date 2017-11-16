#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

/* this program connects to a socket in the abstract namespace;
 * the leading null byte in its name is implicit. it does not 
 * put a trailing null byte on the socket name, because autobind
 * generated socket names do not have one.
 *
 */

int main(int argc, char *argv[]) {
  struct sockaddr_un addr;
  char *socket_name;
  int fd=-1,rc=-1,sc;
  size_t len;
  char *buf;

  if (argc < 2) {
    fprintf(stderr, "usage: %s <name> (omit leading nul)\n", argv[0]);
    goto done;
  }

  socket_name = argv[1];

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "socket: %s", strerror(errno));
    goto done;
  }

  /* abstract socket namespace has leading null byte then string */
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  *addr.sun_path = '\0';
  strncpy(addr.sun_path+1, socket_name, sizeof(addr.sun_path)-1);

  /* the length when connecting to an abstract socket is the
   * initial sa_family_t (2 bytes) plus leading null byte + name 
   * (no trailing null in the name, for an autobind socket) */
  socklen_t slen = sizeof(sa_family_t)+1+strlen(socket_name);
  sc = connect(fd, (struct sockaddr*)&addr, slen);
  if (sc < 0) {
    fprintf(stderr,"connect: %s\n", strerror(errno));
    goto done;
  }

  buf = (argc > 2) ? argv[2] : "hello, world!";
  len = strlen(buf);
  sc = write(fd, buf, len);
  if (sc < 0) {
    fprintf(stderr,"write: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  if (fd != -1) close(fd);
  return rc;
}
