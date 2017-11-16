#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

struct {
  int verbose;
  char *prog;
  char *sock; /* unix domain socket */
  int sock_fd;
} cfg = {
	.sock = "log.sk",
  .sock_fd = -1,
};

void usage() {
  fprintf(stderr,"usage: %s [-v] [-f <socket>]\n", cfg.prog);
  exit(-1);
}

int open_socket(void) {
  struct sockaddr_un addr;
  int sc, fd, rc = -1;

  cfg.sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (cfg.sock_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, cfg.sock, sizeof(addr.sun_path)-1);

  sc = connect(cfg.sock_fd, (struct sockaddr*)&addr, sizeof(addr));
  if (sc == -1) {
    fprintf(stderr,"connect: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  cfg.prog = argv[0];
  int opt, rc=-1, sc;

  while ( (opt = getopt(argc,argv,"vhf:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'f': cfg.sock=strdup(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  if (open_socket() < 0) goto done;

  /* we don't really need to send any data; the peer 
   * can get our pid from the connected socket itself */
  char unused = '*';
  sc = write(cfg.sock_fd, &unused, 1);
  if (sc < 0) {
    fprintf(stderr,"write: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;
 
 done:
  if (cfg.sock_fd != -1) close(cfg.sock_fd);
  return rc;
}
