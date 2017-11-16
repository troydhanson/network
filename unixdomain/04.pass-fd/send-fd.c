#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

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
  fprintf(stderr,"usage: %s [-v] -f <socket> <file>\n", cfg.prog);
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

/* pass fd over unix domain socket sock_fd */
int pass_fd(int fd, int sock_fd) {
  struct msghdr hdr;
  struct iovec iov;
  int rc = -1, sc;

  /* Allocate a char array of suitable size to hold the ancillary data.
     However, since this buffer is in reality a 'struct cmsghdr', use a
     union to ensure that it is aligned as required for that structure. */
  union {
    struct cmsghdr cmh;
    char   control[CMSG_SPACE(sizeof(int))]; /* sized to hold an fd (int) */
  } control_un;
  memset(&control_un, 0, sizeof(control_un));

  /* we have to transmit at least 1 byte to send ancillary data */
  char unused = '*';
  iov.iov_base = &unused;
  iov.iov_len = sizeof(unused);

  /* point to iov to transmit */
  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  /* no dest address; socket is connected */
  hdr.msg_name = NULL; 
  hdr.msg_namelen = 0;
  /* control is where specificy SCM_RIGHTS (fd pass)*/
  hdr.msg_control = control_un.control;
  hdr.msg_controllen = sizeof(control_un.control);

  /* poke into the union which is now inside hdr */
  struct cmsghdr *hp;
  hp = CMSG_FIRSTHDR(&hdr);
  hp->cmsg_len = CMSG_LEN(sizeof(int));
  hp->cmsg_level = SOL_SOCKET;
  hp->cmsg_type = SCM_RIGHTS;
  *((int *) CMSG_DATA(hp)) = fd;

  sc = sendmsg(sock_fd, &hdr, 0);
  if (sc < 0) {
    fprintf(stderr,"sendmsg: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  int opt, rc=-1, sc, fd;
  cfg.prog = argv[0];
  pid_t pid;

  while ( (opt = getopt(argc,argv,"vhf:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'f': cfg.sock=strdup(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  if (cfg.sock == NULL) usage();
  if (optind >= argc) usage();

  /* open the unix domain socket (client end) */
  if (open_socket() < 0) goto done;

  /* open the file. we'll pass its fd over socket */
  fd = open(argv[optind], O_RDONLY);
  if (fd < 0) {
    fprintf(stderr,"open: %s\n", strerror(errno));
    goto done;
  }

  /* pass descriptor fd to peer over socket */
  if (pass_fd(fd, cfg.sock_fd) < 0) goto done;

  rc = 0;
 
 done:
  if (cfg.sock_fd != -1) close(cfg.sock_fd);
  return rc;
}
