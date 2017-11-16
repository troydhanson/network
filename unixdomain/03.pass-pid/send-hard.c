#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

/*
  From "The Linux Programming Interface", by Michael Kerrisk, section 61.13:

  > 61.13.4 Receiving Sender Credentials
  > Another example of the use of ancillary data is for receiving sender
  > credentials via a UNIX domain socket. These credentials consist of the user
  > ID, the group ID, and the process ID of the sending process. The sender may
  > specify its user and group IDs as the corresponding real, effective, or saved
  > set IDs. This allows the receiving process to authenticate a sender on the
  > same host. For further details, see the socket(7) and unix(7) manual pages.
  > Unlike passing file descriptors, passing sender credentials is not specified
  > in SUSv3.  On Linux, a privileged process can fake the user ID, group ID, and
  > process ID that are passed as credentials if it has, respectively, the
  > CAP_SETUID, CAP_SETGID, and CAP_SYS_ADMIN capabilities.
*/

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

/* pass pid/uid/gid creds over unix domain socket sock_fd */
int pass_creds(void) {
  struct msghdr hdr;
  struct iovec iov;
  int rc = -1, sc;

  /* we have to transmit at least 1 byte to send ancillary data */
  char unused = '*';
  iov.iov_base = &unused;
  iov.iov_len = sizeof(unused);

  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  /* no dest address; socket is connected */
  hdr.msg_name = NULL; 
  hdr.msg_namelen = 0;
  /* control is null; transmit real creds */
  hdr.msg_control = NULL;
  hdr.msg_controllen = 0;

  sc = sendmsg(cfg.sock_fd, &hdr, 0);
  if (sc < 0) {
    fprintf(stderr,"sendmsg: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  cfg.prog = argv[0];
  int opt, rc=-1;

  while ( (opt = getopt(argc,argv,"vhf:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'f': cfg.sock=strdup(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  if (open_socket() < 0) goto done;
  if (pass_creds() < 0) goto done;

  rc = 0;
 
 done:
  if (cfg.sock_fd != -1) close(cfg.sock_fd);
  return rc;
}
