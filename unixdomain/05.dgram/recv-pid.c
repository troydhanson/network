#define _GNU_SOURCE /* To get SCM_CREDENTIALS definition from <sys/sockets.h> */

#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

/* 
   The example uses some sample code from scm_cred_recv.c by Michael Kerrisk.

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
  char *file; /* unix domain socket */
  char *prog;
  int sock_fd;     /* listening descriptor */
  int epoll_fd;
  int signal_fd;
} cfg = {
	.file = "log.sk",
  .sock_fd = -1,
  .epoll_fd = -1,
  .signal_fd = -1,
};

void usage() {
  fprintf(stderr,"usage: %s [-v] -f <socket>\n", cfg.prog);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

int bind_socket(void) {
  struct sockaddr_un addr;
  int sc, rc = -1;

  cfg.sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (cfg.sock_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, cfg.file, sizeof(addr.sun_path)-1);
  unlink(cfg.file);

  sc = bind(cfg.sock_fd, (struct sockaddr*)&addr, sizeof(addr));
  if (sc == -1) {
    fprintf(stderr,"bind: %s\n", strerror(errno));
    goto done;
  }

  /* set SO_PASSCRED option on socket; get creds in recvmsg */
  int one = 1;
  sc = setsockopt(cfg.sock_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
  if (sc < 0) {
    fprintf(stderr,"setsockopt: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int new_epoll(int events, int fd) {
  struct epoll_event ev;
  int rc;
  memset(&ev,0,sizeof(ev)); // placate valgrind
  ev.events = events;
  ev.data.fd= fd;
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

int periodic_work(void) {
	int rc = -1;
  rc = 0;
	return rc;
}

int handle_signal() {
  struct signalfd_siginfo info;
	ssize_t nr;
  int rc=-1;
  
  nr = read(cfg.signal_fd, &info, sizeof(info));
  if (nr != sizeof(info)) {
    fprintf(stderr,"failed to read signal fd buffer\n");
    goto done;
  }

  switch(info.ssi_signo) {
    case SIGALRM: 
      if (periodic_work() < 0) goto done;
      alarm(1); 
      break;
    default: 
      fprintf(stderr,"got signal %d\n", info.ssi_signo);  
      goto done;
      break;
  }

 rc = 0;

 done:
  return rc;
}

int handle_client(int fd) {
  char buf[1000], *l;
  ssize_t nr, n;
  int rc = -1;

	/* Allocate a char array of suitable size to hold the ancillary data.
		 However, since this buffer is in reality a 'struct cmsghdr', use a
		 union to ensure that it is aligned as required for that structure. */
	union {
		struct cmsghdr cmh;
		char   control[CMSG_SPACE(sizeof(struct ucred))];
	} control_un;
  memset(&control_un, 0, sizeof(control_un));

  /* Set 'control_un' to describe ancillary data that we want to receive */
  control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
  control_un.cmh.cmsg_level = SOL_SOCKET;
  control_un.cmh.cmsg_type = SCM_CREDENTIALS;

  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  /* Set hdr fields to describe 'control_un' */
  struct msghdr hdr;
  hdr.msg_control = control_un.control;
  hdr.msg_controllen = sizeof(control_un.control);
  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  hdr.msg_name = NULL; /* no peer address */
  hdr.msg_namelen = 0;

  nr = recvmsg(fd, &hdr, 0);
  if (nr < 0) {
    fprintf(stderr,"read: %s\n", strerror(errno));
    goto done;
  }
  else if (nr == 0) { /* normal client closure */
    if (cfg.verbose) fprintf(stderr,"read: eof\n");
    close(fd);
  } else {

    assert(nr > 0);

    /* Extract credentials information from ancillary data if present */
    struct cmsghdr *cmhp;
    cmhp = CMSG_FIRSTHDR(&hdr);
    if (cmhp                                              && 
       (cmhp->cmsg_len == CMSG_LEN(sizeof(struct ucred))) &&
       (cmhp->cmsg_level == SOL_SOCKET)                   && 
       (cmhp->cmsg_type == SCM_CREDENTIALS)) {

      struct ucred *ucredp = (struct ucred *) CMSG_DATA(cmhp);
      fprintf(stderr, "Received credentials pid=%ld, uid=%ld, gid=%ld\n",
              (long) ucredp->pid, (long) ucredp->uid, (long) ucredp->gid);
    }

    /* emit any bytes of actual data received */
    fprintf(stderr, "received %ld bytes: %.*s\n", nr, (int)nr, buf);
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  int opt, rc=-1, sc, n;
  struct epoll_event ev;
  cfg.prog = argv[0];

  while ( (opt = getopt(argc,argv,"vhf:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'f': cfg.file=strdup(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  if (cfg.file == NULL) usage();
  if (bind_socket() < 0) goto done;

  /* block all signals. we take signals synchronously via signalfd */
  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* a few signals we'll accept via our signalfd */
  sigset_t sw;
  sigemptyset(&sw);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigaddset(&sw, sigs[n]);

  /* create the signalfd for receiving signals */
  cfg.signal_fd = signalfd(-1, &sw, 0);
  if (cfg.signal_fd == -1) {
    fprintf(stderr,"signalfd: %s\n", strerror(errno));
    goto done;
  }


  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  if (new_epoll(EPOLLIN, cfg.sock_fd)) goto done;
  if (new_epoll(EPOLLIN, cfg.signal_fd)) goto done;

  alarm(1);
  while (epoll_wait(cfg.epoll_fd, &ev, 1, -1) > 0) {
    if      (ev.data.fd == cfg.signal_fd)   { if (handle_signal() < 0) goto done; }
    else { if (handle_client(ev.data.fd) < 0) goto done; }
  }

  rc = 0;
 
 done:
  if (cfg.sock_fd != -1) close(cfg.sock_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  return rc;
}
