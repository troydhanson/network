#include <sys/types.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "utarray.h"

/*****************************************************************************
 * This program demonstrates epoll-based event notification. It monitors for
 * new client connections, input on existing connections or their closure, as
 * well as signals. The signals are also accepted via a file descriptor using
 * signalfd. This program uses blocking I/O in all cases. The epoll mechanism
 * tell us which exactly which descriptor is ready, when it is ready, so there
 * is no need for speculative/non-blocking reads. This program is more
 * efficient than sigio-server.c.
 *
 * Troy D. Hanson
 ****************************************************************************/

struct {
  in_addr_t addr;    /* local IP or INADDR_ANY   */
  int port;          /* local port to listen on  */
  int fd;            /* listener descriptor      */
  UT_array *fds;     /* array of client descriptors */
  int signal_fd;     /* used to receive signals  */
  int epoll_fd;      /* used for all notification*/
  int verbose;
  int ticks;         /* uptime in seconds        */
  int pid;           /* our own pid              */
  char *prog;
} cfg = {
  .addr = INADDR_ANY, /* by default, listen on all local IP's   */
  .fd = -1,
  .signal_fd = -1,
  .epoll_fd = -1,
};

void usage() {
  fprintf(stderr,"usage: %s [-v] [-a <ip>] -p <port\n", cfg.prog);
  exit(-1);
}

/* do periodic work here */
void periodic() {
  if (cfg.verbose) fprintf(stderr,"up %d seconds\n", cfg.ticks);
}

int add_epoll(int events, int fd) {
  int rc;
  struct epoll_event ev;
  memset(&ev,0,sizeof(ev)); // placate valgrind
  ev.events = events;
  ev.data.fd= fd;
  if (cfg.verbose) fprintf(stderr,"adding fd %d to epoll\n", fd);
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

int del_epoll(int fd) {
  int rc;
  struct epoll_event ev;
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_DEL, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

/* signals that we'll accept synchronously via signalfd */
int sigs[] = {SIGIO,SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

int setup_listener() {
  int rc = -1, one=1;

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /**********************************************************
   * internet socket address structure: our address and port
   *********************************************************/
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = cfg.addr;
  sin.sin_port = htons(cfg.port);

  /**********************************************************
   * bind socket to address and port 
   *********************************************************/
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    fprintf(stderr,"bind: %s\n", strerror(errno));
    goto done;
  }

  /**********************************************************
   * put socket into listening state
   *********************************************************/
  if (listen(fd,1) == -1) {
    fprintf(stderr,"listen: %s\n", strerror(errno));
    goto done;
  }

  cfg.fd = fd;
  rc=0;

 done:
  if ((rc < 0) && (fd != -1)) close(fd);
  return rc;
}

/* accept a new client connection to the listening socket */
int accept_client() {
  int fd;
  struct sockaddr_in in;
  socklen_t sz = sizeof(in);

  fd = accept(cfg.fd,(struct sockaddr*)&in, &sz);
  if (fd == -1) {
    fprintf(stderr,"accept: %s\n", strerror(errno)); 
    goto done;
  }

  if (cfg.verbose && (sizeof(in)==sz)) {
    fprintf(stderr,"connection fd %d from %s:%d\n", fd,
    inet_ntoa(in.sin_addr), (int)ntohs(in.sin_port));
  }

  if (add_epoll(EPOLLIN, fd) == -1) { close(fd); fd = -1; }

 done:
  if (fd != -1) utarray_push_back(cfg.fds,&fd);
  return fd;
}

void drain_client(int fd) {
  int rc, pos, *fp;
  char buf[1024];

  rc = read(fd, buf, sizeof(buf));
  switch(rc) { 
    default: fprintf(stderr,"received %d bytes\n", rc);         break;
    case  0: fprintf(stderr,"fd %d closed\n", fd);              break;
    case -1: fprintf(stderr, "recv: %s\n", strerror(errno));    break;
  }

  if (rc != 0) return;

  /* client closed. log it, tell epoll to forget it, close it */
  if (cfg.verbose) fprintf(stderr,"client %d has closed\n", fd);
  del_epoll(fd);
  close(fd);

  /* delete record of fd. linear scan. want hash if lots of fds */
  fp=NULL;
  while ( (fp=(int*)utarray_next(cfg.fds,fp))) { 
    if (*fp != fd) continue;
    pos = utarray_eltidx(cfg.fds,fp);
    utarray_erase(cfg.fds,pos,1);
    break;
  }

}

int main(int argc, char *argv[]) {
  cfg.prog = argv[0];
  cfg.prog=argv[0];
  cfg.pid = getpid();
  int n, opt, *fd;
  struct epoll_event ev;
  struct signalfd_siginfo info;

  utarray_new(cfg.fds,&ut_int_icd);

  while ( (opt=getopt(argc,argv,"vp:a:h")) != -1) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'p': cfg.port=atoi(optarg); break; 
      case 'a': cfg.addr=inet_addr(optarg); break; 
      case 'h': default: usage(); break;
    }
  }
  if (cfg.addr == INADDR_NONE) usage();
  if (cfg.port==0) usage();

  /* block all signals. we take signals synchronously via signalfd */
  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* a few signals we'll accept via our signalfd */
  sigset_t sw;
  sigemptyset(&sw);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigaddset(&sw, sigs[n]);

  if (setup_listener()) goto done;

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

  /* add descriptors of interest */
  if (add_epoll(EPOLLIN, cfg.fd))        goto done; // listening socket
  if (add_epoll(EPOLLIN, cfg.signal_fd)) goto done; // signal socket

  /*
   * This is our main loop. epoll for input or signals.
   */
  alarm(1);
  while (epoll_wait(cfg.epoll_fd, &ev, 1, -1) > 0) {

    /* if a signal was sent to us, read its signalfd_siginfo */
    if (ev.data.fd == cfg.signal_fd) { 
      if (read(cfg.signal_fd, &info, sizeof(info)) != sizeof(info)) {
        fprintf(stderr,"failed to read signal fd buffer\n");
        continue;
      }
      switch (info.ssi_signo) {
        case SIGALRM: 
          if ((++cfg.ticks % 10) == 0) periodic(); 
          alarm(1); 
          continue;
        default:  /* exit */
          fprintf(stderr,"got signal %d\n", info.ssi_signo);  
          goto done;
      }
    }

    /* regular POLLIN. handle the particular descriptor that's ready */
    assert(ev.events & EPOLLIN);
    if (cfg.verbose) fprintf(stderr,"handle POLLIN on fd %d\n", ev.data.fd);
    if (ev.data.fd == cfg.fd) accept_client();
    else drain_client(ev.data.fd);

  }

  fprintf(stderr, "epoll_wait: %s\n", strerror(errno));

 done:   /* we get here if we got a signal like Ctrl-C */
  fd=NULL;
  while ( (fd=(int*)utarray_next(cfg.fds,fd))) {del_epoll(*fd); close(*fd);}
  utarray_free(cfg.fds);
  if (cfg.fd != -1) close(cfg.fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  return 0;
}
