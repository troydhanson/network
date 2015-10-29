/*
 * Manage nano socket and OS descriptors via epoll.
 * signals are also handled signalfd
 */

#include <errno.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>

struct {
  int verbose;
  char *prog;
  int signal_fd;
  int epoll_fd;
  int ticks;
  int nn_socket; /* nano socket */
  int nn_fd;     /* nano descriptor */
  char *local;   /* nano binding */
  char *buf;     /* nano allocd msg */
  int len;       /* len of msg */
} CF = {
  .signal_fd = -1,
  .epoll_fd = -1,
  .local = "tcp://127.0.0.1:9995",
  .nn_socket = -1,
  .nn_fd = -1,
};

void usage() {
  fprintf(stderr,"usage: %s [-v] [-l <local-bind>]\n", CF.prog);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void periodic_work() {
  fprintf(stderr,"periodic work...\n");
}

int new_epoll(int events, int fd) {
  int rc;
  struct epoll_event ev;
  memset(&ev,0,sizeof(ev)); // placate valgrind
  ev.events = events;
  ev.data.fd= fd;
  if (CF.verbose) fprintf(stderr,"adding fd %d to epoll\n", fd);
  rc = epoll_ctl(CF.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

int handle_signal() {
  int rc=-1;
  struct signalfd_siginfo info;
  
  if (read(CF.signal_fd, &info, sizeof(info)) != sizeof(info)) {
    fprintf(stderr,"failed to read signal fd buffer\n");
    goto done;
  }

  switch(info.ssi_signo) {
    case SIGALRM: 
      if ((++CF.ticks % 10) == 0) periodic_work();
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

int handle_nn() {
  int rc=-1;

  rc = (CF.len = nn_recv(CF.nn_socket, &CF.buf, NN_MSG, 0));
  if (rc < 0) goto done;
  fprintf(stderr,"received: %.*s", CF.len, CF.buf);
  nn_freemsg(CF.buf);

  rc = 0;

 done:
  if (rc < 0) fprintf(stderr,"nano: %s\n", nn_strerror(errno));
  return rc;
}

int main(int argc, char *argv[]) {
  int opt, rc=0, eid;
  unsigned n;
  CF.prog = argv[0];
  struct epoll_event ev;

  while ( (opt=getopt(argc,argv,"v+l:h")) != -1) {
    switch(opt) {
      case 'v': CF.verbose++; break;
      case 'l': CF.local = strdup(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  /* block all signals. we take signals synchronously via signalfd */
  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* a few signals we'll accept via our signalfd */
  sigset_t sw;
  sigemptyset(&sw);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigaddset(&sw, sigs[n]);

  /* create the signalfd for receiving signals */
  CF.signal_fd = signalfd(-1, &sw, 0);
  if (CF.signal_fd == -1) {
    fprintf(stderr,"signalfd: %s\n", strerror(errno));
    goto done;
  }

  /* set up the epoll instance */
  CF.epoll_fd = epoll_create(1); 
  if (CF.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* set up the nano PULL socket */
  rc = (CF.nn_socket = nn_socket(AF_SP, NN_PULL));
  if (rc < 0) goto done;
  rc = (eid = nn_bind(CF.nn_socket, CF.local));
  if (rc < 0) goto done;

  /* add descriptors of interest */
  size_t fd_sz = sizeof(int);
  rc = nn_getsockopt(CF.nn_socket, NN_SOL_SOCKET, NN_RCVFD, &CF.nn_fd, &fd_sz);
  if (rc < 0) goto done;
  if (new_epoll(EPOLLIN, CF.nn_fd)) goto done;     // nano socket
  if (new_epoll(EPOLLIN, CF.signal_fd)) goto done; // signal socket

  fprintf(stderr,"starting... press ctrl-c to exit\n");

  alarm(1);
  while (epoll_wait(CF.epoll_fd, &ev, 1, -1) > 0) {
    if (CF.verbose > 1)  fprintf(stderr,"epoll reports fd %d\n", ev.data.fd);
    if (ev.data.fd == CF.nn_fd)     { if (handle_nn() < 0) goto done; }
    if (ev.data.fd == CF.signal_fd) { if (handle_signal() < 0) goto done; }
  }

done:
  if (rc < 0) fprintf(stderr,"nano: %s\n", nn_strerror(errno));
  if (CF.nn_socket >= 0) nn_close(CF.nn_socket);
  if (CF.epoll_fd != -1) close(CF.epoll_fd);
  if (CF.signal_fd != -1) close(CF.signal_fd);
  return 0;
}
