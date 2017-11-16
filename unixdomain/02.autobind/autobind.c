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
   from unix(7): 

   Autobind feature
       If  a  bind(2)  call specifies addrlen as sizeof(sa_family_t), or the SO_PASSCRED socket option was
       specified for a socket that was not explicitly bound to an address, then the socket is autobound to
       an  abstract address.  The address consists of a null byte followed by 5 bytes in the character set
       [0-9a-f].  Thus, there is a limit of 2^20 autobind addresses.  (From Linux 2.1.15, when  the  auto‐
       bind  feature  was  added,  8 bytes were used, and the limit was thus 2^32 autobind addresses.  The
       change to 5 bytes came in Linux 2.3.15.)

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

static void hexdump(char *buf, size_t len) {
  size_t i,n=0;
  unsigned char c;
  while(n < len) {
    //fprintf(stderr,"%08x ", (int)n);
    for(i=0; i < 16; i++) {
      c = (n+i < len) ? buf[n+i] : 0;
      if (n+i < len) fprintf(stderr,"%.2x ", c);
      else fprintf(stderr, "   ");
    }
    for(i=0; i < 16; i++) {
      c = (n+i < len) ? buf[n+i] : ' ';
      if (c < 0x20 || c > 0x7e) c = '.';
      fprintf(stderr,"%c",c);
    }
    fprintf(stderr,"\n");
    n += 16;
  }
}

int setup_listener(void) {
  struct sockaddr_un addr;
  int sc, rc = -1;

  cfg.sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (cfg.sock_fd < 0) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  /* request autobind */
  socklen_t want_autobind = sizeof(sa_family_t);
  sc = bind(cfg.sock_fd, (struct sockaddr*)&addr, want_autobind);
  if (sc < 0) {
    fprintf(stderr,"bind: %s\n", strerror(errno));
    goto done;
  }

  /* display the abstract socket name. the socket name isn't null terminated! */
  struct sockaddr_un tmp;
  socklen_t addrlen = sizeof(struct sockaddr_un);
	sc = getsockname(cfg.sock_fd, (struct sockaddr *)&tmp, &addrlen);
  if (sc < 0) {
    fprintf(stderr,"getsockname: %s\n", strerror(errno));
    goto done;
  }
  fprintf(stderr, "socket name in hex and ASCII (. for null byte):\n");
  hexdump(tmp.sun_path, addrlen-sizeof(sa_family_t));

  /* begin listening */
  sc = listen(cfg.sock_fd, 5);
  if (sc < 0) {
    fprintf(stderr,"listen: %s\n", strerror(errno));
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

int handle_socket(void) {
  int fd, rc = -1;

  fd = accept(cfg.sock_fd, NULL, NULL);
  if (fd < 0) {
    fprintf(stderr,"accept: %s\n", strerror(errno));
    goto done;
  }

  if (new_epoll(EPOLLIN, fd)) goto done;

  rc = 0;

 done:
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
  char buf[1000];
  int rc = -1;
  ssize_t nr;

	/* emit any bytes of actual data received */
  nr = read(fd, buf, sizeof(buf));
  if (nr < 0){
    fprintf(stderr,"read: %s\n", strerror(errno));
    goto done;
  }
  if (nr == 0) {
    fprintf(stderr,"client: eof\n");
    close(fd);
  } else {
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
  if (setup_listener() < 0) goto done;

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
    else if (ev.data.fd == cfg.sock_fd)     { if (handle_socket() < 0) goto done; }
    else { if (handle_client(ev.data.fd) < 0) goto done; }
  }

  rc = 0;
 
 done:
  if (cfg.sock_fd != -1) close(cfg.sock_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  return rc;
}
