#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

/* demonstrates use of signal-based I/O to implement a UDP server */


/* signals that we'll allow (unblock) during sigsuspend */
static const int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM,SIGIO};
sigjmp_buf jmp;

struct {
  int verbose;
  in_addr_t ip;
  int port;
  int fd; /* listener */
  FILE *out; 
  char* file;
} cfg;

void usage(char *prog) {
  fprintf(stderr, "usage: %s [-v] [-s <ip>] -p <port> -f <status-file>\n", prog);
  exit(-1);
}

void sighandler(int signo) {
  siglongjmp(jmp,signo);
}

void decode_datagram(char *buf, int len) {
  fprintf(stderr,"received [%.*s]\n", (int)len, buf); /* this is a stub */
}

static char buf[2000];
void handle_datagram() {
  int rc;
  do {
    rc = read(cfg.fd, buf, sizeof(buf));   /* fd is non-blocking, thus */
    if (rc > 0) decode_datagram(buf,rc);   /* we get rc==-1 after last */
  } while (rc >= 0);
}

int setup_listener() {
  cfg.fd = socket(AF_INET, SOCK_DGRAM, 0);
  int fd = cfg.fd;
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = cfg.ip;
  sin.sin_port = htons(cfg.port);
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    close(fd);
    fprintf(stderr,"can't bind: %s", strerror(errno));
    return -1;
  }
  int fl = fcntl(fd, F_GETFL); /* request SIGIO whenever it's readable */
  fl |= O_ASYNC | O_NONBLOCK;
  fcntl(fd, F_SETFL, fl);
  fcntl(fd, F_SETOWN, getpid()); 
  return 0;
}

int main(int argc, char *argv[]) {
  int rc=-1, opt, n;
  cfg.ip = htonl(INADDR_ANY);

  while ( (opt = getopt(argc, argv, "v+s:p:f:")) != -1) {
    switch (opt) {
      case 'v': cfg.verbose++; break;
      case 's': cfg.ip=inet_addr(optarg); break;
      case 'p': cfg.port=atoi(optarg); break;
      default: usage(argv[0]); break;
    }
  }
  if (cfg.port == 0) usage(argv[0]);

  /* block all signals. we remain fully blocked except in sigsuspend */
  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* define a smaller set of signals to block within sigsuspend. */
  sigset_t ss;
  sigfillset(&ss);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigdelset(&ss, sigs[n]);

  /* establish handlers for signals that we'll unblock in sigsuspend */
  struct sigaction sa;
  sa.sa_handler = sighandler;
  sa.sa_flags = 0;
  sigfillset(&sa.sa_mask);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigaction(sigs[n], &sa, NULL);

  if (setup_listener() < 0) goto done;

  /* here is a special line. we'll come back here whenever a signal happens */
  int signo = sigsetjmp(jmp,1);

  switch(signo) {
    case 0:      /* not a signal yet, first time setup */
      break;
    case SIGIO:  /* our UDP listener got a datagram */
      handle_datagram();
      break;
    default:
      fprintf(stderr,"exiting on signal %d\n", signo);
      goto done;
      break;
  }

  /* wait for signals */
  sigsuspend(&ss);

  /* the only way to get past this point 
   * is from the "goto done" above, because 
   * sigsuspend waits for signals, and when
   * one arrives we longjmp back to sigsetjmp! */

 done:
  return rc;
}

