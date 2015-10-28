#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>

struct {
  char *local;
  int verbose;
  int nn_socket;
  char *buf;
  int len;
} CF = {
  .local = "tcp://127.0.0.1:9995",
  .nn_socket = -1,
};

void usage(char *prog) {
  fprintf(stderr, "usage: %s [-v] [-l <local-bind>]\n", prog);
  exit(-1);
}

int main(int argc, char *argv[]) {
  int eid, opt;

  while ( (opt = getopt(argc, argv, "v+l:")) != -1) {
    switch (opt) {
      case 'v': CF.verbose++; break;
      case 'l': CF.local = strdup(optarg); break;
      default: usage(argv[0]); break;
    }
  }

  if ( (CF.nn_socket = nn_socket(AF_SP, NN_PULL)) < 0) goto done;
  if ( (eid = nn_bind(CF.nn_socket, CF.local)) < 0) goto done;

  while (1) {
    if ( (CF.len = nn_recv(CF.nn_socket, &CF.buf, NN_MSG, 0)) == -1) goto done;
    fprintf(stderr,"received: %.*s\n", CF.len, CF.buf);
    nn_freemsg(CF.buf);
  }

 done:
  if (CF.nn_socket >= 0) nn_close(CF.nn_socket);
  return 0;
}

