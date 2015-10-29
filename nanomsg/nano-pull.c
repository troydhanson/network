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
  int eid, opt, rc = 0;

  while ( (opt = getopt(argc, argv, "v+l:h")) != -1) {
    switch (opt) {
      case 'v': CF.verbose++; break;
      case 'l': CF.local = strdup(optarg); break;
      case 'h': default: usage(argv[0]); break;
    }
  }

  rc = (CF.nn_socket = nn_socket(AF_SP, NN_PULL));
  if (rc < 0) goto done;
  rc = (eid = nn_bind(CF.nn_socket, CF.local));
  if (rc < 0) goto done;

  while (1) {
    rc = (CF.len = nn_recv(CF.nn_socket, &CF.buf, NN_MSG, 0));
    if (rc < 0) goto done;
    fprintf(stderr,"received: %.*s", CF.len, CF.buf);
    nn_freemsg(CF.buf);
  }

  rc = 0;

 done:
  if (rc < 0) fprintf(stderr,"nano: %s\n", nn_strerror(errno));
  if (CF.nn_socket >= 0) nn_close(CF.nn_socket);
  return 0;
}

