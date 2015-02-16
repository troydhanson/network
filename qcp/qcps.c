#include <stdio.h>
#include <getopt.h>
#include <libgen.h>
#include <assert.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSZ (200*1024*1024)  // 200 mb
char buf[BUFSZ];
int port = 2000;             /* no significance */
int verbose=0;

void usage(char *prog) {
  fprintf(stderr, "usage: %s [-v] [-p <port>]\n", prog);
  exit(-1);
}


int main(int argc, char *argv[]) {

  int opt,rc;
  int namelen;
  char *base;

  while ( (opt = getopt(argc, argv, "v+p:h")) != -1) {
    switch (opt) {
      case 'p': port = atoi(optarg); break;
      case 'v': verbose++; break;
      default: usage(argv[0]); break;
    }
  }
 
  /**********************************************************
   * create an IPv4/TCP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    printf("socket: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * internet socket address structure: our address and port
   *********************************************************/
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  sin.sin_port = htons(port);

  /**********************************************************
   * bind socket to address and port we'd like to receive on
   *********************************************************/
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    printf("bind: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * put socket into listening state 
   *********************************************************/
  if (listen(fd,1) == -1) {
    printf("listen: %s\n", strerror(errno));
    exit(-1);
  }

  /**********************************************************
   * accept a connection, read til it closes, repeat
   *********************************************************/
  while (1) {
    struct sockaddr_in cin;
    socklen_t cin_sz = sizeof(cin);
    int fa = accept(fd, (struct sockaddr*)&cin, &cin_sz);
    if (fa == -1) {
      printf("accept: %s\n", strerror(errno));
      continue;
    }
    if (sizeof(cin)==cin_sz) {
      if (verbose) printf("connection from %s:%d\n", 
        inet_ntoa(cin.sin_addr), (int)ntohs(cin.sin_port));
    }
    /* first read the length prefixed filename */
    if (read(fa,&namelen,sizeof(namelen)) != sizeof(namelen)) {
      fprintf(stderr,"failed to read length\n");
      exit(-1);
    }
    assert(namelen < 200);
    if (read(fa,buf,namelen) != namelen) {
      fprintf(stderr,"failed to read name\n");
      exit(-1);
    }
    char *filename = buf;
    filename[namelen]='\0';
    base = basename(filename);
    int fw = open(base, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fw == -1) {
      fprintf(stderr,"can't open %s: %s\n",filename,strerror(errno));
      exit(-1);
    }
    if (verbose) fprintf(stderr,"writing %s\n",filename);
    do {
      rc = read(fa,buf,BUFSZ);
      if (rc==-1) printf("read: %s\n", strerror(errno));
      if (rc<=0) close(fw);
      else {
        //if (verbose) printf("received %d bytes: %.*s\n", rc, rc, buf);
        if (write(fw,buf,rc) != rc) {
          fprintf(stderr,"error writing to %s: %s\n", filename, strerror(errno));
          exit(-1);
        }
      }
    } while (rc > 0);
    close(fa);
  }
}
