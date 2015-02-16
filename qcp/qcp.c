#include <stdio.h>
#include <sys/inotify.h>
#include <limits.h>
#include <netdb.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/fcntl.h>
 
int verbose=0;
char *watch_dir;

void usage(char *prog) {
  fprintf(stderr, "usage: %s -s <ip> -p <port> <file>   (send one file)\n", prog);
  fprintf(stderr, "   or: %s -s <ip> -p <port> -w <dir> (watch directory)\n", prog);
  exit(-1);
}

char *server = "127.0.0.1";
uint16_t port = 2000;
int md;
 
char *map(char *file, size_t *len) {
  struct stat s;
  char *buf;

  if ( (md = open(file, O_RDONLY)) == -1) {
      fprintf(stderr,"can't open %s: %s\n", file, strerror(errno));
      exit(-1);
  }
  if (fstat(md, &s) == -1) {
      close(md);
      fprintf(stderr,"can't stat %s: %s\n", file, strerror(errno));
      exit(-1);
  }
  *len = s.st_size;
  buf = mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, md, 0);
  if (buf == MAP_FAILED) {
    close(md);
    fprintf(stderr, "failed to mmap %s: %s\n", file, strerror(errno));
    exit(-1);
  }
  /* don't: close(md); */
  return buf;
}

int send_file(char *filename) {
  char *buf, *base;
  size_t buflen;
  int rc=-1,baselen;
  time_t before,after;

  buf = map(filename, &buflen);
  if (!buf) return -1;

  /**********************************************************
   * create an IPv4/TCP socket, not yet bound to any address
   *********************************************************/
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  struct hostent *h=gethostbyname(server);
  if (!h) {
    fprintf(stderr,"cannot resolve name: %s\n", hstrerror(h_errno));
    goto done;
  }
    
  /**********************************************************
   * internet socket address structure, for the remote side
   *********************************************************/
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = ((struct in_addr*)h->h_addr)->s_addr;
  sin.sin_port = htons(port);

  if (sin.sin_addr.s_addr == INADDR_NONE) {
    fprintf(stderr,"invalid remote IP %s\n", server);
    goto done;
  }

  /**********************************************************
   * Perform the 3 way handshake, (c)syn, (s)ack/syn, c(ack)
   *********************************************************/
  if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
    fprintf(stderr,"connect: %s\n", strerror(errno));
    goto done;
  }

  time(&before);

  /* write a length-prefixed filename.*/
  base = basename(filename);
  baselen = strlen(base);
  if (verbose) fprintf(stderr,"sending %s\n", base);
  if (write(fd,&baselen,sizeof(baselen)) != sizeof(baselen)) {
    fprintf(stderr,"write: %s\n", (rc<0)?strerror(errno):"incomplete");
    goto done;
  }

  if (write(fd,base,baselen) != baselen) {
    fprintf(stderr,"write: %s\n", (rc<0)?strerror(errno):"incomplete");
    goto done;
  }

  /* and write the file content */
  size_t l = buflen;
  char *b  = buf;
  
  while(l) {
    rc = write(fd,b,l);
    if (rc < 0) {
      fprintf(stderr,"write: %s\n", strerror(errno));
      goto done;
    }
    l -= rc;
    b += rc;
  }

  close(fd);
  time(&after);
  int sec = after-before;
  if (verbose) fprintf(stderr,"sent in %u sec (%.0f MB/s)\n", sec, 
    sec ? ((buflen/(1024.0*1024))/sec) :0);


  munmap(buf,buflen);
  close(md);

  if (verbose) fprintf(stderr,"sent %s\n",filename);
  rc = 0;

 done:
  return rc;
}

int main(int argc, char * argv[]) {
  int opt, fd = -1, wd, rc;
  char *file=NULL, *buf, *name;
  char filename[100];
 
  while ( (opt = getopt(argc, argv, "v+s:p:hw:")) != -1) {
    switch (opt) {
      case 's': server = strdup(optarg); break;
      case 'p': port = atoi(optarg); break;
      case 'v': verbose++; break;
      case 'w': watch_dir=strdup(optarg); break;
      default: usage(argv[0]); break;
    }
  }
 
  if (optind < argc) file=argv[optind++];
  if (!file && !watch_dir) usage(argv[0]);

  /* send one file only */
  if (file) {
    send_file(file);
    goto done;
  }
  
  /* prepare a buffer that's prefixed with the watchdir/ */
  char path[PATH_MAX];
  int len = strlen(watch_dir);
  memcpy(path, watch_dir, len); path[len]='/';

  /* send a stream of files by watching a directory */
  if ( (fd = inotify_init()) == -1) {
    perror("inotify_init failed");
    goto done; 
  }

  int mask = IN_CLOSE_WRITE;
  if ( (wd = inotify_add_watch(fd, watch_dir, mask)) == -1) {
    perror("inotify_add_watch failed");
    goto done;
  }

  /* see inotify(7) as inotify_event has a trailing name
   * field allocated beyond the fixed structure; we must
   * allocate enough room for the kernel to populate it */
  struct inotify_event *eb, *ev, *nx;
  size_t eb_sz = sizeof(*eb) + PATH_MAX, sz;
  if ( (eb = malloc(eb_sz)) == NULL) {
    fprintf(stderr, "out of memory\n");
    goto done;
  }

  /* one read will produce one or more event structures */
  while ( (rc=read(fd,eb,eb_sz)) > 0) {
    for(ev = eb; rc > 0; ev = nx) {

      sz = sizeof(*ev) + ev->len;
      nx = (struct inotify_event*)((char*)ev + sz);
      rc -= sz;

      name = (ev->len ? ev->name : watch_dir);
      memcpy(&path[len+1],name,strlen(name)+1);

      if (send_file(path)) goto done;
    }
  }

  if (rc < 0) {
   fprintf(stderr, "read: %s\n", strerror(errno));
  }


 done:
  if (fd != -1) close(fd);
}

