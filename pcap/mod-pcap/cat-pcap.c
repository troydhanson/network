#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define PCAP_GLOBAL_HDR_LEN 24

int verbose;
int offset;

/* usage: cat-pcap <file> ...
 *
 * Append subsequent files to the first, stripping the pcap header
 * off the subsequent files. This only produces a good result if the
 * pcap files had the same header to start with.
 * 
 */

int append_pcap(int cat_fd, char *file) {
  char *buf=NULL,*data;
  size_t sz;
  struct stat s;
  int fd,rc=-1;

  /* concat file */
  if ( (fd = open(file, O_RDONLY)) == -1) {
    fprintf(stderr,"can't open %s: %s\n", file, strerror(errno));
    goto done;
  }
  if (fstat(fd, &s) == -1) {
    fprintf(stderr,"can't stat %s: %s\n", file, strerror(errno));
    goto done;
  }
  if (s.st_size < PCAP_GLOBAL_HDR_LEN) {
    fprintf(stderr,"file lacks pcap header: %s\n", file);
    goto done;
  }
  if (!S_ISREG(s.st_mode)) {
    fprintf(stderr,"not a regular file: %s\n", file);
    goto done;
  }
  buf = mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (buf == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", file, strerror(errno));
    goto done;
  }
 
  data = buf + PCAP_GLOBAL_HDR_LEN;
  sz = s.st_size - PCAP_GLOBAL_HDR_LEN;
  
  if (verbose) fprintf(stderr,"appending %s [%lu bytes]\n", file, sz);
  if (write(cat_fd, data, sz) != sz) {
    fprintf(stderr, "write %s: %s\n", file, strerror(errno));
    goto done;
  }

  rc = 0;

done:
  if (buf && (buf != MAP_FAILED)) if (munmap(buf, s.st_size)) fprintf(stderr,"munmap: %s\n",strerror(errno));
  if (fd != -1) close(fd);
  return rc;
}

int main(int argc, char *argv[]) {
  struct stat s;
  int i=0, opt, rc=-1, fd=-1;
  char *file=NULL;

  while ( (opt = getopt(argc, argv, "v+o:")) != -1) {
    switch (opt) {
      case 'v': verbose++;             break;
      case 'o': offset = atoi(optarg); break;
    }
  }

  if (optind >= argc) goto done;
  file = argv[optind++];

  /* open initial */
  fd = open(file,O_WRONLY|O_APPEND);
  if (fd == -1) {
    fprintf(stderr,"open: %s\n", strerror(errno));
    goto done;
  }
  if (fstat(fd,&s) == -1) {
    fprintf(stderr,"stat: %s\n", strerror(errno));
    goto done;
  }
  if (s.st_size < PCAP_GLOBAL_HDR_LEN) {
    fprintf(stderr,"first file lacks pcap header\n");
    goto done;
  }
  if (verbose) fprintf(stderr,"%s\n",file);

  /* append subsequent */
  while (optind < argc) {
    file = argv[optind++];
    if (verbose) fprintf(stderr,"%s\n",file);
    append_pcap(fd,file);
  }

  rc = 0;

 done:
  
  if (fd != -1) close(fd);
  return rc;
}
