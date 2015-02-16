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

int verbose;
int offset;

/* usage: mod-pcap -t <sec> <file> ...
 *
 * The pcap file is re-written with packet times offset
 * by "sec" seconds, which can be negative.
 * 
 */

int mod_pcap(char *file) {
  struct stat s;
  char *buf=NULL;
  int fd=-1,rc=-1;
  uint32_t plen;

  /* source file */
  if ( (fd = open(file, O_RDWR)) == -1) {
    fprintf(stderr,"can't open %s: %s\n", file, strerror(errno));
    goto done;
  }
  if (fstat(fd, &s) == -1) {
    fprintf(stderr,"can't stat %s: %s\n", file, strerror(errno));
    goto done;
  }
  if (!S_ISREG(s.st_mode)) {
    fprintf(stderr,"not a regular file: %s\n", file);
    goto done;
  }
  buf = mmap(0, s.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", file, strerror(errno));
    goto done;
  }

  /* pcap global header */
  uint32_t *magic_number =  (uint32_t*)buf;
  uint16_t *version_major = (uint16_t*)((char*)magic_number  + sizeof(*magic_number));
  uint16_t *version_minor = (uint16_t*)((char*)version_major + sizeof(*version_major));
  uint32_t *thiszone =      (uint32_t*)((char*)version_minor + sizeof(*version_minor));
  uint32_t *sigfigs =       (uint32_t*)((char*)thiszone      + sizeof(*thiszone));
  uint32_t *snaplen =       (uint32_t*)((char*)sigfigs       + sizeof(*sigfigs));
  uint32_t *network =       (uint32_t*)((char*)snaplen       + sizeof(*snaplen));
  
  char *cur = ((char*)network) + sizeof(*network);
  char *p;

  /* individual packets: guint32 sec, uint32 usec, uint32 incl_len, uint32 orig_len */
  for(p = cur; p < buf + s.st_size; p += plen) {
     uint32_t *sec =      (uint32_t*)p;
     uint32_t *usec =     (uint32_t*)((char*)sec      + sizeof(*sec));
     uint32_t *incl_len = (uint32_t*)((char*)usec     + sizeof(*usec));
     uint32_t *orig_len = (uint32_t*)((char*)incl_len + sizeof(*incl_len));
     p = (char*)((char*)orig_len + sizeof(*orig_len));
     plen = *incl_len;

     if (verbose) fprintf(stderr,"pkt ts: %u sec\n", *sec);
     *sec += offset;
  }

  rc = 0;

done:
  if (buf && (buf != MAP_FAILED)) if (munmap(buf, s.st_size)) fprintf(stderr,"munmap: %s\n",strerror(errno));
  if (fd != -1) close(fd);
  return rc;
}

int main(int argc, char *argv[]) {
  int i=0, opt;
  char *file;

  while ( (opt = getopt(argc, argv, "v+t:")) != -1) {
    switch (opt) {
      case 'v': verbose++;             break;
      case 't': offset = atoi(optarg); break;
    }
  }

  while (optind < argc) {
    file = argv[optind];
    fprintf(stderr,"%s\n",file);
    mod_pcap(file);
    optind++;
  }
}
