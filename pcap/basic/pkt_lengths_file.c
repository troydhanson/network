#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

char err[PCAP_ERRBUF_SIZE];
const int maxsz = 65535;

void usage(char *prog) {
  fprintf(stderr,"usage: %s [-v] -i <eth> | -r <file>\n", prog);
  exit(-1);
}

void cb(u_char *data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  printf("packet of length %d\n", hdr->len);
}

int main(int argc, char *argv[]) {
  char *dev=NULL,*file=NULL;
  int verbose=0,opt,rc=-1;
  pcap_t *p=NULL;

  while ( (opt=getopt(argc,argv,"vr:i:h")) != -1) {
    switch(opt) {
      case 'v': verbose++; break;
      case 'r': file=strdup(optarg); break;
      case 'i': dev=strdup(optarg); break;
      case 'h': default: usage(argv[0]); break;
    }
  }

  if (file) p = pcap_open_offline(file, err);
  else if (dev) p = pcap_open_live(dev,maxsz,1,0,err);
  else usage(argv[0]);

  if (p == NULL) {
    fprintf(stderr, "can't open %s: %s\n", dev, err);
    goto done;
  }

  rc = pcap_loop(p, 0, cb, NULL);

 done:
  return rc;
}

