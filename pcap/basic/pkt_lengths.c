#include <stdio.h>
#include <pcap.h>

char err[PCAP_ERRBUF_SIZE];
const int maxsz = 65535;

void cb(u_char *data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  printf("packet of length %d\n", hdr->len);
}

int main(int argc, char *argv[]) {
  pcap_t *p=NULL;
  int rc=-1;
  char *dev;

  dev = (argc > 1) ? argv[1] : pcap_lookupdev(err);
  if (dev == NULL) {
    fprintf(stderr, "no device: %s\n", err);
    goto done;
  }

  p = pcap_open_live(dev, maxsz, 1, 0, err);
  if (p == NULL) {
    fprintf(stderr, "can't open %s: %s\n", dev, err);
    goto done;
  }

  rc = pcap_loop(p, 0, cb, NULL);

 done:
  return rc;
}

