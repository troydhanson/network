#include <stdio.h>
#include <pcap.h>

char err[PCAP_ERRBUF_SIZE];
const int maxsz = 65535;
#define pkt_interval 100

void gen_report(pcap_t *p) {
  struct pcap_stat ps;
  if (pcap_stats(p,&ps) < 0) {
    fprintf(stderr,"pcap_stat error\n");
    pcap_breakloop(p);
    return;
  }
  fprintf(stderr,"received : %u\n", ps.ps_recv);
  fprintf(stderr,"dropped: %u\n", ps.ps_drop);

}

int pkt_cnt=0;
void cb(u_char *data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  if (++pkt_cnt % pkt_interval == 0) gen_report((pcap_t*)data);
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

  rc = pcap_loop(p, 0, cb, (u_char*)p);

 done:
  return rc;
}

