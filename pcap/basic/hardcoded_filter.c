#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <pcap/bpf.h>

/* hardcoded filter expression, representing the bpf
 * expression 'host 10.0.2.15'. Generated using this:
 *    tcpdump -i eth0 'host 10.0.2.15' -d -d 
 */
struct bpf_insn bpf_insns[] = {
  { 0x28, 0, 0, 0x0000000c },
  { 0x15, 0, 4, 0x00000800 },
  { 0x20, 0, 0, 0x0000001a },
  { 0x15, 8, 0, 0x0a00020f },
  { 0x20, 0, 0, 0x0000001e },
  { 0x15, 6, 7, 0x0a00020f },
  { 0x15, 1, 0, 0x00000806 },
  { 0x15, 0, 5, 0x00008035 },
  { 0x20, 0, 0, 0x0000001c },
  { 0x15, 2, 0, 0x0a00020f },
  { 0x20, 0, 0, 0x00000026 },
  { 0x15, 0, 1, 0x0a00020f },
  { 0x6, 0, 0, 0x0000ffff },
  { 0x6, 0, 0, 0x00000000 },
};

struct bpf_program bpf_prog = {
  .bf_len = sizeof(bpf_insns)/sizeof(*bpf_insns),
  .bf_insns = bpf_insns,
};

char err[PCAP_ERRBUF_SIZE];
const int maxsz = 65535;

void usage(char *prog) {
  fprintf(stderr,"usage: %s [-v] -i <eth> | -r <file> 'filter'\n", prog);
  exit(-1);
}

void cb(u_char *data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  printf("packet of length %d\n", hdr->len);
}

int main(int argc, char *argv[]) {
  char *dev=NULL,*file=NULL;
  int verbose=0,opt,rc=-1;
  struct bpf_program fp;
  pcap_t *p=NULL;
  bpf_u_int32 net=0, mask=0;

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

  if ( (rc = pcap_setfilter(p, &bpf_prog)) != 0) {
    fprintf(stderr, "can't set filter expression: %s\n", err);
    goto done;
  }

  rc = pcap_loop(p, 0, cb, NULL);

 done:
  return rc;
}

