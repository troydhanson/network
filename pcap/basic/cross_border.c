#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* 
 * decode IP header and test if CIDR border is crossed
 *
 * the CIDR defines the "inside" of a subnet.
 * the crosses_border function tests if the dst or src
 * IP is inside the cidr and the other one is outside.
 *
 * try it:
 *
 * ./cross_border -s 192.168.1.0/24 -r ping.pcap 
 *
 * loosen cidr:
 *
 * ./cross_border -s 192.0.0.0/8 -r ping.pcap 
 *
 * tighten cidr:
 *
 * ./cross_border -s 192.128.0.0/9 -r ping.pcap
 */

struct cfg {
  char *prog;
  char err[PCAP_ERRBUF_SIZE];
  int maxsz;
  int verbose;
  char *border;
  uint32_t cidr;
  int slash_n;
} cfg = {
  .maxsz =  65535,
};

void usage(void) {
  fprintf(stderr,"usage: %s [-v] [-s cidr] -i <eth> | -r <file>\n", cfg.prog);
  exit(-1);
}

/* IP followed by a /N */
int is_cidr(char *w) {
  unsigned a, b, c, d, n;
  int rc = -1, sc;

  sc = sscanf(w, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &n);
  if (sc != 5) goto done;

  if ((a > 255) || (b > 255) || (c > 255) || (d > 255)) goto done;
  if (n > 32) goto done;

  cfg.cidr = (a << 24) | (b << 16) | (c << 8) | d;
  cfg.slash_n = n;

  rc = 0;

 done:
  return !rc;
}

/* do the two IPv4 addresses (in host order) differ in their network part? 
 * if so, is one (but not both) of them "inside" the cidr of interest? */
int crosses_border(uint32_t a, uint32_t b) {
  uint64_t m, host_part_nbits;

  host_part_nbits = 32 - cfg.slash_n;
  m = ~((1UL << host_part_nbits) - 1);

  return (((cfg.cidr & m) == (a & m)) ^ ((cfg.cidr & m) == (b & m))) ? 1 : 0;
}

/*******************************************************************************
 * ethernet frame: | 6 byte dst MAC | 6 byte src MAC | 2 byte type | data
 * IP datagram: | 1 byte v/len | 1 byte TOS | 2 byte len | 16 more bytes | data
 * TCP segment: | 2 byte src port | 2 byte dst port | 4 byte seq | 4 byte ack | 
 *                2 byte flags | 2 byte window | 2 byte sum | 2 byte urg | data
 ******************************************************************************/
void cb(u_char *unused, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  /* data link: ethernet frame */
  enum {other,arp,rarp,ip,vlan,ipv6,e802} etype=other;
  enum {none,icmp,igmp,tcp,udp} ipproto=none;
  char *etypes[] = {"other","arp","rarp","ip","vlan","ipv6","802_2/3"};
  const uint8_t *dst_mac=pkt, *src_mac=pkt+6, *typep=pkt+12;
  const uint8_t *data = pkt+14, *tci_p;
  uint16_t type,tci,vid;
  if (hdr->caplen < 12) return;
 again:
  if (hdr->caplen < ((typep - pkt) + 2)) return;
  memcpy(&type, typep, sizeof(uint16_t)); 
  type = ntohs(type); 
  switch(type) {
    case 0x0800: etype = ip; break;
    case 0x8100: etype = vlan; break;
    case 0x0806: etype = arp; break;
    case 0x8035: etype = rarp; break;
    case 0x86dd: etype = ipv6; break;
    default: 
      if (type < 1500) etype = e802;  // 802.2/3 link encapsulation vs. EthernetII
      else etype = other; 
      break;
  }

  if (etype==e802) {
    // skip SNAP and LLC header
    typep += 6;
    goto again;
  }

  /* vlan tags are 'interjected' before the ethertype; they are known by their
   * own ethertype (0x8100) followed by a TCI, after which the real etherype 
   * (or another double VLAN tag) occurs. Each VLAN tag adds two bytes to the
   * frame size. The TCI (tag control identifier) contains the VLAN ID (vid).*/
  if (etype==vlan) { 
    tci_p = typep + 2; 
    if (hdr->caplen < ((tci_p - pkt)+2)) return;
    memcpy(&tci, tci_p, sizeof(uint16_t));  
    tci = ntohs(tci);
    vid = tci & 0xfff; // vlan VID is in the low 12 bits of the TCI
    typep = tci_p + 2;
    goto again; 
  }
  data = typep + 2;

  /*****************************************************************************
  * IP datagram 
   ****************************************************************************/

  const uint8_t *ip_datagram, *ip_hl, *ip_tos, *ip_len, *ip_id, *ip_fo, *ip_ttl, 
          *ip_proto, *ip_sum, *ip_src, *ip_dst, *ip_opt, *ip_data;
  uint8_t ip_version, ip_hdr_len, *ap;
  uint16_t ip_lenh, ip_idh, ip_opts_len, ip_foh;
  uint32_t ip_srch, ip_dsth;
  if (etype == ip) {
    ip_datagram = data;
    if (hdr->caplen < ((ip_datagram - pkt) + 20)) return;
    ip_hl = data;   
       ip_hdr_len = (*ip_hl & 0x0f) * 4; assert(ip_hdr_len >= 20);
       ip_opts_len = ip_hdr_len - 20;
       ip_version = (*ip_hl & 0xf0) >> 4;
    ip_tos = data + 1;
    ip_len = data + 2;
    ip_id =  data + 4;
    ip_fo =  data + 6;
    ip_ttl = data + 8;
    ip_proto=data + 9;
    ip_sum = data + 10;
    ip_src = data + 12;
    ip_dst = data + 16;
    ip_opt = data + 20;
    ip_data= data + 20 + ip_opts_len;

    memcpy(&ip_lenh, ip_len, sizeof(uint16_t)); ip_lenh = ntohs(ip_lenh);
    memcpy(&ip_idh, ip_id, sizeof(uint16_t)); ip_idh = ntohs(ip_idh);
    memcpy(&ip_foh, ip_fo, sizeof(uint16_t)); ip_foh = (ntohs(ip_foh) & 0x1fff)*8;
    switch((unsigned)(*ip_proto)) {
      case 1: ipproto = icmp;  break;
      case 2: ipproto = igmp;  break;
      case 6: ipproto = tcp;  break;
      case 17: ipproto = udp;  break;
      default: ipproto = none;  break;
    }
    memcpy(&ip_srch, ip_src, sizeof(uint32_t)); ip_srch = ntohl(ip_srch);
    memcpy(&ip_dsth, ip_dst, sizeof(uint32_t)); ip_dsth = ntohl(ip_dsth);
    printf("src: %d.%d.%d.%d ", (ip_srch & 0xff000000) >> 24,
                                (ip_srch & 0x00ff0000) >> 16,
                                (ip_srch & 0x0000ff00) >>  8,
                                (ip_srch & 0x000000ff) >>  0);
    printf("dst: %d.%d.%d.%d ", (ip_dsth & 0xff000000) >> 24,
                                (ip_dsth & 0x00ff0000) >> 16,
                                (ip_dsth & 0x0000ff00) >>  8,
                                (ip_dsth & 0x000000ff) >>  0);
    data = ip_data;

    if (crosses_border(ip_srch, ip_dsth)) printf("cross-border ");
    else printf("not cross-border ");
    printf("\n"); /* end of IP datagram level */
  }
}

int main(int argc, char *argv[]) {
  char *dev=NULL,*file=NULL;
  int opt,rc=-1, lt;
  pcap_t *p=NULL;

  cfg.prog = argv[0];

  while ( (opt=getopt(argc,argv,"vr:i:hs:")) != -1) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'r': file=strdup(optarg); break;
      case 'i': dev=strdup(optarg); break;
      case 's': cfg.border=strdup(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  if (file) p = pcap_open_offline(file, cfg.err);
  else if (dev) p = pcap_open_live(dev,cfg.maxsz,1,0,cfg.err);
  else usage();
  if (cfg.border == NULL) usage();
  if (is_cidr(cfg.border) < 0) usage();

  if (p == NULL) {
    fprintf(stderr, "can't open %s: %s\n", dev, cfg.err);
    goto done;
  }

  /* confirm ethernet frame type; c.f. "man pcap-linktype" */
  if ( (lt=pcap_datalink(p)) != 1) { /* LINKTYPE_ETHERNET */
    fprintf(stderr, "not ethernet encapsulation: %d\n", lt);
    goto done;
  }

  rc = pcap_loop(p, 0, cb, NULL);

 done:
  return rc;
}

