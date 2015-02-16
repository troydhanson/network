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


/* NOTES 
 *
 * to test this program's correctness it was compared with the output of
 *
 *  tcpdump -ne (to show link level headers and inhibit name resolution)
 * 
 * another useful program is tcprewrite (part of tcpreplay package) which
 * can be used, for example, to insert vlan tags into a pcap, like 
 *
 *  tcprewrite -i some.pcap -o vlan.pcap --enet-vlan=add --enet-vlan-tag=2210 \
 *              --enet-vlan-pri=0 --enet-vlan-cfi=0
 *
 */

char err[PCAP_ERRBUF_SIZE];
const int maxsz = 65535;
int verbose;

void usage(char *prog) {
  fprintf(stderr,"usage: %s [-v] -i <eth> | -r <file>\n", prog);
  exit(-1);
}

char m[18];
char *macf(const uint8_t *mac) {
  snprintf(m,sizeof(m),"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", (unsigned)mac[0], 
       (unsigned)mac[1], (unsigned)mac[2], (unsigned)mac[3], 
       (unsigned)mac[4], (unsigned)mac[5]);
  return m;
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
  printf("dst_mac: %s ", macf(dst_mac));
  printf("src_mac: %s ", macf(src_mac));
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
  printf("type: 0x%x (%s) ", (unsigned)type, etypes[etype]);

  if (etype==802) {
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
    printf("vlan %d ", vid);
    typep = tci_p + 2;
    goto again; 
  }
  data = typep + 2;
  printf("\n"); /* end of frame level stuff */

  /*****************************************************************************
  * IP datagram 
   ****************************************************************************/

  const uint8_t *ip_datagram, *ip_hl, *ip_tos, *ip_len, *ip_id, *ip_fo, *ip_ttl, 
          *ip_proto, *ip_sum, *ip_src, *ip_dst, *ip_opt, *ip_data;
  uint8_t ip_version, ip_hdr_len, *ap;
  uint16_t ip_lenh, ip_idh, ip_opts_len;
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
    ip_fo =  data + 6;  /* TODO if fragmented, TCP/UDP header not repeated */
    ip_ttl = data + 8;
    ip_proto=data + 9;
    ip_sum = data + 10;
    ip_src = data + 12;
    ip_dst = data + 16;
    ip_opt = data + 20;
    ip_data= data + 20 + ip_opts_len;

    memcpy(&ip_lenh, ip_len, sizeof(uint16_t)); ip_lenh = ntohs(ip_lenh);
    memcpy(&ip_idh, ip_id, sizeof(uint16_t)); ip_idh = ntohs(ip_idh);
    printf(" IP vers: %d hdr_len: %d opts_len: %d id: %d ttl: %d, proto: %d ",
     (unsigned)ip_version, (unsigned)ip_hdr_len, (unsigned)ip_opts_len, 
     (unsigned)ip_idh, (unsigned)(*ip_ttl), (unsigned)(*ip_proto));
    switch((unsigned)(*ip_proto)) {
      case 1: ipproto = icmp; printf("(icmp) "); break;
      case 2: ipproto = igmp; printf("(igmp) "); break;
      case 6: ipproto = tcp; printf("(tcp) "); break;
      case 17: ipproto = udp; printf("(udp) "); break;
      default: ipproto = none; printf("(none) "); break;
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
    printf("\n"); /* end of IP datagram level */

  /*****************************************************************************
  * UDP datagram or TCP segment
   ****************************************************************************/

    const uint8_t *srcpp, *dstpp;
    uint16_t srcport, dstport;
    if (ipproto == udp || ipproto == tcp) {
      srcpp = data;
      dstpp = data + sizeof(uint16_t);
      memcpy(&srcport, srcpp, sizeof(uint16_t));
      memcpy(&dstport, dstpp, sizeof(uint16_t));
      srcport = ntohs(srcport);
      dstport = ntohs(dstport);
      printf("  %s src port: %d dst port: %d ", (ipproto==tcp)?"tcp":"udp",
       (unsigned)srcport, (unsigned)dstport);
    }
    const uint8_t *seqp, *ackp, *hlenp, *flagp, *winp, *optp, *datp;
    uint8_t hlen, flags;
    uint32_t seqno, ackno;
    uint16_t winsz;
    if (ipproto == tcp) {
      seqp = data + 2*sizeof(uint16_t);
      ackp = seqp + sizeof(uint32_t);
      hlenp = ackp + sizeof(uint32_t);
      flagp = hlenp + 1;
      winp = hlenp + sizeof(int16_t);
      datp = hlenp + 2 * sizeof(uint16_t);

      memcpy(&seqno, seqp, sizeof(uint32_t));
      seqno = ntohl(seqno);
      memcpy(&ackno, ackp, sizeof(uint32_t));
      ackno = ntohl(ackno);
      hlen = (((*hlenp) & 0xf0) >> 4) * 4;
      flags = (*flagp) & 0x3f;
      memcpy(&winsz,winp,sizeof(uint16_t));
      winsz = ntohs(winsz);
      printf(" seq %u ack %u hlen: %u win: %u ", seqno, ackno, (unsigned)hlen, 
       (unsigned)winsz);
      printf("%c%c%c%c%c%c ", (flags&0x20)?'u':'-', (flags&0x10)?'a':'-', 
       (flags&0x08)?'p':'-', (flags&0x04)?'r':'-', (flags&0x02)?'s':'-', 
       (flags&0x01)?'f':'-');
    }
    printf("\n"); /* end of transport level */
  }

}

int main(int argc, char *argv[]) {
  char *dev=NULL,*file=NULL;
  int opt,rc=-1, lt;
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

  /* confirm ethernet frame type; c.f. "man pcap-linktype" */
  if ( (lt=pcap_datalink(p)) != 1) { /* LINKTYPE_ETHERNET */
    fprintf(stderr, "not ethernet encapsulation: %d\n", lt);
    goto done;
  }

  rc = pcap_loop(p, 0, cb, NULL);

 done:
  return rc;
}

