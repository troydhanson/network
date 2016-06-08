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
#include "iptop.h"

extern struct iptop_conf cfg;

/*******************************************************************************
 * ethernet frame: | 6 byte dst MAC | 6 byte src MAC | 2 byte type | data
 * IP datagram: | 1 byte v/len | 1 byte TOS | 2 byte len | 16 more bytes | data
 ******************************************************************************/
void cb(u_char *unused, const struct pcap_pkthdr *hdr, const u_char *pkt) {
  /* data link: ethernet frame */
  const uint8_t *dst_mac=pkt, *src_mac=pkt+6, *typep=pkt+12;
  const uint8_t *data = pkt+14, *tci_p;
  uint16_t type,tci,vid;

  // need at least a MAC pair, ethertype and IP header
  if (hdr->caplen < 12+2+20) return;

 again:
  if (hdr->caplen < ((typep - pkt) + 2)) return;
  memcpy(&type, typep, sizeof(uint16_t)); 
  type = ntohs(type); 

  /* 802.2/802.3 encapsulation (RFC 1042). Skip LLC/SNAP to reach ethertype. */
  if (type <= 1500) {
    typep += 6;
    goto again;
  }

  if (type == 0x8100) /* vlan */ {
  /* vlan tags are 'interjected' before the ethertype; they are known by their
   * own ethertype (0x8100) followed by a TCI, after which the real etherype 
   * (or another double VLAN tag) occurs. Each VLAN tag adds two bytes to the
   * frame size. The TCI (tag control identifier) contains the VLAN ID (vid).*/
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
  uint16_t ip_lenh, ip_idh, ip_opts_len;
  uint32_t ip_srch, ip_dsth;
  if (type == 0x0800) {
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
    memcpy(&ip_srch, ip_src, sizeof(uint32_t)); ip_srch = ntohl(ip_srch);
    memcpy(&ip_dsth, ip_dst, sizeof(uint32_t)); ip_dsth = ntohl(ip_dsth);
    utstring_clear(cfg.label);
    utstring_printf(cfg.label, "%d.%d.%d.%d->%d.%d.%d.%d", 
                                (ip_srch & 0xff000000) >> 24,
                                (ip_srch & 0x00ff0000) >> 16,
                                (ip_srch & 0x0000ff00) >>  8,
                                (ip_srch & 0x000000ff) >>  0,
                                (ip_dsth & 0xff000000) >> 24,
                                (ip_dsth & 0x00ff0000) >> 16,
                                (ip_dsth & 0x0000ff00) >>  8,
                                (ip_dsth & 0x000000ff) >>  0);
    data = ip_data;
    char *label = utstring_body(cfg.label);
    abtop_hit(cfg.abtop, label, cfg.now, ip_lenh, 0); /* len excludes frame */ // FIXME ab ba
  }
}

