#ifndef J0LT_NETWORK_H
#define J0LT_NETWORK_H

#include <stddef.h>   // for size_t
#include <stdint.h>   // for uint8_t, uint16_t, uint32_t, uint64_t
#include <stdbool.h>  // for bool

typedef struct __attribute__((packed, aligned(1))) {
  uint32_t sourceaddr;
  uint32_t destaddr;

#if __BYTE_ORDER == __BIGENDIAN
  uint32_t zero : 8;
  uint32_t protocol : 8;
  uint32_t udplen : 16;
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
  uint32_t udplen : 16;
  uint32_t protocol : 8;
  uint32_t zero : 8;
#endif
} PSEUDOHDR;

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

// IP HEADER VALUES
#define IP_IHL_MIN_J0LT 5
#define IP_IHL_MAX_J0LT 15
#define IP_TTL_J0LT 0x40
#define IP_ID_J0LT 0xc4f3
// FLAGS
#define IP_RF_J0LT 0x8000  // reserved fragment flag
#define IP_DF_J0LT 0x4000  // dont fragment flag
#define IP_MF_J0LT 0x2000  // more fragments flag
#define IP_OF_J0LT 0x0000
// END FLAGS
#define IP_VER_J0LT 4
// END IPHEADER VALUES

// DNS HEADER VALUES
#define DNS_ID_J0LT 0xb4b3
#define DNS_QR_J0LT 0  // query (0), response (1).
// OPCODE
#define DNS_OPCODE_J0LT ns_o_query
// END OPCODE
#define DNS_AA_J0LT 0  // Authoritative Answer
#define DNS_TC_J0LT 0  // TrunCation
#define DNS_RD_J0LT 1  // Recursion Desired
#define DNS_RA_J0LT 0  // Recursion Available
#define DNS_Z_J0LT 0   // Reserved
#define DNS_AD_J0LT 0  // dns sec
#define DNS_CD_J0LT 0  // dns sec
// RCODE
#define DNS_RCODE_J0LT ns_r_noerror
// END RCODE
#define DNS_QDCOUNT_J0LT 0x0001  // num questions
#define DNS_ANCOUNT_J0LT 0x0000  // num answer RRs
#define DNS_NSCOUNT_J0LT 0x0000  // num authority RRs
#define DNS_ARCOUNT_J0LT 0x0000  // num additional RRs
// END HEADER VALUES

#define PEWPEW_J0LT 100  // value for the tmc effect.
#define MAX_LINE_SZ_J0LT 0x30

size_t forge_j0lt_packet(char *payload, uint32_t resolvip, uint32_t spoofip,
                         uint16_t spoofport);
uint16_t j0lt_checksum(const uint16_t *addr, size_t count);
bool insert_dns_header(uint8_t **buf, size_t *buflen);
bool insert_dns_question(void **buf, size_t *buflen, const char *domain,
                         uint16_t query_type, uint16_t query_class);
bool insert_udp_header(uint8_t **buf, size_t *buflen, PSEUDOHDR *phdr,
                       const uint8_t *data, size_t ulen, uint16_t sport);
bool insert_ip_header(uint8_t **buf, size_t *buflen, PSEUDOHDR *pheader,
                      uint32_t daddr, uint32_t saddr, size_t ulen);
bool send_payload(const uint8_t *datagram, uint32_t daddr, uint16_t uh_dport,
                  size_t nwritten);

bool is_valid_ip4(const char *str);

#endif  // J0LT_NETWORK_H

