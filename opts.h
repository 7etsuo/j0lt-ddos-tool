#ifndef OPTS_H
#define OPTS_H

#include "result.h"

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

extern const char *g_args;

typedef struct JoltOptions {
  uint32_t spoof_ip;    // IP to spoof
  uint16_t spoof_port;  // Port to spoof
  uint16_t nthreads;    // nthreads of the attack
  const char *pathptr;
  char resolv_path[PATH_MAX];  // Path to the resolver list
  bool debug_mode;             // Debug mode flag
  bool hex_mode;               // Hex dump mode flag
} JoltOptions;

Result_T get_opt_nthreads(JoltOptions *opts, const char *optarg);
Result_T retrieve_max_threads(long *nprocs);
Result_T get_opt_port(JoltOptions *opts, const char *optarg);
Result_T get_opt_target(JoltOptions *opts, const char *optarg);
Result_T parse_opts(JoltOptions *opts, int argc, const char **argv);
void init_opts(JoltOptions *opts);

#endif // OPTS_H

