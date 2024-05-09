#ifndef OPTS_H
#define OPTS_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "result.h"
#include "my_types.h"

extern GLOBAL_STRING_TYPE GLOBAL_STRING_OPTS;

typedef struct Target {
  uint32_t ip;    // IP to attack
  uint16_t port;  // Port to attack
} Target;

typedef struct DebugFlags {
  uint16_t nthreads;  // nthreads of the attack
  bool debug_mode;    // Debug mode flag
  bool hex_mode;      // Hex dump mode flag
} DebugFlags;

typedef struct JoltOptions {
  uint32_t ip;        // IP to attack
  uint16_t port;      // Port to attack
  uint16_t nthreads;  // nthreads of the attack
  bool debug_mode;    // Debug mode flag
  bool hex_mode;      // Hex dump mode flag
} JoltOptions;

Result_T get_opt_nthreads(JoltOptions *opts, const char *optarg);
Result_T retrieve_max_threads(long *nprocs);
Result_T get_opt_port(JoltOptions *opts, const char *optarg);
Result_T get_opt_target(JoltOptions *opts, const char *optarg);
Result_T parse_opts(JoltOptions *opts, int argc, const char *const *const argv);
void init_opts(JoltOptions *opts);

#endif  // OPTS_H
