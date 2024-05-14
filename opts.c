#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "opts.h"
#include "result.h"

GLOBAL_STRING_TYPE GLOBAL_STRING_OPTS = "xdt:p:n:r:";

char *optarg = NULL;

Result_T get_opt_target(JoltOptions *opts, const char *optarg) {
  assert(opts != NULL && optarg != NULL);

  while (*optarg == ' ') optarg++;
  opts->ip = inet_addr(optarg);
  if (opts->ip == 0) return RESULT_FAIL_ARG;

  return RESULT_SUCCESS;
}

Result_T get_opt_port(JoltOptions *opts, const char *optarg) {
  assert(opts != NULL && optarg != NULL);

  errno = 0;
  char *endptr = NULL;
  opts->port = (uint16_t)strtol(optarg, &endptr, 0);
  if (errno != 0 || endptr == optarg || *endptr != '\0' || opts->port == 0)
    return RESULT_FAIL_ARG;

  return RESULT_SUCCESS;
}

Result_T retrieve_max_threads(long *nprocs) {
  *nprocs = sysconf(_SC_NPROCESSORS_ONLN);
  if (*nprocs == -1) return RESULT_FAIL_THREAD;

  return RESULT_SUCCESS;
}

Result_T get_opt_nthreads(JoltOptions *opts, const char *optarg) {
  assert(opts != NULL && optarg != NULL);

  errno = 0;
  char *endptr = NULL;
  opts->nthreads = (uint16_t)strtol(optarg, &endptr, 0);
  if (errno != 0 || endptr == optarg || *endptr != '\0')
    return RESULT_FAIL_UNKNOWN;

  long nprocs = 0;
  if (retrieve_max_threads(&nprocs) != RESULT_SUCCESS ||
      opts->nthreads > nprocs || opts->nthreads <= 0)
    return RESULT_FAIL_THREAD;

  return RESULT_SUCCESS;
}

Result_T parse_opts(JoltOptions *option_struct, int argc,
                    const char *const *const argv) {
  assert(argc > 0 && argv != NULL);

  Result_T result = RESULT_SUCCESS;

#ifdef TESTING
  char *const argv_copy[] = {
      "./j0lt",     // Program name
      "-t",         // Option for target
      "127.0.0.1",  // IP address
      "8080",       // Port number
      "-n",         // Option for number of connections
      "1",          // Number of connections
      "-x",         // Another option
      NULL          // Null pointer to mark the end of the array
  };
  argc = sizeof(argv_copy) / sizeof(argv_copy[0]) - 1;
#else
  char *const *argv_copy = (char *const *)argv;
#endif  // TESTING

  init_opts(option_struct);
  int opt = getopt(argc, argv_copy, GLOBAL_STRING_OPTS);
  do {
    switch (opt) {
      case 't':
        result = get_opt_target(option_struct, optarg);
        break;
      case 'p':
        result = get_opt_port(option_struct, optarg);
        break;
      case 'n':
        result = get_opt_nthreads(option_struct, optarg);
        break;
      case 'x':
        option_struct->hex_mode = true;
        break;
      case 'd':
        option_struct->debug_mode = true;
        break;
      default:
        result = RESULT_FAIL_ARG;
        break;
    }
  } while ((opt = getopt(argc, (char *const *)argv_copy, GLOBAL_STRING_OPTS)) != -1);

  if (result == RESULT_FAIL_ARG)
    fprintf(stderr,
            "Usage: ./j0lt -t target -p port -n nthreads [OPTION]...\n");

  return result;
}

void init_opts(JoltOptions *opts) {
  assert(opts != NULL);
  opts->ip = 0;
  opts->port = 0;
  opts->nthreads = 0;
  opts->debug_mode = false;
  opts->hex_mode = false;
}
