#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "opts.h"

Result_T get_opt_target(JoltOptions *opts, const char *optarg) {
  assert(opts != NULL && optarg != NULL);

  while (*optarg == ' ') optarg++;
  opts->spoof_ip = inet_addr(optarg);
  if (opts->spoof_ip == 0) return RESULT_FAILURE;

  return RESULT_SUCCESS;
}

Result_T get_opt_port(JoltOptions *opts, const char *optarg) {
  assert(opts != NULL && optarg != NULL);

  errno = 0;
  char *endptr = NULL;
  opts->spoof_port = (uint16_t)strtol(optarg, &endptr, 0);
  if (errno != 0 || endptr == optarg || *endptr != '\0' || opts->spoof_port == 0) return RESULT_FAILURE;

  return RESULT_SUCCESS;
}

Result_T retrieve_max_threads(void) {
  long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
  if (nprocs == -1) return RESULT_FAIL_THREAD;

  return RESULT_SUCCESS;
}

Result_T get_opt_nthreads(JoltOptions *opts, const char *optarg) {
  assert(opts != NULL && optarg != NULL);

  errno = 0;
  char *endptr = NULL;
  opts->nthreads = (uint16_t)strtol(optarg, &endptr, 0);
  if (errno != 0 || endptr == optarg || *endptr != '\0') return RESULT_FAILURE;

  int max_threads = retrieve_max_threads();
  if (opts->nthreads > max_threads || opts->nthreads <= 0) return RESULT_FAIL_THREAD;

  return RESULT_SUCCESS;
}

Result_T parse_opts(JoltOptions *opts, int argc, const char **argv) {
  assert(argc > 0 && argv != NULL);

  Result_T result = RESULT_SUCCESS;

  int opt = getopt(argc, (char *const *)argv, g_args);
  do {
    switch (opt) {
      case 't':
        result = get_opt_target(opts, optarg);
        break;
      case 'p':
        result = get_opt_port(opts, optarg);
        break;
      case 'n':
        result = get_opt_nthreads(opts, optarg);
        break;
      case 'x':
        opts->hex_mode = true;
        break;
      case 'd':
        opts->debug_mode = true;
        break;
      default:
        result = RESULT_FAILURE;
        break;
    }
  } while ((opt = getopt(argc, (char *const *)argv, g_args)) != -1);

  if (result == RESULT_FAILURE) 
    fprintf(stderr, "Usage: ./j0lt -t target -p port -n nthreads [OPTION]...\n");

  return result;
}

void init_opts(JoltOptions *opts) {
  assert(opts != NULL);
  opts->spoof_ip = 0;
  opts->spoof_port = 0;
  opts->nthreads = 0;
  opts->debug_mode = false;
  opts->hex_mode = false;
}


