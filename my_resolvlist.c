#include <spawn.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "process_control.h"
#include "my_resolvlist.h"
#include "my_types.h"
#include "result.h"
#include "io.h"

char **environ;
GLOBAL_STRING_TYPE GLOBAL_STRING_RESOLV_LIST_SAVE_NAME = "logs/j0lt-resolv.txt";

static Result_T do_wget_resolv_list(char *resolv_list_save_path) {
  if (resolv_list_save_path == NULL) return RESULT_FAIL_IO;
  char *wget[] = {"/bin/wget", "-O", resolv_list_save_path,
                  "https://public-dns.info/nameservers.txt", NULL};

#ifdef DEBUG
  printf("+ wget command: ");
  for (int i = 0; wget[i] != NULL; i++) printf("%s ", wget[i]);
#endif  // DEBUG

  posix_spawnattr_t attr = {0};
  posix_spawn_file_actions_t *file_actionsp = NULL;

  int status = init_spawnattr(&attr);
  if (status != 0) return status;

  status = spawn_process(wget[0], file_actionsp, &attr, wget, environ);
  if (status != 0) return status;

  status = destroy_spawnattr(&attr);
  if (status != 0) return status;

  return status;
}

static Result_T wget_resolvlist_and_save_path(const char *const pathname,
                                       char **result_path) {
  *result_path = get_current_directory_with_filename(pathname);
  if (*result_path == NULL) return RESULT_FAIL_IO;

  int status = do_wget_resolv_list(*result_path);
  if (status != RESULT_SUCCESS) {
    free(*result_path);
    *result_path = NULL;
  }

  return status;
}

static Result_T read_resolver_list_into_mem(char *filename, void **data_out, size_t *size_out) {
  Result_T result = read_file_into_mem(filename, data_out, size_out); 
  free(filename);
  return result;
}

Result_T get_resolver_list(void **data_out, size_t *size_out) {
  char *full_resolv_pathname = NULL;
  Result_T result = wget_resolvlist_and_save_path(GLOBAL_STRING_RESOLV_LIST_SAVE_NAME, &full_resolv_pathname);
  if (result != RESULT_SUCCESS) return result;
  printf("+ resolv list saved to %s\n", full_resolv_pathname);

  return read_resolver_list_into_mem(full_resolv_pathname, data_out, size_out);
}