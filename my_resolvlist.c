#include <spawn.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "io.h"
#include "process_control.h"
#include "result.h"

char **environ;

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

Result_T wget_resolvlist_and_save_path(const char *const pathname,
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
