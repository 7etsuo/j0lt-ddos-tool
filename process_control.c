#include <spawn.h>
#include <sys/wait.h>
#include <linux/wait.h>  // for WIFEXITED, WIFSIGNALED, WIFSTOPPED
#include <signal.h>
#include <unistd.h>

#include "result.h"
#include "process_control.h"

Result_T init_spawnattr(posix_spawnattr_t *attr) {
  int s = posix_spawnattr_init(attr);
  if (s != 0) return RESULT_FAIL_INIT;

  s = posix_spawnattr_setflags(attr,
                               POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP);
  if (s != 0) return RESULT_FAIL_ARG;

  sigset_t mask;
  sigfillset(&mask);
  // sigaddset(&mask, SIGINT | SIGQUIT | SIGTERM | SIGTSTP | SIGTTIN | SIGTTOU);
  s = posix_spawnattr_setsigmask(attr, &mask);
  if (s != 0) return RESULT_FAIL_ARG;

  return RESULT_SUCCESS;
}

Result_T spawn_process(const char *path,
                       posix_spawn_file_actions_t *file_actions,
                       posix_spawnattr_t *attr, char *const environ[]) {
  if (path == NULL) return RESULT_FAIL_ARG;
  if (access(path, X_OK) != 0) return RESULT_FAIL_PERM;

  pid_t child_pid;
  int s = posix_spawn(&child_pid, path, file_actions, attr,(const char **) &path, environ);
  if (s != 0) return RESULT_FAIL_IO;

  int status;
  do {
    s = waitpid(child_pid, &status, WUNTRACED | WCONTINUED);
    if (s == -1) return RESULT_FAIL_IO;
  } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  return RESULT_SUCCESS;
}

Result_T destroy_spawnattr(posix_spawnattr_t *attr) {
  int s = posix_spawnattr_destroy(attr);
  if (s != 0) return RESULT_FAIL_ARG;
  return RESULT_SUCCESS;
}

