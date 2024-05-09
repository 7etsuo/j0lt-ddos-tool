#ifndef PROCESS_CONTROL_H
#define PROCESS_CONTROL_H

#include <spawn.h>
#include "result.h"

Result_T init_spawnattr(posix_spawnattr_t *attr);
Result_T destroy_spawnattr(posix_spawnattr_t *attr);
Result_T spawn_process(const char *path,
                       posix_spawn_file_actions_t *file_actions,
                       posix_spawnattr_t *attr, char *const argv[], 
                       char *const environ[]);

#endif  // PROCESS_CONTROL_H
