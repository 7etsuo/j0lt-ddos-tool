#ifndef JOLT_H
#define JOLT_H

#include <stddef.h>  // for size_t

#include "my_types.h"

// [TODO] replace with CHECK_SUCCESS forall subroutines
#include <stdlib.h>  // for exit, EXIT_FAILURE [TODO] remove with err_exit
#include <stdio.h>   // for perror [TODO] remove with err_exit
#define err_exit(msg)   \
  do {                  \
    perror(msg);        \
    exit(EXIT_FAILURE); \
  } while (0)

typedef struct JoltData {
  void *resolvlist_buffer;
  size_t szresolvlist;
  void (*dtors)(void **, size_t);
} JoltData;

extern GLOBAL_STRING_TYPE GLOBAL_STRING_MENU;

#endif  // JOLT_H
