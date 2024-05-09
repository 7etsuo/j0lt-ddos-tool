#ifndef MY_RESOLVLIST_H
#define MY_RESOLVLIST_H

#include "result.h"

Result_T wget_resolvlist_and_save_path(const char *const pathname,
                                       char **result_path);

#endif // MY_RESOLVLIST_H