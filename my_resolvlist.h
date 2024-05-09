#ifndef MY_RESOLVLIST_H
#define MY_RESOLVLIST_H

#include "result.h"
#include "my_types.h"

extern GLOBAL_STRING_TYPE GLOBAL_STRING_RESOLV_LIST_SAVE_NAME;

Result_T get_resolver_list(void **data_out, size_t *size_out);

#endif  // MY_RESOLVLIST_H