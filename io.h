#ifndef IO_H
#define IO_H

#include <stdbool.h>
#include <stddef.h>

bool read_file_into_mem (const char *filename, void **data_out,
                         size_t *size_out);
size_t readline (char *src, char *dest, size_t srclim, size_t destlim);
void print_hex (void *data, size_t len);
bool insert_data (void **dst, size_t *dst_buflen, const void *src,
                  size_t src_len);

#endif // IO_H