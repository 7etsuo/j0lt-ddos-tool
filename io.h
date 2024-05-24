#ifndef IO_H
#define IO_H

#include <stdbool.h>
#include <stddef.h>

#include "result.h"

Result_T read_file_into_mem(const char *filename, void **data_out,
                            size_t *size_out);
size_t readline(const char *src, char *dest, size_t srclim, size_t destlim);
void print_hex(const void *data, size_t len);
bool insert_data(void **dst, size_t *dst_buflen, const void *src,
                 size_t src_len);
char *get_current_directory_with_filename(const char *const filename);

Result_T do_allocate_buffer(void **data_out, size_t size);
void do_deallocate_buffer(void **data, size_t size);
void debug_print(bool condition, const char *message, int value);

#endif  // IO_H
