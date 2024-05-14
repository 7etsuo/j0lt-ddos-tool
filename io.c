#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "io.h"
#include "result.h"

void do_deallocate_buffer(void **data, size_t size) {
  if (data == NULL) return;
  memset(*data, 0, size);
  free(*data);
  *data = NULL;
}

Result_T do_allocate_buffer(void **data_out, size_t size) {
  if (size == 0) return RESULT_FAIL_MEM;
  *data_out = malloc(size);
  if (*data_out == NULL) return RESULT_FAIL_MEM;
  return RESULT_SUCCESS;
}

Result_T read_file_into_mem(const char *filename, void **data_out,
                            size_t *size_out) {
  if (filename == NULL || size_out == NULL) {
    fprintf(stderr, "NULL pointer error\n");
    return RESULT_FAIL_ARG;
  }

  struct stat st;
  if (stat(filename, &st) != 0) {
    perror("Failed to get file size");
    return RESULT_FAIL_IO;
  }
  size_t filesize = st.st_size;

  if (do_allocate_buffer(data_out, filesize) != RESULT_SUCCESS) {
#ifdef DEBUG
    fprintf(stderr, "Failed to allocate memory\n");
#endif  // DEBUG
    return RESULT_FAIL_MEM;
  }

  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    perror("Failed to open file");
    return RESULT_FAIL_IO;
  }

  void *mem = malloc(filesize);
  if (mem == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    fclose(file);
    return RESULT_FAIL_MEM;
  }

  if (fread(mem, filesize, 1, file) != 1) {
    fprintf(stderr, "Failed to read data\n");
    fclose(file);
    free(mem);
    return RESULT_FAIL_IO;
  }

  fclose(file);

  *data_out = mem;
  *size_out = filesize;

  return RESULT_SUCCESS;
}

size_t readline(char *src, char *dest, size_t srclim, size_t destlim) {
  if (src == NULL || dest == NULL) {
    fprintf(stderr, "NULL pointer error\n");
    return 0;
  }

  size_t i;
  for (i = 0; i < srclim - 1 && i < destlim - 1; ++i) {
    if (*dest == '\n') {
      break;
    }
    src[i] = *dest++;
  }

  src[i] = '\0';

  return i;
}

bool insert_data(void **dst, size_t *dst_buflen, const void *src,
                 size_t src_len) {
  if (dst == NULL || dst_buflen == NULL || src == NULL) {
    fprintf(stderr, "NULL pointer error\n");
    return false;
  }

  if (*dst_buflen < src_len) return false;

  memcpy(*dst, src, src_len);
  *dst += src_len;
  *dst_buflen -= src_len;

  return true;
}

void print_hex(const void *data, size_t len) {
  if (data == NULL) {
    fprintf(stderr, "NULL pointer error\n");
    return;
  }

  const uint8_t *d = (const uint8_t *)data;
  size_t i, j;
  for (j = 0, i = 0; i < len; i++) {
    if (i % 16 == 0) {
      printf("\n0x%.4zx: ", j);
      j += 16;
    }
    if (i % 2 == 0) putchar(' ');
    printf("%.2x", d[i]);
  }
  putchar('\n');
}

char *get_current_directory_with_filename(const char *const filename) {
  if (filename == NULL) return NULL;

  char *cwd = getcwd(NULL, 0);
  if (cwd == NULL) {
    perror("Failed to get current directory");
    return NULL;
  }

  size_t path_length = strlen(cwd) + strlen(filename) +
                       2;  // +2 for the slash and null terminator.
  char *full_path = malloc(path_length * sizeof(char));
  if (full_path == NULL) {
    perror("Failed to allocate memory for full path");
    free(cwd);
    return NULL;
  }

  snprintf(full_path, path_length, "%s/%s", cwd, filename);

  free(cwd);

  return full_path;
}

void debug_print(bool condition, const char *message, int value) {
  if (condition) printf(message, value);
}
