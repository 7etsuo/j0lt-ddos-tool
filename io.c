#include "io.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool
read_file_into_mem (const char *filename, void **data_out, size_t *size_out)
{
  if (filename == NULL || data_out == NULL || size_out == NULL)
    {
      fprintf (stderr, "NULL pointer error\n");
      return false;
    }

  struct stat st;
  if (stat (filename, &st) != 0)
    {
      perror ("Failed to get file size");
      return false;
    }
  size_t filesize = st.st_size;

  FILE *file = fopen (filename, "rb");
  if (file == NULL)
    {
      perror ("Failed to open file");
      return false;
    }

  void *mem = malloc (filesize);
  if (mem == NULL)
    {
      fprintf (stderr, "Failed to allocate memory\n");
      fclose (file);
      return false;
    }

  if (fread (mem, filesize, 1, file) != 1)
    {
      fprintf (stderr, "Failed to read data\n");
      fclose (file);
      free (mem);
      return false;
    }

  fclose (file);

  *data_out = mem;
  *size_out = filesize;
  return true;
}

size_t
readline (char *src, char *dest, size_t srclim, size_t destlim)
{
  if (src == NULL || dest == NULL)
    {
      fprintf (stderr, "NULL pointer error\n");
      return 0;
    }

  size_t i;
  for (i = 0; i < srclim - 1 && i < destlim - 1; ++i)
    {
      if (*dest == '\n')
        {
          break;
        }
      src[i] = *dest++;
    }

  src[i] = '\0';

  return i;
}

bool
insert_data (void **dst, size_t *dst_buflen, const void *src, size_t src_len)
{
  if (dst == NULL || dst_buflen == NULL || src == NULL)
    {
      fprintf (stderr, "NULL pointer error\n");
      return false;
    }

  if (*dst_buflen < src_len)
    return false;

  memcpy (*dst, src, src_len);
  *dst += src_len;
  *dst_buflen -= src_len;

  return true;
}

void
print_hex (void *data, size_t len)
{
  if (data == NULL)
    {
      fprintf (stderr, "NULL pointer error\n");
      return;
    }

  const uint8_t *d = (const uint8_t *)data;
  size_t i, j;
  for (j = 0, i = 0; i < len; i++)
    {
      if (i % 16 == 0)
        {
          printf ("\n0x%.4zx: ", j);
          j += 16;
        }
      if (i % 2 == 0)
        putchar (' ');
      printf ("%.2x", d[i]);
    }
  putchar ('\n');
}
