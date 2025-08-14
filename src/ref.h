/* 
    simple header-only "library" to read an entire file
*/
#ifndef _REF_H
#define _REF_H

#include <stdio.h>
#include <stdint.h>

uint64_t read_entire_file(FILE *fd, uint8_t **d);

#endif /* _REF_H */

#ifdef REF_IMPLEMENTATION

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Reads an entire file by chunks, allocating on the heap */
/* Returns the amount of bytes read */
/* a NULL uint8_t should be passed to 'd' */
/* On realloc failure, returns number of bytes read so far, leaves *d allocated */
/* Returns 0 and sets errno on error */
#define READ_ENTIRE_FILE_CHUNK_BYTE_SIZE 4096
uint64_t read_entire_file(FILE *fd, uint8_t **d)
{
  uint64_t size;
  uint64_t capacity;
  uint64_t new_capacity;
  uint8_t buffer[READ_ENTIRE_FILE_CHUNK_BYTE_SIZE];
  uint64_t bytes_read;
  uint8_t **tmp = d;

  if (*d != NULL) {
    return 0;
  }
  *d = malloc(READ_ENTIRE_FILE_CHUNK_BYTE_SIZE);
  if (*d == NULL) return 0; /* errno is set by malloc */
  size = 0;
  capacity = READ_ENTIRE_FILE_CHUNK_BYTE_SIZE;

  for (
    bytes_read = fread(buffer, 1, sizeof buffer, fd); /* reads (sizeof buffer) amount of bytes */
    bytes_read > 0;                                           /* the '1' refers to the amount of bytes */
    size += bytes_read, bytes_read = fread(buffer, 1, sizeof buffer, fd)
  ) {
    if (capacity < size + bytes_read) {
      new_capacity = capacity + (capacity / 2);
      *tmp = realloc(*d, new_capacity);
      while (new_capacity < size + bytes_read) {
        new_capacity += new_capacity / 2;
      }

      if (tmp == NULL) {
        /* keep the data and let caller decide */
        return 0; /* errno is set by realloc */
      }

      *d = *tmp;
      capacity = new_capacity;
    }

    memcpy(*d + size, buffer, bytes_read);
  }

  if (ferror(fd)) {
    return 0;
  }

  return size;
}

#endif /* REF_IMPLEMENTATION */

/*
    Revision history:

      1.0.0 (2025-8-14) first release
*/
/* 
    TODO: get rid of malloc!
*/
