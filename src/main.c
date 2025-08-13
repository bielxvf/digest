/* SHA-512 implementation */
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char bool;
#define true 1
#define false 0

uint64_t K[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd,
  0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019,
  0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe,
  0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
  0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
  0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
  0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210,
  0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725,
  0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926,
  0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8,
  0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001,
  0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910,
  0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
  0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
  0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60,
  0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9,
  0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207,
  0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6,
  0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493,
  0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
  0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (~x & z);
}

uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

uint64_t rotr(uint64_t x, unsigned short n)
{
  return (x >> n) | (x << (64 - n));
}

uint64_t S_0(uint64_t x)
{
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

uint64_t S_1(uint64_t x)
{
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

uint64_t s_0(uint64_t x)
{
  return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
}

uint64_t s_1(uint64_t x)
{
  return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

#define BS_IMPLEMENTATION
#include <BitStream.h>
/* Reads an entire file by chunks */
/* Returns the amount of bytes read */
/* On realloc failure, returns number of bytes read so far, leaves *d allocated */
/* Returns 0 and sets errno on error */
#define READ_ENTIRE_FILE_CHUNK_BYTE_SIZE 4096
size_t read_entire_file(FILE *fd, uint8_t **d)
{
  if (*d != NULL) {
    return 0;
  }
  *d = malloc(READ_ENTIRE_FILE_CHUNK_BYTE_SIZE);
  if (*d == NULL) return 0; /* errno is set by malloc */
  size_t size = 0;
  size_t capacity = READ_ENTIRE_FILE_CHUNK_BYTE_SIZE;

  uint8_t buffer[READ_ENTIRE_FILE_CHUNK_BYTE_SIZE];

  for (
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fd); /* reads sizeof(buffer) amount of bytes */
    bytes_read > 0;                                           /* the '1' refers to the amount of bytes */
    size += bytes_read, bytes_read = fread(buffer, 1, sizeof(buffer), fd)
  ) {
    if (capacity < size + bytes_read) {
      size_t new_capacity = capacity + (capacity / 2);
      while (new_capacity < size + bytes_read) {
        new_capacity += new_capacity / 2;
      }

      uint8_t *tmp = realloc(*d, new_capacity);
      if (tmp == NULL) {
        /* keep the data and let caller decide */
        return 0; /* errno is set by realloc */
      }

      *d = tmp;
      capacity = new_capacity;
    }

    memcpy(*d + size, buffer, bytes_read);
  }

  if (ferror(fd)) {
    return 0;
  }

  return size;
}

int main(int argc, char **argv)
{
  /* TODO: commandline arguments, read all files, display sha512 sums for each */
  uint8_t *data = NULL;
  size_t length = read_entire_file(stdin, &data);
  if (length == 0) {
    fprintf(stderr, "Error reading stdin: %s", strerror(errno));
    return errno;
  }

  void *end = &data[length];
  for (uint8_t *it = data; it != end; it++) {
    printf("%c", *it);
  }

  size_t bit_count = length * 8;

  return 0;
}

