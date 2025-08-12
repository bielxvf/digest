/* SHA-512 implementation */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  return (x << n) | (x << (64 - n));
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

/* Errors */
#define ENLOBJ  0x7D0 /* Passed null object, expected non null */
#define ENNLOBJ 0x7D1 /* Passed non null object, expected null */

const char *my_strerror(int err)
{
  switch (err) {
    case ENLOBJ: return "BitStream error: A null pointer was passed";
    case ENNLOBJ: return "read_entire_file: A non null pointer was passed";
    default: return strerror(err);
  }
}

struct BitStream {
  uint8_t *items;
  size_t bytes_capacity;

  size_t bitcount;
};

/* Allocates a BitStream on the heap */
/* Returns a pointer to the newly allocated struct */
/* Returns NULL and sets errno if there were errors */
struct BitStream *BitStream_new(size_t bytes_capacity)
{
  struct BitStream *bs;
  bs = malloc(sizeof(struct BitStream));
  if (bs == NULL) return NULL; /* errno is set by malloc */

  size_t capacity = bytes_capacity == 0 ? 8 : bytes_capacity;
  bs->items = malloc(capacity);
  if (bs->items == NULL) return NULL; /* errno is set by malloc */

  memset(bs->items, 0, capacity);

  bs->bytes_capacity = capacity;
  bs->bitcount = 0;
  return bs;
}

/* Frees a heap allocated BitStream and its items */
void BitStream_free(struct BitStream *bs)
{
  assert(bs != NULL);
  assert(bs->items != NULL);
  free(bs->items);
  free(bs);
}

/* Appends a bit (either 0 or 1) to the BitStream */
/* Returns false and sets errno on error */
bool BitStream_append_bit(struct BitStream *bs, bool bit)
{
  if (bs == NULL) {
    errno = ENLOBJ;
    return false;
  }
  if (bs->bitcount + 1 > bs->bytes_capacity * 8) {
    size_t new_capacity = bs->bytes_capacity + (bs->bytes_capacity / 2);
    struct BitStream *new_bs = realloc(bs->items, new_capacity);
    if (new_bs == NULL) return false; /* errno is set by realloc */
    memset(
      bs->items + bs->bytes_capacity,
      0,
      new_capacity - bs->bytes_capacity
    );
    bs = new_bs;
    bs->bytes_capacity = new_capacity;
  }

  if (!bit) {
    bs->bitcount++;
    return true;
  }

  size_t byte_index = bs->bitcount == 0 ? 0 : bs->bitcount / 8 - 1;
  size_t bit_index = bs->bitcount == 0 ? 0 : bs->bitcount % 8;

  bs->items[byte_index] |= 1 << (7 - bit_index);
  bs->bitcount++;

  return true;
}

/* Reads an entire file by chunks */
/* Returns the amount of bytes read */
/* On realloc failure, returns number of bytes read so far, leaves *d allocated */
/* Returns 0 and sets errno on error */
size_t read_entire_file(FILE *fd, uint8_t **d)
{
  if (*d != NULL) {
    errno = ENNLOBJ;
    return 0;
  }
  *d = malloc(4096);
  if (*d == NULL) return 0; /* errno is set by malloc */
  size_t size = 0;
  size_t capacity = 4096;

  uint8_t buffer[4096];

  for (
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fd); /* reads sizeof(buffer) amount of bytes */
    bytes_read > 0;
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
    errno = EIO;
    return 0;
  }

  return size;
}

#define strerror my_strerror
int main(int argc, char **argv)
{
  /* TODO: commandline arguments, read all files, display sha512 sums for each */
  uint8_t *data = NULL;
  size_t data_size = read_entire_file(stdin, &data);
  if (data_size == 0) {
    fprintf(stderr, "Error reading from stdin: %s", strerror(errno));
    return errno;
  }

  printf("%s", (const char *) data);

  /* 5. Preprocessing */
  /* 5.1 Padding */
  /* 5.2 Parsing */
  /* 5.3 Setting the initial hash value */

  return 0;
}
