#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

struct BitStream {
  uint8_t *items;
  size_t bytes_capacity;

  size_t bitcount;
};

struct BitStream *BitStream_create(size_t bytes_capacity);
void BitStream_destroy(struct BitStream *bs);
bool BitStream_append_bit(struct BitStream *bs, bool bit);
bool BitStream_append_uint8(struct BitStream *bs, uint8_t byte);

#ifdef BS_IMPLEMENTATION
/* Allocates a BitStream on the heap */
/* Returns a pointer to the newly allocated struct */
/* Returns NULL and sets errno if there were errors */
struct BitStream *BitStream_create(size_t bytes_capacity)
{
  struct BitStream *bs = malloc(sizeof *bs);
  if (bs == NULL) return NULL; /* errno is set by malloc */

  size_t capacity = bytes_capacity == 0 ? 8 : bytes_capacity;
  bs->items = malloc(capacity);
  if (bs->items == NULL) return NULL; /* errno is set by malloc */

  memset(bs->items, 0, capacity);

  bs->bytes_capacity = capacity;
  bs->bitcount = 0;
  return bs;
}

/* Destroys a heap allocated BitStream and its items */
void BitStream_destroy(struct BitStream *bs)
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
    return false;
  }
  if (bs->bitcount + 1 > bs->bytes_capacity * 8) {
    size_t new_capacity = bs->bytes_capacity + (bs->bytes_capacity / 2);
    uint8_t *new_items = realloc(bs->items, new_capacity);
    if (new_items == NULL) return false; /* errno is set by realloc */
    memset(
      bs->items + bs->bytes_capacity,
      0,
      new_capacity - bs->bytes_capacity
    );
    bs->items = new_items;
    bs->bytes_capacity = new_capacity;
  }

  if (!bit) {
    bs->bitcount++;
    return true;
  }

  size_t byte_index = bs->bitcount / 8;
  size_t bit_index = bs->bitcount % 8;

  bs->items[byte_index] |= 1 << (7 - bit_index);
  bs->bitcount++;

  return true;
}

/* Appends a byte to the BitStream */
/* Returns false and sets errno on error */
bool BitStream_append_uint8(struct BitStream *bs, uint8_t byte)
{
  if (bs == NULL) {
    return false;
  }
  
  if (bs->bitcount + 8 > bs->bytes_capacity * 8) {
    size_t new_capacity = bs->bytes_capacity + (bs->bytes_capacity / 2);
    uint8_t *new_items = realloc(bs->items, new_capacity);
    if (new_items == NULL) return false; /* errno is set by realloc */
    memset(
      bs->items + bs->bytes_capacity,
      0,
      new_capacity - bs->bytes_capacity
    );
    bs->items = new_items;
    bs->bytes_capacity = new_capacity;
  }

  size_t bs_byte_index = bs->bitcount / 8;
  size_t bs_bit_index = bs->bitcount % 8;

  short byte_index = 0;
  for (short i = bs_bit_index; i < 7; i++) {
    bs->items[bs_byte_index] |= ((1 >> (7 - byte_index++)) & byte) >> (7 - i);
  }

  if (bs_bit_index > 0) {
    for (unsigned short i = 0; i < 7 - bs_bit_index; i++) {
      bs->items[bs_byte_index + 1] |= ((1 >> (7 - byte_index++)) & byte) >> (7 - i); 
    }
  }

  bs->bitcount += 8;
  return true;
}
#endif /* BS_IMPLEMENTATION */
