#define BS_IMPLEMENTATION
#include <BitStream.h>

#include <assert.h>

int main()
{
  struct BitStream *bs = BitStream_create(1);
  BitStream_append_bit(bs, 1);
  assert(bs->items[0] == 128);
  BitStream_destroy(bs);
}
