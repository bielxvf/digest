#ifndef _SHA512_H
#define _SHA512_H

const uint64_t sha512_K[80] = {
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

const uint64_t sha512_H[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

int sha512_digest(uint8_t *source, uint64_t source_length, uint64_t *destination);

#endif /* _SHA512_H */

#ifdef SHA512_IMPLEMENTATION

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static uint64_t sha512_Ch(uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (~x & z);
}

static uint64_t sha512_Maj(uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint64_t sha512_rotr(uint64_t x, unsigned short n)
{
  return (x >> n) | (x << (64 - n));
}

static uint64_t sha512_S_0(uint64_t x)
{
  return sha512_rotr(x, 28) ^ sha512_rotr(x, 34) ^ sha512_rotr(x, 39);
}

static uint64_t sha512_S_1(uint64_t x)
{
  return sha512_rotr(x, 14) ^ sha512_rotr(x, 18) ^ sha512_rotr(x, 41);
}

static uint64_t sha512_s_0(uint64_t x)
{
  return sha512_rotr(x, 1) ^ sha512_rotr(x, 8) ^ (x >> 7);
}

static uint64_t sha512_s_1(uint64_t x)
{
  return sha512_rotr(x, 19) ^ sha512_rotr(x, 61) ^ (x >> 6);
}

/* source: message, array of bytes */
/* source_length: message length in bytes */
/* destination: uint64_t[8] (result) */
/* RETURN non-zero on error and sets errno (indirectly) */
int sha512_digest(uint8_t *source, uint64_t source_length, uint64_t *destination)
{
  uint8_t *data = NULL;
  uint64_t data_length;
  uint64_t source_length_bits;
  uint64_t n_zeroes;
  uint64_t W[80];
  uint64_t hash[8];

  uint64_t i;
  uint64_t j;
  uint8_t *it;
  void *end;

  uint64_t a, b, c, d, e, f, g, h;
  uint64_t T_1, T_2;

  source_length_bits = source_length * 8;

  /* calculate padding */
  for (n_zeroes = 0; (source_length_bits + 1 + n_zeroes) % 1024 != 896; n_zeroes++);

  data_length = source_length + (1 + n_zeroes + 128) / 8;
  data = malloc(data_length);
  if (data == NULL) {
    return errno;
  }

  memcpy(data, source, source_length);
  memset(data + source_length, 0, data_length - source_length);
  data[source_length] |= 1 << 7;

  for (i = 0; i < 8; i++) {
    data[data_length - 8 + i] |= (uint8_t) (source_length_bits >> ((7 - i) * 8));
  }
  
  for (i = 0; i < 8; i++) {
    hash[i] = sha512_H[i];
  }

  for (it = data, end = &data[data_length]; it != end; it += 128) {
    for (i = 0; i < 16; i++) {
      uint64_t value = 0;
      for (j = 0; j < 8; j++) {
        value <<= 8;
        value |= *(it + i * 8 + j);
      }

      W[i] = value;
    }

    for (i = 16; i < 80; i++) {
      W[i] = sha512_s_1(W[i - 2]) + W[i - 7] + sha512_s_0(W[i - 15]) + W[i - 16];
    }

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    for (i = 0; i < 80; i++) {
      T_1 = h + sha512_S_1(e) + sha512_Ch(e, f, g) + sha512_K[i] + W[i];
      T_2 = sha512_S_0(a) + sha512_Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T_1;
      d = c;
      c = b;
      b = a;
      a = T_1 + T_2;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
  }

  for (i = 0; i < 8; i++) {
    destination[i] = hash[i];
  }

  free(data);

  return 0;
}

#endif /* SHA512_IMPLEMENTATION */
