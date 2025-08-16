/* 
    simple header-only "library" for multiple hash digests
*/
#ifndef _DIGEST_H
#define _DIGEST_H

/* pretty sure this is just a hack */
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

int digest_sha512(uint8_t *source, uint64_t source_length, uint64_t *destination);
int digest_sha384(uint8_t *source, uint64_t source_length, uint64_t *destination);
int digest_sha256(uint8_t *source, uint32_t source_length, uint32_t *destination);

#endif /* _DIGEST_H */

#ifdef DIGEST_IMPLEMENTATION

#include <string.h>
#include <errno.h>
#include <stdlib.h>

/* SHA-512 implementation */

static const uint64_t digest_sha512_K[80] = {
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

static const uint64_t digest_sha512_H[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

/* SHA-512 implementation */

static uint64_t digest_sha512_Ch(uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (~x & z);
}

static uint64_t digest_sha512_Maj(uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint64_t digest_sha512_rotr(uint64_t x, unsigned short n)
{
  return (x >> n) | (x << (64 - n));
}

static uint64_t digest_sha512_S_0(uint64_t x)
{
  return digest_sha512_rotr(x, 28) ^ digest_sha512_rotr(x, 34) ^ digest_sha512_rotr(x, 39);
}

static uint64_t digest_sha512_S_1(uint64_t x)
{
  return digest_sha512_rotr(x, 14) ^ digest_sha512_rotr(x, 18) ^ digest_sha512_rotr(x, 41);
}

static uint64_t digest_sha512_s_0(uint64_t x)
{
  return digest_sha512_rotr(x, 1) ^ digest_sha512_rotr(x, 8) ^ (x >> 7);
}

static uint64_t digest_sha512_s_1(uint64_t x)
{
  return digest_sha512_rotr(x, 19) ^ digest_sha512_rotr(x, 61) ^ (x >> 6);
}

/* source: message, array of bytes */
/* source_length: message length in bytes */
/* destination: uint64_t[8] (result) */
/* RETURN non-zero on error and sets errno (indirectly) */
int digest_sha512(uint8_t *source, uint64_t source_length, uint64_t *destination)
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
    hash[i] = digest_sha512_H[i];
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
      W[i] = digest_sha512_s_1(W[i - 2]) + W[i - 7] + digest_sha512_s_0(W[i - 15]) + W[i - 16];
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
      T_1 = h + digest_sha512_S_1(e) + digest_sha512_Ch(e, f, g) + digest_sha512_K[i] + W[i];
      T_2 = digest_sha512_S_0(a) + digest_sha512_Maj(a, b, c);
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

/* SHA-384 implementation */

#define digest_sha384_K digest_sha512_K

static const uint64_t digest_sha384_H[8] = {
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
  0x9159015a3070dd17, 0x152fecd8f70e5939,
  0x67332667ffc00b31, 0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

#define digest_sha384_Ch   digest_sha512_Ch
#define digest_sha384_Maj  digest_sha512_Maj
#define digest_sha384_rotr digest_sha512_rotr
#define digest_sha384_S_0  digest_sha512_S_0
#define digest_sha384_S_1  digest_sha512_S_1
#define digest_sha384_s_0  digest_sha512_s_0
#define digest_sha384_s_1  digest_sha512_s_1

/* source: message, array of bytes */
/* source_length: message length in bytes */
/* destination: uint64_t[6] (result) */
/* RETURN non-zero on error and sets errno (indirectly) */
int digest_sha384(uint8_t *source, uint64_t source_length, uint64_t *destination)
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
    hash[i] = digest_sha384_H[i];
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
      W[i] = digest_sha384_s_1(W[i - 2]) + W[i - 7] + digest_sha384_s_0(W[i - 15]) + W[i - 16];
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
      T_1 = h + digest_sha384_S_1(e) + digest_sha384_Ch(e, f, g) + digest_sha384_K[i] + W[i];
      T_2 = digest_sha384_S_0(a) + digest_sha384_Maj(a, b, c);
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

  for (i = 0; i < 6; i++) {
    destination[i] = hash[i];
  }

  free(data);

  return 0;
}

/* SHA-256 implementation */

static const uint32_t digest_sha256_K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t digest_sha256_H[8] = {
  0x6a09e667, 0xbb67ae85,
  0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c,
  0x1f83d9ab, 0x5be0cd19
};

static uint32_t digest_sha256_Ch(uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) ^ (~x & z);
}

static uint32_t digest_sha256_Maj(uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t digest_sha256_rotr(uint32_t x, unsigned short n)
{
  return (x >> n) | (x << (32 - n));
}

static uint32_t digest_sha256_S_0(uint32_t x)
{
  return digest_sha256_rotr(x, 2) ^ digest_sha256_rotr(x, 13) ^ digest_sha256_rotr(x, 22);
}

static uint32_t digest_sha256_S_1(uint32_t x)
{
  return digest_sha256_rotr(x, 6) ^ digest_sha256_rotr(x, 11) ^ digest_sha256_rotr(x, 25);
}

static uint32_t digest_sha256_s_0(uint32_t x)
{
  return digest_sha256_rotr(x, 7) ^ digest_sha256_rotr(x, 18) ^ (x >> 3);
}

static uint32_t digest_sha256_s_1(uint32_t x)
{
  return digest_sha256_rotr(x, 17) ^ digest_sha256_rotr(x, 19) ^ (x >> 10);
}

/* source: message, array of bytes */
/* source_length: message length in bytes */
/* destination: uint32_t[8] (result) */
/* RETURN non-zero on error and sets errno (indirectly) */
int digest_sha256(uint8_t *source, uint32_t source_length, uint32_t *destination)
{
  uint8_t *data = NULL;
  uint64_t data_length;
  uint64_t source_length_bits;
  uint64_t n_zeroes;
  uint32_t W[64];

  uint64_t i;
  uint64_t j;
  uint8_t *it;
  void *end;

  uint32_t a, b, c, d, e, f, g, h;
  uint32_t T_1, T_2;

  source_length_bits = source_length * 8;

  /* calculate padding */
  for (n_zeroes = 0; (source_length_bits + 1 + n_zeroes) % 512 != 448; n_zeroes++);

  data_length = source_length + (1 + n_zeroes + 64) / 8;
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
    destination[i] = digest_sha256_H[i];
  }

  for (it = data, end = &data[data_length]; it != end; it += 64) {
    for (i = 0; i < 16; i++) {
      uint32_t value = 0;
      for (j = 0; j < 4; j++) {
        value <<= 8;
        value |= *(it + i * 4 + j);
      }

      W[i] = value;
    }

    for (i = 16; i < 64; i++) {
      W[i] = digest_sha256_s_1(W[i - 2]) + W[i - 7] + digest_sha256_s_0(W[i - 15]) + W[i - 16];
    }

    a = destination[0];
    b = destination[1];
    c = destination[2];
    d = destination[3];
    e = destination[4];
    f = destination[5];
    g = destination[6];
    h = destination[7];

    for (i = 0; i < 64; i++) {
      T_1 = h + digest_sha256_S_1(e) + digest_sha256_Ch(e, f, g) + digest_sha256_K[i] + W[i];
      T_2 = digest_sha256_S_0(a) + digest_sha256_Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T_1;
      d = c;
      c = b;
      b = a;
      a = T_1 + T_2;
    }

    destination[0] += a;
    destination[1] += b;
    destination[2] += c;
    destination[3] += d;
    destination[4] += e;
    destination[5] += f;
    destination[6] += g;
    destination[7] += h;
  }

  free(data);

  return 0;
}

#endif /* DIGEST_IMPLEMENTATION */

/*
    Revision history:

      2.2.2 (2025-8-16) added sha-384 implementation and patched sha-256
      2.1.1 (2025-8-15) remove unnecessary stdio.h + digest_sha256 implemented
      2.0.0 (2025-8-15) renamed to digest, added prefix
      1.0.0 (2025-8-14) first release
*/

/*
    TODO: get rid of malloc!
    TODO: platform independent
*/
