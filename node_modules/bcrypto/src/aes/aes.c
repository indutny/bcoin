#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "openssl/aes.h"

static inline void
XOR(uint8_t *out, const uint8_t *a, const uint8_t *b) {
  int i;
  for (i = 0; i < 16; i++)
    out[i] = a[i] ^ b[i];
}

int
bcrypto_aes_encipher(uint8_t *out,
                     size_t *outlen,
                     const uint8_t *data,
                     size_t datalen,
                     const uint8_t *key,
                     const uint8_t *iv) {
  const uint8_t *pblock = data;
  const uint8_t *pprev = pblock;
  const uint8_t *cprev = iv;
  uint8_t *cblock = out;
  size_t blocks = datalen / 16;
  size_t trailing = datalen % 16;
  size_t i;

  AES_KEY enckey;
  AES_set_encrypt_key(key, 256, &enckey);

  if (*outlen != datalen + (16 - trailing))
    return 0;

  // Encrypt all blocks except for the last.
  for (i = 0; i < blocks; i++) {
    XOR(cblock, pblock, cprev);
    AES_encrypt(cblock, cblock, &enckey);
    cprev = cblock;
    cblock += 16;
    pblock += 16;
    pprev = pblock;
  }

  // Handle padding on the last block.
  uint8_t *last = cblock;
  size_t left = 16 - trailing;

  memcpy(last, pprev, trailing);

  for (i = trailing; i < 16; i++)
    last[i] = left;

  // Encrypt the last block,
  // as well as the padding.
  XOR(cblock, last, cprev);
  AES_encrypt(cblock, cblock, &enckey);

  return 1;
}

int
bcrypto_aes_decipher(uint8_t *out,
                     size_t *outlen,
                     const uint8_t *data,
                     const size_t datalen,
                     const uint8_t *key,
                     const uint8_t *iv) {
  const uint8_t *cblock = data;
  const uint8_t *cprev = iv;
  uint8_t *pblock = out;
  uint8_t *pprev = pblock;
  size_t blocks = datalen / 16;
  size_t trailing = datalen % 16;
  size_t i;

  if (*outlen != datalen)
    return 0;

  if (trailing != 0)
    return 0;

  AES_KEY deckey;
  AES_set_decrypt_key(key, 256, &deckey);

  // Decrypt all blocks.
  for (i = 0; i < blocks; i++) {
    AES_decrypt(cblock, pblock, &deckey);
    XOR(pblock, pblock, cprev);
    cprev = cblock;
    pprev = pblock;
    cblock += 16;
    pblock += 16;
  }

  // Check padding on the last block.
  uint8_t *last = pprev;
  size_t b = 16;
  size_t n = last[b - 1];

  if (n == 0 || n > b)
    return 0;

  for (i = 0; i < n; i++) {
    if (last[--b] != n)
      return 0;
  }

  *outlen = datalen - n;

  return 1;
}
