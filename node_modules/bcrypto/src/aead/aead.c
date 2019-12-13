#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "aead.h"
#include "../chacha20/chacha20.h"
#include "../poly1305/poly1305.h"

static void
bcrypto_aead_pad16(bcrypto_aead_ctx *aead, uint64_t size);

void
bcrypto_aead_init(bcrypto_aead_ctx *aead) {
  memset(&aead->chacha, 0x00, sizeof(bcrypto_chacha20_ctx));
  memset(&aead->poly, 0x00, sizeof(bcrypto_poly1305_ctx));
  memset(&aead->key[0], 0x00, 64);
  aead->mode = -1;
  aead->aad_len = 0;
  aead->cipher_len = 0;
}

void
bcrypto_aead_setup(bcrypto_aead_ctx *aead,
                   const uint8_t *key,
                   const uint8_t *iv,
                   size_t iv_len) {
  memset(&aead->key[0], 0x00, 64);

  bcrypto_chacha20_init(&aead->chacha, key, 32, iv, iv_len, 0);
  bcrypto_chacha20_encrypt(&aead->chacha, aead->key, aead->key, 64);
  bcrypto_poly1305_init(&aead->poly, aead->key);

  aead->mode = 0;
  aead->aad_len = 0;
  aead->cipher_len = 0;
}

void
bcrypto_aead_aad(bcrypto_aead_ctx *aead, const uint8_t *aad, size_t len) {
  assert(aead->mode == 0);

  bcrypto_poly1305_update(&aead->poly, aad, len);

  aead->aad_len += len;
}

void
bcrypto_aead_encrypt(bcrypto_aead_ctx *aead,
                     uint8_t *out,
                     const uint8_t *in,
                     size_t len) {
  if (aead->mode == 0) {
    bcrypto_aead_pad16(aead, aead->aad_len);
    aead->mode = 1;
  }

  assert(aead->mode == 1);

  bcrypto_chacha20_encrypt(&aead->chacha, out, in, len);
  bcrypto_poly1305_update(&aead->poly, out, len);

  aead->cipher_len += len;
}

void
bcrypto_aead_decrypt(bcrypto_aead_ctx *aead,
                     uint8_t *out,
                     const uint8_t *in,
                     size_t len) {
  if (aead->mode == 0) {
    bcrypto_aead_pad16(aead, aead->aad_len);
    aead->mode = 2;
  }

  assert(aead->mode == 2);

  aead->cipher_len += len;

  bcrypto_poly1305_update(&aead->poly, in, len);
  bcrypto_chacha20_encrypt(&aead->chacha, out, in, len);
}

void
bcrypto_aead_auth(bcrypto_aead_ctx *aead, const uint8_t *in, size_t len) {
  if (aead->mode == 0) {
    bcrypto_aead_pad16(aead, aead->aad_len);
    aead->mode = 3;
  }

  assert(aead->mode == 3);

  aead->cipher_len += len;

  bcrypto_poly1305_update(&aead->poly, in, len);
}

void
bcrypto_aead_final(bcrypto_aead_ctx *aead, uint8_t *tag) {
  uint8_t len[16];

#ifdef WORDS_BIGENDIAN
  len[0] = aead->aad_len & 0xff;
  len[1] = (aead->aad_len >> 8) & 0xff;
  len[2] = (aead->aad_len >> 16) & 0xff;
  len[3] = (aead->aad_len >> 24) & 0xff;
  len[4] = (aead->aad_len >> 32) & 0xff;
  len[5] = (aead->aad_len >> 40) & 0xff;
  len[6] = (aead->aad_len >> 48) & 0xff;
  len[7] = (aead->aad_len >> 56) & 0xff;

  len[8] = aead->cipher_len & 0xff;
  len[9] = (aead->cipher_len >> 8) & 0xff;
  len[10] = (aead->cipher_len >> 16) & 0xff;
  len[11] = (aead->cipher_len >> 24) & 0xff;
  len[12] = (aead->cipher_len >> 32) & 0xff;
  len[13] = (aead->cipher_len >> 40) & 0xff;
  len[14] = (aead->cipher_len >> 48) & 0xff;
  len[15] = (aead->cipher_len >> 56) & 0xff;
#else
  memcpy(&len[0], (void *)&aead->aad_len, 8);
  memcpy(&len[8], (void *)&aead->cipher_len, 8);
#endif

  if (aead->mode == 0)
    bcrypto_aead_pad16(aead, aead->aad_len);

  bcrypto_aead_pad16(aead, aead->cipher_len);
  bcrypto_poly1305_update(&aead->poly, len, 16);

  bcrypto_poly1305_finish(&aead->poly, tag);

  aead->mode = -1;
}

static void
bcrypto_aead_pad16(bcrypto_aead_ctx *aead, uint64_t size) {
  uint64_t pos = size & 15;

  if (pos == 0)
    return;

  uint8_t pad[16];

  memset(&pad[0], 0x00, 16);

  bcrypto_poly1305_update(&aead->poly, pad, 16 - pos);
}

int
bcrypto_aead_verify(const uint8_t *mac1, const uint8_t *mac2) {
  return bcrypto_poly1305_verify(mac1, mac2) != 0;
}
