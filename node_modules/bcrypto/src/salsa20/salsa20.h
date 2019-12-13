/**
 * Parts of this software are based on chacha20-simple:
 * http://chacha20.insanecoding.org/
 *
 *   Copyright (C) 2014 insane coder
 *
 *   Permission to use, copy, modify, and distribute this software for any
 *   purpose with or without fee is hereby granted, provided that the above
 *   copyright notice and this permission notice appear in all copies.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 *   SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 *   IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   This implementation is intended to be simple, many optimizations can be
 *   performed.
 */

#ifndef _BCRYPTO_SALSA20_H
#define _BCRYPTO_SALSA20_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct {
  uint32_t state[16];
  uint32_t stream[16];
  size_t available;
} bcrypto_salsa20_ctx;

void
bcrypto_salsa20_init(bcrypto_salsa20_ctx *ctx,
                     const uint8_t *key,
                     size_t key_len,
                     const uint8_t *nonce,
                     size_t nonce_len,
                     uint64_t counter);

void
bcrypto_salsa20_block(bcrypto_salsa20_ctx *ctx, uint32_t output[16]);

void
bcrypto_salsa20_encrypt(bcrypto_salsa20_ctx *ctx,
                        uint8_t *out,
                        const uint8_t *in,
                        size_t length);

void
bcrypto_salsa20_derive(uint8_t *out,
                       const uint8_t *key,
                       size_t key_len,
                       const uint8_t *nonce,
                       size_t nonce_len);

#if defined(__cplusplus)
}
#endif

#endif
