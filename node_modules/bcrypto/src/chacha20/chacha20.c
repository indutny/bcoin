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

#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "chacha20.h"

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))

#define READLE(p)               \
  (((uint32_t)((p)[0]))         \
  | ((uint32_t)((p)[1]) << 8)   \
  | ((uint32_t)((p)[2]) << 16)  \
  | ((uint32_t)((p)[3]) << 24))

#define WRITELE(b, i)        \
  (b)[0] = i & 0xFF;         \
  (b)[1] = (i >> 8) & 0xFF;  \
  (b)[2] = (i >> 16) & 0xFF; \
  (b)[3] = (i >> 24) & 0xFF;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define QUARTERROUND(x, a, b, c, d)             \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8);  \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

void
bcrypto_chacha20_init(bcrypto_chacha20_ctx *ctx,
                      const uint8_t *key,
                      size_t key_len,
                      const uint8_t *nonce,
                      size_t nonce_len,
                      uint64_t counter) {
  assert(key_len == 16 || key_len == 32);

  uint8_t key_[32];
  uint8_t nonce_[16];

  memcpy(&key_[0], key, MIN(32, key_len));
  memcpy(&nonce_[0], nonce, MIN(16, nonce_len));

  // XChaCha20
  if (nonce_len >= 24) {
    bcrypto_chacha20_derive(&key_[0], key, key_len, nonce, 16);

    key_len = 32;
    nonce_len -= 16;

    memcpy(&nonce_[0], &nonce[16], MIN(16, nonce_len));
  }

  const char *constants = (key_len == 32)
    ? "expand 32-byte k"
    : "expand 16-byte k";

  ctx->state[0] = READLE(constants + 0);
  ctx->state[1] = READLE(constants + 4);
  ctx->state[2] = READLE(constants + 8);
  ctx->state[3] = READLE(constants + 12);
  ctx->state[4] = READLE(key_ + 0);
  ctx->state[5] = READLE(key_ + 4);
  ctx->state[6] = READLE(key_ + 8);
  ctx->state[7] = READLE(key_ + 12);
  ctx->state[8] = READLE(key_ + 16 % key_len);
  ctx->state[9] = READLE(key_ + 20 % key_len);
  ctx->state[10] = READLE(key_ + 24 % key_len);
  ctx->state[11] = READLE(key_ + 28 % key_len);

  if (nonce_len == 8) {
    ctx->state[12] = counter & 0xffffffffu;
    ctx->state[13] = counter >> 32;
    ctx->state[14] = READLE(nonce_ + 0);
    ctx->state[15] = READLE(nonce_ + 4);
  } else if (nonce_len == 12) {
    ctx->state[12] = counter & 0xffffffffu;
    ctx->state[13] = READLE(nonce_ + 0);
    ctx->state[14] = READLE(nonce_ + 4);
    ctx->state[15] = READLE(nonce_ + 8);
  } else if (nonce_len == 16) {
    ctx->state[12] = READLE(nonce_ + 0);
    ctx->state[13] = READLE(nonce_ + 4);
    ctx->state[14] = READLE(nonce_ + 8);
    ctx->state[15] = READLE(nonce_ + 12);
  } else {
    assert(0 && "invalid nonce size for chacha20");
  }

  ctx->available = 0;
}

void
bcrypto_chacha20_block(bcrypto_chacha20_ctx *ctx, uint32_t output[16]) {
#ifdef BCRYPTO_USE_ASM
  // Borrowed from:
  // https://github.com/gnutls/nettle/blob/master/x86_64/chacha-core-internal.asm
  //
  // Note: Seems as though %rsi can't be clobbered here. Every ABI description
  // I've read says %rsi is clobber-able. Maybe GCC is doing something weird.
  // Futhermore, clang breaks if %edx is clobbered.
  //
  // See:
  // - https://github.com/gnutls/nettle/blob/master/x86_64/README
  // - https://wiki.cdot.senecacollege.ca/wiki/X86_64_Register_and_Instruction_Quick_Start
  //
  // Layout:
  //   %rsi = src pointer (&ctx->state[0])
  //   %rdi = dst pointer (&output[0])
  //   %edx = rounds integer (nettle does `20 >> 1`)
  //
  // For reference, our full range of clobbered registers:
  // rsi, rdi, edx
  __asm__ __volatile__(
    "movq %[src], %%rsi\n"
    "movq %[dst], %%rdi\n"
    "movl $20, %%edx\n"

    "movups (%%rsi), %%xmm0\n"
    "movups 16(%%rsi), %%xmm1\n"
    "movups 32(%%rsi), %%xmm2\n"
    "movups 48(%%rsi), %%xmm3\n"

    "shrl $1, %%edx\n"

    "1:\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"

    "pshufhw $0xb1, %%xmm3, %%xmm3\n"
    "pshuflw $0xb1, %%xmm3, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $12, %%xmm1\n"
    "psrld $20, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"
    "pslld $8, %%xmm3\n"
    "psrld $24, %%xmm4\n"
    "por %%xmm4, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $7, %%xmm1\n"
    "psrld $25, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "pshufd $0x39, %%xmm1, %%xmm1\n"
    "pshufd $0x4e, %%xmm2, %%xmm2\n"
    "pshufd $0x93, %%xmm3, %%xmm3\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"

    "pshufhw $0xb1, %%xmm3, %%xmm3\n"
    "pshuflw $0xb1, %%xmm3, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $12, %%xmm1\n"
    "psrld $20, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"
    "pslld $8, %%xmm3\n"
    "psrld $24, %%xmm4\n"
    "por %%xmm4, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $7, %%xmm1\n"
    "psrld $25, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "pshufd $0x93, %%xmm1, %%xmm1\n"
    "pshufd $0x4e, %%xmm2, %%xmm2\n"
    "pshufd $0x39, %%xmm3, %%xmm3\n"

    "decl %%edx\n"
    "jnz 1b\n"

    "movups (%%rsi), %%xmm4\n"
    "movups 16(%%rsi), %%xmm5\n"
    "paddd %%xmm4, %%xmm0\n"
    "paddd %%xmm5, %%xmm1\n"
    "movups %%xmm0,(%%rdi)\n"
    "movups %%xmm1,16(%%rdi)\n"
    "movups 32(%%rsi), %%xmm4\n"
    "movups 48(%%rsi), %%xmm5\n"
    "paddd %%xmm4, %%xmm2\n"
    "paddd %%xmm5, %%xmm3\n"
    "movups %%xmm2,32(%%rdi)\n"
    "movups %%xmm3,48(%%rdi)\n"

    "incq 48(%%rsi)\n"
    :
    : [src] "r" (ctx->state),
      [dst] "r" (output)
    : "rsi", "rdi", "edx", "cc", "memory"
  );
#else
  uint32_t *ctr = ctx->state + 12;
  int i = 10;

  memcpy(output, ctx->state, sizeof(ctx->state));

  while (i--) {
    QUARTERROUND(output, 0, 4, 8, 12)
    QUARTERROUND(output, 1, 5, 9, 13)
    QUARTERROUND(output, 2, 6, 10, 14)
    QUARTERROUND(output, 3, 7, 11, 15)
    QUARTERROUND(output, 0, 5, 10, 15)
    QUARTERROUND(output, 1, 6, 11, 12)
    QUARTERROUND(output, 2, 7, 8, 13)
    QUARTERROUND(output, 3, 4, 9, 14)
  }

  for (i = 0; i < 16; i++) {
    uint32_t result = output[i] + ctx->state[i];
    WRITELE((uint8_t *)(output + i), result);
  }

  if (++ctr[0] == 0)
    ctr[1] += 1;
#endif
}

static inline
void bcrypto_chacha20_xor(uint8_t *stream,
                          uint8_t **out,
                          const uint8_t **in,
                          size_t length) {
  uint8_t *end_stream = stream + length;
  do {
    *(*out)++ = *(*in)++ ^ *stream++;
  } while (stream < end_stream);
}

void
bcrypto_chacha20_encrypt(bcrypto_chacha20_ctx *ctx,
                         uint8_t *out,
                         const uint8_t *in,
                         size_t length) {
  if (length) {
    uint8_t *k = (uint8_t *)ctx->stream;

    if (ctx->available) {
      size_t amount = MIN(length, ctx->available);
      size_t size = sizeof(ctx->stream) - ctx->available;
      bcrypto_chacha20_xor(k + size, &out, &in, amount);
      ctx->available -= amount;
      length -= amount;
    }

    while (length) {
      size_t amount = MIN(length, sizeof(ctx->stream));
      bcrypto_chacha20_block(ctx, ctx->stream);
      bcrypto_chacha20_xor(k, &out, &in, amount);
      length -= amount;
      ctx->available = sizeof(ctx->stream) - amount;
    }
  }
}

void
bcrypto_chacha20_derive(uint8_t *out,
                        const uint8_t *key,
                        size_t key_len,
                        const uint8_t *nonce,
                        size_t nonce_len) {
  assert(key_len == 16 || key_len == 32);
  assert(nonce_len == 16);

  const char *constants = (key_len == 32)
    ? "expand 32-byte k"
    : "expand 16-byte k";

  uint32_t state[16];

  state[0] = READLE(constants + 0);
  state[1] = READLE(constants + 4);
  state[2] = READLE(constants + 8);
  state[3] = READLE(constants + 12);
  state[4] = READLE(key + 0);
  state[5] = READLE(key + 4);
  state[6] = READLE(key + 8);
  state[7] = READLE(key + 12);
  state[8] = READLE(key + 16 % key_len);
  state[9] = READLE(key + 20 % key_len);
  state[10] = READLE(key + 24 % key_len);
  state[11] = READLE(key + 28 % key_len);
  state[12] = READLE(nonce + 0);
  state[13] = READLE(nonce + 4);
  state[14] = READLE(nonce + 8);
  state[15] = READLE(nonce + 12);

  int i = 10;

  while (i--) {
    QUARTERROUND(state, 0, 4, 8, 12)
    QUARTERROUND(state, 1, 5, 9, 13)
    QUARTERROUND(state, 2, 6, 10, 14)
    QUARTERROUND(state, 3, 7, 11, 15)
    QUARTERROUND(state, 0, 5, 10, 15)
    QUARTERROUND(state, 1, 6, 11, 12)
    QUARTERROUND(state, 2, 7, 8, 13)
    QUARTERROUND(state, 3, 4, 9, 14)
  }

  WRITELE(out + 0, state[0]);
  WRITELE(out + 4, state[1]);
  WRITELE(out + 8, state[2]);
  WRITELE(out + 12, state[3]);
  WRITELE(out + 16, state[12]);
  WRITELE(out + 20, state[13]);
  WRITELE(out + 24, state[14]);
  WRITELE(out + 28, state[15]);
}
