#ifndef _BCRYPTO_ED25519_H
#define _BCRYPTO_ED25519_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef unsigned char bcrypto_ed25519_sig_t[64];
typedef unsigned char bcrypto_ed25519_pubkey_t[32];
typedef unsigned char bcrypto_ed25519_privkey_t[32];
typedef unsigned char bcrypto_ed25519_scalar_t[32];
typedef unsigned char bcrypto_x25519_pubkey_t[32];

int
bcrypto_ed25519_pubkey_from_scalar(
  bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t sk
);

int
bcrypto_ed25519_pubkey_create(
  bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_privkey_t sk
);

int
bcrypto_ed25519_verify(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len,
  const bcrypto_ed25519_sig_t RS
);

int
bcrypto_ed25519_verify_single(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len,
  const bcrypto_ed25519_sig_t RS
);

int
bcrypto_ed25519_pubkey_verify(const bcrypto_ed25519_pubkey_t pk);

int
bcrypto_ed25519_pubkey_is_infinity(const bcrypto_ed25519_pubkey_t pk);

int
bcrypto_ed25519_pubkey_is_small(const bcrypto_ed25519_pubkey_t pk);

int
bcrypto_ed25519_pubkey_has_torsion(const bcrypto_ed25519_pubkey_t pk);

int
bcrypto_x25519_pubkey_verify(const bcrypto_x25519_pubkey_t pk);

int
bcrypto_x25519_pubkey_is_small(const bcrypto_x25519_pubkey_t pk);

int
bcrypto_x25519_pubkey_has_torsion(const bcrypto_x25519_pubkey_t pk);

int
bcrypto_ed25519_verify_batch(
  const unsigned char **m,
  size_t *mlen,
  const unsigned char **pk,
  const unsigned char **RS,
  size_t num,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
);

int
bcrypto_ed25519_randombytes(void *out, size_t count);

void
bcrypto_ed25519_privkey_expand(
  unsigned char out[64],
  const bcrypto_ed25519_privkey_t sk
);

void
bcrypto_ed25519_privkey_convert(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_privkey_t sk
);

int
bcrypto_ed25519_pubkey_convert(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk
);

int
bcrypto_x25519_pubkey_convert(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t pk,
  int sign
);

int
bcrypto_ed25519_derive_with_scalar(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t sk
);

int
bcrypto_ed25519_derive(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_privkey_t sk
);

int
bcrypto_x25519_pubkey_create(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_ed25519_scalar_t sk
);

int
bcrypto_x25519_derive(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t xpk,
  const bcrypto_ed25519_scalar_t sk
);

int
bcrypto_ed25519_scalar_is_zero(const bcrypto_ed25519_scalar_t sk);

int
bcrypto_ed25519_scalar_tweak_add(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk,
  const bcrypto_ed25519_scalar_t tweak
);

int
bcrypto_ed25519_scalar_tweak_mul(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk,
  const bcrypto_ed25519_scalar_t tweak
);

void
bcrypto_ed25519_scalar_reduce(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
);

int
bcrypto_ed25519_scalar_negate(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
);

int
bcrypto_ed25519_scalar_invert(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
);

int
bcrypto_ed25519_pubkey_tweak_add(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak
);

int
bcrypto_ed25519_pubkey_tweak_mul(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak
);

int
bcrypto_ed25519_pubkey_add(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk1,
  const bcrypto_ed25519_pubkey_t pk2
);

int
bcrypto_ed25519_pubkey_combine(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t *pks,
  size_t length
);

int
bcrypto_ed25519_pubkey_negate(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk
);

int
bcrypto_ed25519_sign_with_scalar(
  bcrypto_ed25519_sig_t RS,
  const unsigned char *m,
  size_t mlen,
  const unsigned char extsk[64],
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
);

int
bcrypto_ed25519_sign(
  bcrypto_ed25519_sig_t RS,
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_privkey_t sk,
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
);

int
bcrypto_ed25519_sign_tweak_add(
  bcrypto_ed25519_sig_t RS,
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_privkey_t sk,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
);

int
bcrypto_ed25519_sign_tweak_mul(
  bcrypto_ed25519_sig_t RS,
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_privkey_t sk,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
);

void
bcrypto_ed25519_pubkey_from_uniform(
  bcrypto_ed25519_pubkey_t out,
  const unsigned char bytes[32]
);

void
bcrypto_x25519_pubkey_from_uniform(
  bcrypto_x25519_pubkey_t out,
  const unsigned char bytes[32]
);

int
bcrypto_ed25519_pubkey_to_uniform(
  unsigned char out[32],
  const bcrypto_ed25519_pubkey_t pub,
  unsigned int hint
);

int
bcrypto_x25519_pubkey_to_uniform(
  unsigned char out[32],
  const bcrypto_x25519_pubkey_t pub,
  unsigned int hint
);

void
bcrypto_ed25519_pubkey_from_hash(
  bcrypto_ed25519_pubkey_t out,
  const unsigned char bytes[64],
  int pake
);

int
bcrypto_x25519_pubkey_from_hash(
  bcrypto_x25519_pubkey_t out,
  const unsigned char bytes[64],
  int pake
);

int
bcrypto_ed25519_pubkey_to_hash(
  unsigned char out[64],
  const bcrypto_ed25519_pubkey_t pub
);

int
bcrypto_x25519_pubkey_to_hash(
  unsigned char out[64],
  const bcrypto_x25519_pubkey_t pub
);

#if defined(__cplusplus)
}
#endif

#endif // _BCRYPTO_ED25519_H
