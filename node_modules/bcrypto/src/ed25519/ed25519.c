/*
  Public domain by Andrew M. <liquidsun@gmail.com>

  Ed25519 reference implementation using Ed25519-donna
*/

#include <assert.h>
#include "ed25519-donna.h"
#include "ed25519.h"
#include "ed25519-randombytes.h"
#include "ed25519-hash.h"

static const unsigned char ED25519_PREFIX[] =
  "SigEd25519 no Ed25519 collisions";

/*
  Generates a (extsk[0..31]) and aExt (extsk[32..63])
*/

DONNA_INLINE static void
bcrypto_ed25519_extsk(hash_512bits extsk, const bcrypto_ed25519_privkey_t sk) {
  bcrypto_ed25519_hash(extsk, sk, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;
}

static void
bcrypto_ed25519_hprefix(
  bcrypto_ed25519_hash_t *hctx,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
) {
  if (ph != -1) {
    bcrypto_ed25519_hash_update(hctx, ED25519_PREFIX,
                                sizeof(ED25519_PREFIX) - 1);

    unsigned char slab[2] = {
      (unsigned char)ph,
      (unsigned char)ctx_len
    };

    bcrypto_ed25519_hash_update(hctx, &slab[0], 2);
    bcrypto_ed25519_hash_update(hctx, ctx, ctx_len);
  }
}

static void
bcrypto_ed25519_hram(
  hash_512bits hram,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len,
  const bcrypto_ed25519_sig_t RS,
  const bcrypto_ed25519_pubkey_t pk,
  const unsigned char *m,
  size_t mlen
) {
  bcrypto_ed25519_hash_t hctx;
  bcrypto_ed25519_hash_init(&hctx);
  bcrypto_ed25519_hprefix(&hctx, ph, ctx, ctx_len);
  bcrypto_ed25519_hash_update(&hctx, RS, 32);
  bcrypto_ed25519_hash_update(&hctx, pk, 32);
  bcrypto_ed25519_hash_update(&hctx, m, mlen);
  bcrypto_ed25519_hash_final(&hctx, hram);
}

#include "ed25519-donna-batchverify.h"

int
bcrypto_ed25519_pubkey_from_scalar(
  bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm a;
  ge25519 ALIGN(16) A;

  /* A = aB */
  expand256_modm(a, sk, 32);
  ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);

  ge25519_pack(pk, &A);

  return 1;
}

int
bcrypto_ed25519_pubkey_create(
  bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_privkey_t sk
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  return bcrypto_ed25519_pubkey_from_scalar(pk, extsk);
}

int
bcrypto_ed25519_verify(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len,
  const bcrypto_ed25519_sig_t RS
) {
  ge25519 ALIGN(16) R, A;
  hash_512bits hash;
  bignum256modm hram, S;
  unsigned char checkR[32];

  if (!is_canonical256_modm(RS + 32)
      || !ge25519_is_canonical(RS)
      || !ge25519_unpack_vartime(&A, pk)) {
    return 0;
  }

  /* hram = H(R,A,m) */
  bcrypto_ed25519_hram(hash, ph, ctx, ctx_len, RS, pk, m, mlen);
  expand256_modm(hram, hash, 64);

  /* S */
  expand256_modm(S, RS + 32, 32);

  /* SB - H(R,A,m)A */
  ge25519_neg(&A, &A);
  ge25519_double_scalarmult_vartime(&R, &A, hram, S);
  ge25519_pack(checkR, &R);

  /* check that R = SB - H(R,A,m)A */
  return bcrypto_ed25519_equal(RS, checkR, 32);
}

int
bcrypto_ed25519_verify_single(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len,
  const bcrypto_ed25519_sig_t RS
) {
  ge25519 ALIGN(16) R, A;
  hash_512bits hash;
  bignum256modm hram, S;
  unsigned char expectR[32];
  unsigned char checkR[32];

  if (!is_canonical256_modm(RS + 32)
      || !ge25519_unpack_vartime(&R, RS)
      || !ge25519_unpack_vartime(&A, pk)) {
    return 0;
  }

  ge25519_mulh(&R, &R);
  ge25519_pack(expectR, &R);

  /* hram = H(R,A,m) */
  bcrypto_ed25519_hram(hash, ph, ctx, ctx_len, RS, pk, m, mlen);
  expand256_modm(hram, hash, 64);

  /* Sh */
  expand256_modm(S, RS + 32, 32);
  mulh256_modm(S, S);

  /* ShB - H(R,A,m)Ah */
  ge25519_mulh(&A, &A);
  ge25519_neg(&A, &A);
  ge25519_double_scalarmult_vartime(&R, &A, hram, S);
  ge25519_pack(checkR, &R);

  /* check that Rh = ShB - H(R,A,m)Ah */
  return bcrypto_ed25519_equal(expectR, checkR, 32);
}

int
bcrypto_ed25519_pubkey_verify(const bcrypto_ed25519_pubkey_t pk) {
  ge25519 ALIGN(16) A;
  return ge25519_unpack(&A, pk);
}

int
bcrypto_ed25519_pubkey_is_infinity(const bcrypto_ed25519_pubkey_t pk) {
  return ge25519_is_one(pk);
}

int
bcrypto_ed25519_pubkey_is_small(const bcrypto_ed25519_pubkey_t pk) {
  ge25519 ALIGN(16) A;

  if (!ge25519_unpack(&A, pk))
    return 0;

  return ge25519_is_small(&A);
}

int
bcrypto_ed25519_pubkey_has_torsion(const bcrypto_ed25519_pubkey_t pk) {
  ge25519 ALIGN(16) A;

  if (!ge25519_unpack(&A, pk))
    return 0;

  return ge25519_has_torsion(&A);
}

int
bcrypto_x25519_pubkey_verify(const bcrypto_x25519_pubkey_t pk) {
  bignum25519 ALIGN(16) x;
  curve25519_expand(x, pk);
  return curve25519_valid_x(x);
}

int
bcrypto_x25519_pubkey_is_small(const bcrypto_x25519_pubkey_t pk) {
  bignum25519 ALIGN(16) x, z;

  curve25519_expand(x, pk);
  curve25519_set_word(z, 1);

  if (!curve25519_valid_x(x))
    return 0;

  curve25519_double(x, z, x, z);
  curve25519_double(x, z, x, z);
  curve25519_double(x, z, x, z);

  return curve25519_is_zero(z);
}

int
bcrypto_x25519_pubkey_has_torsion(const bcrypto_x25519_pubkey_t pk) {
  static const unsigned char k[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
  };

  bignum25519 ALIGN(16) x, z;
  int zero;

  curve25519_expand(x, pk);

  if (!curve25519_valid_x(x))
    return 0;

  zero = curve25519_is_zero(x);

  curve25519_ladder(x, z, x, k);

  return (curve25519_is_zero(z) ^ 1) | zero;
}

void
bcrypto_ed25519_privkey_expand(
  unsigned char out[64],
  const bcrypto_ed25519_privkey_t sk
) {
  bcrypto_ed25519_extsk(out, sk);
}

void
bcrypto_ed25519_privkey_convert(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_privkey_t sk
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  memcpy(out, extsk, 32);
}

int
bcrypto_ed25519_pubkey_convert(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk
) {
  ge25519 ALIGN(16) p;
  bignum25519 ALIGN(16) u, z;
  int ret = 1;

  ret &= ge25519_unpack(&p, pk);
  ret &= ge25519_is_neutral(&p) ^ 1;

  /* u = (1 + y) / (1 - y) */
  curve25519_add_reduce(u, p.z, p.y);
  curve25519_sub_reduce(z, p.z, p.y);
  curve25519_recip(z, z);
  curve25519_mul(u, u, z);

  curve25519_contract(out, u);

  return ret;
}

int
bcrypto_x25519_pubkey_convert(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t pk,
  int sign
) {
  static const bignum25519 one = {1};
  bignum25519 ALIGN(16) u, y, z;
  int ret = 1;

  curve25519_expand(u, pk);

  ret &= curve25519_valid_x(u);

  /* y = (u - 1) / (u + 1) */
  curve25519_sub_reduce(y, u, one);
  curve25519_add_reduce(z, u, one);
  curve25519_recip(z, z);
  curve25519_mul(y, y, z);

  curve25519_contract(out, y);

  sign &= curve25519_is_zero(u) ^ 1;

  out[31] |= sign << 7;

  return ret;
}

int
bcrypto_ed25519_derive_with_scalar(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;
  ge25519 ALIGN(16) r, p;
  bcrypto_ed25519_scalar_t ec;
  size_t i;

  /* clamp */
  for (i = 0; i < 32; i++)
    ec[i] = sk[i];

  ec[0] &= 248;
  ec[31] &= 127;
  ec[31] |= 64;

  expand_raw256_modm(k, ec);

  if (!ge25519_unpack(&p, pk))
    return 0;

  ge25519_scalarmult(&r, &p, k);
  ge25519_pack(out, &r);

  return ge25519_is_one(out) ^ 1;
}

int
bcrypto_ed25519_derive(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_privkey_t sk
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  return bcrypto_ed25519_derive_with_scalar(out, pk, extsk);
}

int
bcrypto_x25519_pubkey_create(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_ed25519_scalar_t sk
) {
  bcrypto_ed25519_scalar_t k;
  bignum256modm a;
  ge25519 ALIGN(16) A;
  bignum25519 ALIGN(16) x, z;
  size_t i;

  for (i = 0; i < 32; i++)
    k[i] = sk[i];

  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;

  expand256_modm(a, k, 32);
  ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);

  curve25519_add_reduce(x, A.z, A.y);
  curve25519_sub_reduce(z, A.z, A.y);

  if (curve25519_is_zero(z))
    return 0;

  curve25519_recip(z, z);
  curve25519_mul(x, x, z);
  curve25519_contract(out, x);

  return 1;
}

int
bcrypto_x25519_derive(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t xpk,
  const bcrypto_ed25519_scalar_t sk
) {
  bcrypto_ed25519_scalar_t k;
  bignum25519 ALIGN(16) x, z;
  static const unsigned char zero[32] = {0};
  size_t i;

  for (i = 0; i < 32; i++)
    k[i] = sk[i];

  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;

  curve25519_expand(x, xpk);
  curve25519_ladder(x, z, x, k);
  curve25519_recip(z, z);
  curve25519_mul(x, x, z);
  curve25519_contract(out, x);

  return bcrypto_ed25519_equal(out, zero, 32) ^ 1;
}

int
bcrypto_ed25519_scalar_is_zero(const bcrypto_ed25519_scalar_t sk) {
  bignum256modm k;
  expand256_modm(k, sk, 32);
  return iszero256_modm_batch(k);
}

int
bcrypto_ed25519_scalar_tweak_add(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk,
  const bcrypto_ed25519_scalar_t tweak
) {
  bignum256modm k, t;

  expand256_modm(k, sk, 32);
  expand256_modm(t, tweak, 32);

  add256_modm(k, k, t);

  contract256_modm(out, k);

  return 1;
}

int
bcrypto_ed25519_scalar_tweak_mul(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk,
  const bcrypto_ed25519_scalar_t tweak
) {
  bignum256modm k, t;

  expand256_modm(k, sk, 32);
  expand256_modm(t, tweak, 32);

  mul256_modm(k, k, t);

  contract256_modm(out, k);

  return 1;
}

void
bcrypto_ed25519_scalar_reduce(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;
  expand256_modm(k, sk, 32);
  contract256_modm(out, k);
}

int
bcrypto_ed25519_scalar_negate(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;

  expand256_modm(k, sk, 32);
  negate256_modm(k, k);

  contract256_modm(out, k);

  return 1;
}

int
bcrypto_ed25519_scalar_invert(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;

  expand256_modm(k, sk, 32);
  recip256_modm(k, k);

  contract256_modm(out, k);

  return 1;
}

int
bcrypto_ed25519_pubkey_tweak_add(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak
) {
  ge25519 ALIGN(16) T, k;
  bignum256modm t;

  if (!ge25519_unpack(&k, pk))
    return 0;

  expand256_modm(t, tweak, 32);

  ge25519_scalarmult_base_niels(&T, ge25519_niels_base_multiples, t);

  ge25519_add(&k, &k, &T);
  ge25519_pack(out, &k);

  return 1;
}

int
bcrypto_ed25519_pubkey_tweak_mul(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak
) {
  ge25519 ALIGN(16) T, k;
  bignum256modm t;

  if (!ge25519_unpack(&k, pk))
    return 0;

  expand_raw256_modm(t, tweak);

  ge25519_scalarmult(&T, &k, t);
  ge25519_pack(out, &T);

  return 1;
}

int
bcrypto_ed25519_pubkey_add(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk1,
  const bcrypto_ed25519_pubkey_t pk2
) {
  ge25519 ALIGN(16) k1, k2;

  if (!ge25519_unpack(&k1, pk1))
    return 0;

  if (!ge25519_unpack(&k2, pk2))
    return 0;

  ge25519_add(&k1, &k1, &k2);
  ge25519_pack(out, &k1);

  return 1;
}

int
bcrypto_ed25519_pubkey_combine(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t *pks,
  size_t length
) {
  ge25519 ALIGN(16) k1, k2;
  size_t i;

  ge25519_set_neutral(&k1);

  for (i = 0; i < length; i++) {
    if (!ge25519_unpack(&k2, pks[i]))
      return 0;

    ge25519_add(&k1, &k1, &k2);
  }

  ge25519_pack(out, &k1);

  return 1;
}

int
bcrypto_ed25519_pubkey_negate(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk
) {
  ge25519 ALIGN(16) k;

  if (!ge25519_unpack(&k, pk))
    return 0;

  ge25519_neg(&k, &k);
  ge25519_pack(out, &k);

  return 1;
}

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
) {
  bcrypto_ed25519_hash_t hctx;
  bignum256modm r, S, a;
  ge25519 ALIGN(16) R;
  hash_512bits hashr, hram;

  /* r = H(aExt[32..64], m) */
  bcrypto_ed25519_hash_init(&hctx);
  bcrypto_ed25519_hprefix(&hctx, ph, ctx, ctx_len);
  bcrypto_ed25519_hash_update(&hctx, extsk + 32, 32);
  bcrypto_ed25519_hash_update(&hctx, m, mlen);
  bcrypto_ed25519_hash_final(&hctx, hashr);
  expand256_modm(r, hashr, 64);

  /* R = rB */
  ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
  ge25519_pack(RS, &R);

  /* S = H(R,A,m).. */
  bcrypto_ed25519_hram(hram, ph, ctx, ctx_len, RS, pk, m, mlen);
  expand256_modm(S, hram, 64);

  /* S = H(R,A,m)a */
  expand256_modm(a, extsk, 32);
  mul256_modm(S, S, a);

  /* S = (r + H(R,A,m)a) */
  add256_modm(S, S, r);

  /* S = (r + H(R,A,m)a) mod L */
  contract256_modm(RS + 32, S);

  return 1;
}

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
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  return bcrypto_ed25519_sign_with_scalar(RS, m, mlen, extsk, pk, ph, ctx, ctx_len);
}

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
) {
  hash_512bits extsk, prefix;
  bcrypto_ed25519_pubkey_t tk;
  bcrypto_ed25519_hash_t hctx;

  bcrypto_ed25519_extsk(extsk, sk);

  if (!bcrypto_ed25519_scalar_tweak_add(extsk, extsk, tweak))
    return 0;

  bcrypto_ed25519_hash_init(&hctx);
  bcrypto_ed25519_hash_update(&hctx, extsk + 32, 32);
  bcrypto_ed25519_hash_update(&hctx, tweak, 32);
  bcrypto_ed25519_hash_final(&hctx, prefix);
  memcpy(extsk + 32, prefix, 32);

  if (!bcrypto_ed25519_pubkey_tweak_add(tk, pk, tweak))
    return 0;

  return bcrypto_ed25519_sign_with_scalar(RS, m, mlen, extsk, tk, ph, ctx, ctx_len);
}

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
) {
  hash_512bits extsk, prefix;
  bcrypto_ed25519_pubkey_t tk;
  bcrypto_ed25519_hash_t hctx;

  bcrypto_ed25519_extsk(extsk, sk);

  if (!bcrypto_ed25519_scalar_tweak_mul(extsk, extsk, tweak))
    return 0;

  bcrypto_ed25519_hash_init(&hctx);
  bcrypto_ed25519_hash_update(&hctx, extsk + 32, 32);
  bcrypto_ed25519_hash_update(&hctx, tweak, 32);
  bcrypto_ed25519_hash_final(&hctx, prefix);
  memcpy(extsk + 32, prefix, 32);

  if (!bcrypto_ed25519_pubkey_tweak_mul(tk, pk, tweak))
    return 0;

  return bcrypto_ed25519_sign_with_scalar(RS, m, mlen, extsk, tk, ph, ctx, ctx_len);
}

void
bcrypto_ed25519_pubkey_from_uniform(
  bcrypto_ed25519_pubkey_t out,
  const unsigned char bytes[32]
) {
  ge25519 ALIGN(16) p;
  ge25519_elligator2(&p, bytes);
  ge25519_pack(out, &p);
}

void
bcrypto_x25519_pubkey_from_uniform(
  bcrypto_x25519_pubkey_t out,
  const unsigned char bytes[32]
) {
  bignum25519 ALIGN(16) x, y;
  curve25519_elligator2(x, y, bytes);
  curve25519_contract(out, x);
}

int
bcrypto_ed25519_pubkey_to_uniform(
  unsigned char out[32],
  const bcrypto_ed25519_pubkey_t pub,
  unsigned int hint
) {
  ge25519 ALIGN(16) p;
  int ret = 1;

  ret &= ge25519_unpack(&p, pub);
  ret &= ge25519_invert2(out, &p, hint);

  return ret;
}

int
bcrypto_x25519_pubkey_to_uniform(
  unsigned char out[32],
  const bcrypto_x25519_pubkey_t pub,
  unsigned int hint
) {
  bignum25519 ALIGN(16) x, y;
  int ret = 1;

  ret &= curve25519_unpack(x, y, pub);
  ret &= curve25519_invert2(out, x, y, hint);

  return ret;
}

void
bcrypto_ed25519_pubkey_from_hash(
  bcrypto_ed25519_pubkey_t out,
  const unsigned char bytes[64],
  int pake
) {
  ge25519 ALIGN(16) p;
  ge25519_from_hash(&p, bytes, pake);
  ge25519_pack(out, &p);
}

int
bcrypto_x25519_pubkey_from_hash(
  bcrypto_x25519_pubkey_t out,
  const unsigned char bytes[64],
  int pake
) {
  bignum25519 ALIGN(16) u, z;
  ge25519 ALIGN(16) p;
  int ret = 1;

  ge25519_from_hash(&p, bytes, pake);

  ret &= ge25519_is_neutral(&p) ^ 1;

  curve25519_add_reduce(u, p.z, p.y);
  curve25519_sub_reduce(z, p.z, p.y);
  curve25519_recip(z, z);
  curve25519_mul(u, u, z);
  curve25519_contract(out, u);

  return ret;
}

int
bcrypto_ed25519_pubkey_to_hash(
  unsigned char out[64],
  const bcrypto_ed25519_pubkey_t pub
) {
  ge25519 ALIGN(16) p;

  if (!ge25519_unpack(&p, pub))
    return 0;

  return ge25519_to_hash(out, &p);
}

int
bcrypto_x25519_pubkey_to_hash(
  unsigned char out[64],
  const bcrypto_x25519_pubkey_t pub
) {
  ge25519 ALIGN(16) p;
  bignum25519 ALIGN(16) x, y;

  if (!curve25519_unpack(x, y, pub))
    return 0;

  ge25519_from_mont(&p, x, y);

  return ge25519_to_hash(out, &p);
}
