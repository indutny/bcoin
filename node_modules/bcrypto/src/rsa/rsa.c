#include "../compat.h"

#ifdef BCRYPTO_HAS_RSA

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdlib.h>
#include "rsa.h"

#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/objects.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "../random/random.h"

#define BCRYPTO_RSA_DEFAULT_BITS 2048
#define BCRYPTO_RSA_DEFAULT_EXP 65537
#define BCRYPTO_RSA_MIN_BITS 512
#define BCRYPTO_RSA_MAX_BITS 16384
#define BCRYPTO_RSA_MIN_EXP 3ull
#define BCRYPTO_RSA_MAX_EXP 0x1ffffffffull
#define BCRYPTO_RSA_MIN_EXP_BITS 2
#define BCRYPTO_RSA_MAX_EXP_BITS 33

void
bcrypto_rsa_key_init(bcrypto_rsa_key_t *key) {
  assert(key != NULL);
  memset((void *)key, 0x00, sizeof(bcrypto_rsa_key_t));
}

void
bcrypto_rsa_key_free(bcrypto_rsa_key_t *key) {
  assert(key != NULL);

  if (key->slab != NULL)
    free(key->slab);

  free(key);
}

static size_t
bcrypto_count_bits(const uint8_t *in, size_t in_len) {
  if (in == NULL)
    return 0;

  size_t i = 0;

  for (; i < in_len; i++) {
    if (in[i] != 0)
      break;
  }

  size_t bits = (in_len - i) * 8;

  if (bits == 0)
    return 0;

  bits -= 8;

  uint32_t oct = in[i];

  while (oct) {
    bits += 1;
    oct >>= 1;
  }

  return bits;
}

static int
bcrypto_rsa_sane_pubkey(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return 0;

  size_t nb = bcrypto_count_bits(key->nd, key->nl);

  if (nb < BCRYPTO_RSA_MIN_BITS || nb > BCRYPTO_RSA_MAX_BITS)
    return 0;

  size_t eb = bcrypto_count_bits(key->ed, key->el);

  if (eb < BCRYPTO_RSA_MIN_EXP_BITS || eb > BCRYPTO_RSA_MAX_EXP_BITS)
    return 0;

  if ((key->ed[key->el - 1] & 1) == 0)
    return 0;

  return 1;
}

static int
bcrypto_rsa_sane_privkey(const bcrypto_rsa_key_t *key) {
  if (!bcrypto_rsa_sane_pubkey(key))
    return 0;

  size_t nb = bcrypto_count_bits(key->nd, key->nl);
  size_t pb = bcrypto_count_bits(key->pd, key->pl);
  size_t qb = bcrypto_count_bits(key->qd, key->ql);

  if (nb > pb + qb)
    return 0;

  size_t db = bcrypto_count_bits(key->dd, key->dl);

  if (db == 0 || db > nb)
    return 0;

  size_t dpb = bcrypto_count_bits(key->dpd, key->dpl);

  if (dpb == 0 || dpb > pb)
    return 0;

  size_t dqb = bcrypto_count_bits(key->dqd, key->dql);

  if (dqb == 0 || dqb > qb)
    return 0;

  size_t qib = bcrypto_count_bits(key->qid, key->qil);

  if (qib == 0 || qib > pb)
    return 0;

  return 1;
}

static int
bcrypto_rsa_sane_compute(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return 0;

  size_t nb = bcrypto_count_bits(key->nd, key->nl);
  size_t eb = bcrypto_count_bits(key->ed, key->el);
  size_t db = bcrypto_count_bits(key->dd, key->dl);
  size_t pb = bcrypto_count_bits(key->pd, key->pl);
  size_t qb = bcrypto_count_bits(key->qd, key->ql);
  size_t dpb = bcrypto_count_bits(key->dpd, key->dpl);
  size_t dqb = bcrypto_count_bits(key->dqd, key->dql);
  size_t qib = bcrypto_count_bits(key->qid, key->qil);

  if (pb == 0 || qb == 0)
    return 0;

  if (eb == 0 && db == 0)
    return 0;

  if (nb != 0) {
    if (nb < BCRYPTO_RSA_MIN_BITS || nb > BCRYPTO_RSA_MAX_BITS)
      return 0;

    if (nb > pb + qb)
      return 0;
  }

  if (eb != 0) {
    if (eb < BCRYPTO_RSA_MIN_EXP_BITS || eb > BCRYPTO_RSA_MAX_EXP_BITS)
      return 0;

    if ((key->ed[key->el - 1] & 1) == 0)
      return 0;
  }

  if (db != 0) {
    if (db > pb + qb)
      return 0;
  }

  if (dpb != 0) {
    if (dpb > pb)
      return 0;
  }

  if (dqb != 0) {
    if (dqb > qb)
      return 0;
  }

  if (qib != 0) {
    if (qib > pb)
      return 0;
  }

  return 1;
}

static int
bcrypto_rsa_needs_compute(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return 0;

  return bcrypto_count_bits(key->nd, key->nl) == 0
      || bcrypto_count_bits(key->ed, key->el) == 0
      || bcrypto_count_bits(key->dd, key->dl) == 0
      || bcrypto_count_bits(key->dpd, key->dpl) == 0
      || bcrypto_count_bits(key->dqd, key->dql) == 0
      || bcrypto_count_bits(key->qid, key->qil) == 0;
}

static RSA *
bcrypto_rsa_key2priv(const bcrypto_rsa_key_t *priv) {
  RSA *rsakey = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;
  BIGNUM *d = NULL;
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *dp = NULL;
  BIGNUM *dq = NULL;
  BIGNUM *qi = NULL;

  if (priv == NULL)
    return NULL;

  rsakey = RSA_new();

  if (rsakey == NULL)
    goto fail;

  n = BN_bin2bn(priv->nd, priv->nl, NULL);
  e = BN_bin2bn(priv->ed, priv->el, NULL);
  d = BN_bin2bn(priv->dd, priv->dl, BN_secure_new());
  p = BN_bin2bn(priv->pd, priv->pl, BN_secure_new());
  q = BN_bin2bn(priv->qd, priv->ql, BN_secure_new());
  dp = BN_bin2bn(priv->dpd, priv->dpl, BN_secure_new());
  dq = BN_bin2bn(priv->dqd, priv->dql, BN_secure_new());
  qi = BN_bin2bn(priv->qid, priv->qil, BN_secure_new());

  if (n == NULL
      || e == NULL
      || d == NULL
      || p == NULL
      || q == NULL
      || dp == NULL
      || dq == NULL
      || qi == NULL) {
    goto fail;
  }

  if (!RSA_set0_key(rsakey, n, e, d))
    goto fail;

  n = NULL;
  e = NULL;
  d = NULL;

  if (!RSA_set0_factors(rsakey, p, q))
    goto fail;

  p = NULL;
  q = NULL;

  if (!RSA_set0_crt_params(rsakey, dp, dq, qi))
    goto fail;

  return rsakey;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (n != NULL)
    BN_free(n);

  if (e != NULL)
    BN_free(e);

  if (d != NULL)
    BN_clear_free(d);

  if (p != NULL)
    BN_clear_free(p);

  if (q != NULL)
    BN_clear_free(q);

  if (dp != NULL)
    BN_clear_free(dp);

  if (dq != NULL)
    BN_clear_free(dq);

  if (qi != NULL)
    BN_clear_free(qi);

  return NULL;
}

static RSA *
bcrypto_rsa_key2pub(const bcrypto_rsa_key_t *pub) {
  RSA *rsakey = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;

  if (pub == NULL)
    return NULL;

  rsakey = RSA_new();

  if (rsakey == NULL)
    goto fail;

  n = BN_bin2bn(pub->nd, pub->nl, NULL);
  e = BN_bin2bn(pub->ed, pub->el, NULL);

  if (n == NULL || e == NULL)
    goto fail;

  if (!RSA_set0_key(rsakey, n, e, NULL))
    goto fail;

  return rsakey;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (n != NULL)
    BN_free(n);

  if (e != NULL)
    BN_free(e);

  return NULL;
}

static bcrypto_rsa_key_t *
bcrypto_rsa_priv2key(const RSA *rsakey) {
  bcrypto_rsa_key_t *priv = NULL;
  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *dp = NULL;
  const BIGNUM *dq = NULL;
  const BIGNUM *qi = NULL;
  uint8_t *slab = NULL;

  if (rsakey == NULL)
    return NULL;

  priv = (bcrypto_rsa_key_t *)malloc(sizeof(bcrypto_rsa_key_t));

  if (priv == NULL)
    goto fail;

  bcrypto_rsa_key_init(priv);

  RSA_get0_key(rsakey, &n, &e, &d);
  RSA_get0_factors(rsakey, &p, &q);
  RSA_get0_crt_params(rsakey, &dp, &dq, &qi);

  if (n == NULL
      || e == NULL
      || d == NULL
      || p == NULL
      || q == NULL
      || dp == NULL
      || dq == NULL
      || qi == NULL) {
    goto fail;
  }

  size_t nl = BN_num_bytes(n);
  size_t el = BN_num_bytes(e);
  size_t dl = BN_num_bytes(d);
  size_t pl = BN_num_bytes(p);
  size_t ql = BN_num_bytes(q);
  size_t dpl = BN_num_bytes(dp);
  size_t dql = BN_num_bytes(dq);
  size_t qil = BN_num_bytes(qi);
  size_t size = nl + el + dl + pl + ql + dpl + dql + qil;
  size_t pos = 0;

  /* Align. */
  size += 8 - (size & 7);

  slab = (uint8_t *)malloc(size);

  if (slab == NULL)
    goto fail;

  priv->slab = slab;

  priv->nd = (uint8_t *)&slab[pos];
  priv->nl = nl;
  pos += nl;

  priv->ed = (uint8_t *)&slab[pos];
  priv->el = el;
  pos += el;

  priv->dd = (uint8_t *)&slab[pos];
  priv->dl = dl;
  pos += dl;

  priv->pd = (uint8_t *)&slab[pos];
  priv->pl = pl;
  pos += pl;

  priv->qd = (uint8_t *)&slab[pos];
  priv->ql = ql;
  pos += ql;

  priv->dpd = (uint8_t *)&slab[pos];
  priv->dpl = dpl;
  pos += dpl;

  priv->dqd = (uint8_t *)&slab[pos];
  priv->dql = dql;
  pos += dql;

  priv->qid = (uint8_t *)&slab[pos];
  priv->qil = qil;
  pos += qil;

  assert(BN_bn2bin(n, priv->nd) != -1);
  assert(BN_bn2bin(e, priv->ed) != -1);
  assert(BN_bn2bin(d, priv->dd) != -1);
  assert(BN_bn2bin(p, priv->pd) != -1);
  assert(BN_bn2bin(q, priv->qd) != -1);
  assert(BN_bn2bin(dp, priv->dpd) != -1);
  assert(BN_bn2bin(dq, priv->dqd) != -1);
  assert(BN_bn2bin(qi, priv->qid) != -1);

  return priv;

fail:
  if (priv != NULL)
    bcrypto_rsa_key_free(priv);

  return NULL;
}

static bcrypto_rsa_key_t *
bcrypto_rsa_pub2key(const RSA *rsakey) {
  bcrypto_rsa_key_t *pub = NULL;
  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  uint8_t *slab = NULL;

  if (rsakey == NULL)
    return NULL;

  pub = (bcrypto_rsa_key_t *)malloc(sizeof(bcrypto_rsa_key_t));

  if (pub == NULL)
    goto fail;

  bcrypto_rsa_key_init(pub);

  RSA_get0_key(rsakey, &n, &e, NULL);

  if (n == NULL || e == NULL)
    goto fail;

  size_t nl = BN_num_bytes(n);
  size_t el = BN_num_bytes(e);
  size_t size = nl + el;
  size_t pos = 0;

  /* Align. */
  size += 8 - (size & 7);

  slab = (uint8_t *)malloc(size);

  if (slab == NULL)
    goto fail;

  pub->slab = slab;

  pub->nd = (uint8_t *)&slab[pos];
  pub->nl = nl;
  pos += nl;

  pub->ed = (uint8_t *)&slab[pos];
  pub->el = el;
  pos += el;

  assert(BN_bn2bin(n, pub->nd) != -1);
  assert(BN_bn2bin(e, pub->ed) != -1);

  return pub;

fail:
  if (pub != NULL)
    bcrypto_rsa_key_free(pub);

  return NULL;
}

static int
bcrypto_rsa_hash_type(const char *alg) {
  if (alg == NULL)
    return -1;

  int type = -1;

  if (0)
    type = -1;

#ifdef NID_blake2b160
  else if (strcmp(alg, "BLAKE2B160") == 0)
    type = NID_blake2b160;
#endif

#ifdef NID_blake2b256
  else if (strcmp(alg, "BLAKE2B256") == 0)
    type = NID_blake2b256;
#endif

#ifdef NID_blake2b384
  else if (strcmp(alg, "BLAKE2B384") == 0)
    type = NID_blake2b384;
#endif

#ifdef NID_blake2b512
  else if (strcmp(alg, "BLAKE2B512") == 0)
    type = NID_blake2b512;
#endif

#ifdef NID_blake2s128
  else if (strcmp(alg, "BLAKE2S128") == 0)
    type = NID_blake2s128;
#endif

#ifdef NID_blake2s160
  else if (strcmp(alg, "BLAKE2S160") == 0)
    type = NID_blake2s160;
#endif

#ifdef NID_blake2s224
  else if (strcmp(alg, "BLAKE2S224") == 0)
    type = NID_blake2s224;
#endif

#ifdef NID_blake2s256
  else if (strcmp(alg, "BLAKE2S256") == 0)
    type = NID_blake2s256;
#endif

#ifdef NID_md2
  else if (strcmp(alg, "MD2") == 0)
    type = NID_md2;
#endif

  else if (strcmp(alg, "MD4") == 0)
    type = NID_md4;
  else if (strcmp(alg, "MD5") == 0)
    type = NID_md5;

#ifdef NID_md5_sha1
  else if (strcmp(alg, "MD5SHA1") == 0)
    type = NID_md5_sha1;
#endif

  else if (strcmp(alg, "RIPEMD160") == 0)
    type = NID_ripemd160;
  else if (strcmp(alg, "SHA1") == 0)
    type = NID_sha1;
  else if (strcmp(alg, "SHA224") == 0)
    type = NID_sha224;
  else if (strcmp(alg, "SHA256") == 0)
    type = NID_sha256;
  else if (strcmp(alg, "SHA384") == 0)
    type = NID_sha384;
  else if (strcmp(alg, "SHA512") == 0)
    type = NID_sha512;

#ifdef NID_sha3_224
  else if (strcmp(alg, "SHA3_224") == 0)
    type = NID_sha3_224;
#endif

#ifdef NID_sha3_256
  else if (strcmp(alg, "SHA3_256") == 0)
    type = NID_sha3_256;
#endif

#ifdef NID_sha3_384
  else if (strcmp(alg, "SHA3_384") == 0)
    type = NID_sha3_384;
#endif

#ifdef NID_sha3_512
  else if (strcmp(alg, "SHA3_512") == 0)
    type = NID_sha3_512;
#endif

#ifdef NID_shake128
  else if (strcmp(alg, "SHAKE128") == 0)
    type = NID_shake128;
#endif

#ifdef NID_shake256
  else if (strcmp(alg, "SHAKE256") == 0)
    type = NID_shake256;
#endif

#ifdef NID_whirlpool
  else if (strcmp(alg, "WHIRLPOOL") == 0)
    type = NID_whirlpool;
#endif

  return type;
}

static size_t
bcrypto_rsa_hash_size(int type) {
  switch (type) {
#ifdef NID_blake2b160
    case NID_blake2b160:
      return 20;
#endif

#ifdef NID_blake2b256
    case NID_blake2b256:
      return 32;
#endif

#ifdef NID_blake2b384
    case NID_blake2b384:
      return 48;
#endif

#ifdef NID_blake2b512
    case NID_blake2b512:
      return 64;
#endif

#ifdef NID_blake2s128
    case NID_blake2s128:
      return 16;
#endif

#ifdef NID_blake2s160
    case NID_blake2s160:
      return 20;
#endif

#ifdef NID_blake2s224
    case NID_blake2s224:
      return 28;
#endif

#ifdef NID_blake2s256
    case NID_blake2s256:
      return 32;
#endif

#ifdef NID_md2
    case NID_md2:
      return 16;
#endif

    case NID_md4:
      return 16;
    case NID_md5:
      return 16;

#ifdef NID_md5_sha1
    case NID_md5_sha1:
      return 36;
#endif

    case NID_ripemd160:
      return 20;
    case NID_sha1:
      return 20;
    case NID_sha224:
      return 28;
    case NID_sha256:
      return 32;
    case NID_sha384:
      return 48;
    case NID_sha512:
      return 64;

#ifdef NID_sha3_224
    case NID_sha3_224:
      return 28;
#endif

#ifdef NID_sha3_256
    case NID_sha3_256:
      return 32;
#endif

#ifdef NID_sha3_384
    case NID_sha3_384:
      return 48;
#endif

#ifdef NID_sha3_512
    case NID_sha3_512:
      return 64;
#endif

#ifdef NID_shake128
    case NID_shake128:
      return 16;
#endif

#ifdef NID_shake256
    case NID_shake256:
      return 32;
#endif

#ifdef NID_whirlpool
    case NID_whirlpool:
      return 64;
#endif

    default:
      return 0;
  }
}

static size_t
bcrypto_rsa_mod_size(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return 0;

  return (bcrypto_count_bits(key->nd, key->nl) + 7) / 8;
}

static size_t
bcrypto_rsa_mod_bits(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return 0;

  return bcrypto_count_bits(key->nd, key->nl);
}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_generate(int bits, unsigned long long exponent) {
  RSA *rsakey = NULL;
  BIGNUM *e = NULL;
  bcrypto_rsa_key_t *priv = NULL;

  if (bits < BCRYPTO_RSA_MIN_BITS || bits > BCRYPTO_RSA_MAX_BITS)
    goto fail;

  if (exponent < BCRYPTO_RSA_MIN_EXP || exponent > BCRYPTO_RSA_MAX_EXP)
    goto fail;

  if ((exponent & 1ull) == 0ull)
    goto fail;

  rsakey = RSA_new();

  if (rsakey == NULL)
    goto fail;

  e = BN_new();

  if (e == NULL)
    goto fail;

  if (!BN_set_word(e, (BN_ULONG)exponent))
    goto fail;

  bcrypto_poll();

  if (!RSA_generate_key_ex(rsakey, bits, e, NULL))
    goto fail;

  priv = bcrypto_rsa_priv2key(rsakey);

  if (priv == NULL)
    goto fail;

  RSA_free(rsakey);
  BN_free(e);

  return priv;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (e != NULL)
    BN_free(e);

  return NULL;
}

int
bcrypto_rsa_privkey_compute(bcrypto_rsa_key_t **out,
                            const bcrypto_rsa_key_t *priv) {
  RSA *rsakey = NULL;
  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *dp = NULL;
  const BIGNUM *dq = NULL;
  const BIGNUM *qi = NULL;
  BIGNUM *rsa_n = NULL;
  BIGNUM *rsa_e = NULL;
  BIGNUM *rsa_d = NULL;
  BIGNUM *rsa_p = NULL;
  BIGNUM *rsa_q = NULL;
  BIGNUM *rsa_dmp1 = NULL;
  BIGNUM *rsa_dmq1 = NULL;
  BIGNUM *rsa_iqmp = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *r0 = NULL;
  BIGNUM *r1 = NULL;
  BIGNUM *r2 = NULL;
  RSA *rsa_out = NULL;
  bcrypto_rsa_key_t *key = NULL;

  if (!bcrypto_rsa_sane_compute(priv))
    goto fail;

  if (!bcrypto_rsa_needs_compute(priv)) {
    *out = NULL;
    return 1;
  }

  rsakey = bcrypto_rsa_key2priv(priv);

  if (rsakey == NULL)
    goto fail;

  RSA_get0_key(rsakey, &n, &e, &d);
  RSA_get0_factors(rsakey, &p, &q);
  RSA_get0_crt_params(rsakey, &dp, &dq, &qi);

  assert(n != NULL && e != NULL && d != NULL);
  assert(p != NULL && q != NULL);
  assert(dp != NULL && dq != NULL && qi != NULL);

  rsa_n = BN_new();
  rsa_e = BN_new();
  rsa_d = BN_secure_new();
  rsa_p = BN_secure_new();
  rsa_q = BN_secure_new();
  rsa_dmp1 = BN_secure_new();
  rsa_dmq1 = BN_secure_new();
  rsa_iqmp = BN_secure_new();

  if (rsa_n == NULL
      || rsa_e == NULL
      || rsa_d == NULL
      || rsa_p == NULL
      || rsa_q == NULL
      || rsa_dmp1 == NULL
      || rsa_dmq1 == NULL
      || rsa_iqmp == NULL) {
    goto fail;
  }

  if (!BN_copy(rsa_n, n)
      || !BN_copy(rsa_e, e)
      || !BN_copy(rsa_d, d)
      || !BN_copy(rsa_p, p)
      || !BN_copy(rsa_q, q)
      || !BN_copy(rsa_dmp1, dp)
      || !BN_copy(rsa_dmq1, dq)
      || !BN_copy(rsa_iqmp, qi)) {
    goto fail;
  }

  ctx = BN_CTX_new();
  r0 = BN_new();
  r1 = BN_new();
  r2 = BN_new();

  if (ctx == NULL
      || r0 == NULL
      || r1 == NULL
      || r2 == NULL) {
    goto fail;
  }

  /* See: https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_gen.c */

  if (BN_is_zero(rsa_n)) {
    /* modulus n = p * q * r_3 * r_4 */
    if (!BN_mul(rsa_n, rsa_p, rsa_q, ctx))
      goto fail;
  }

  /* p - 1 */
  if (!BN_sub(r1, rsa_p, BN_value_one()))
    goto fail;

  /* q - 1 */
  if (!BN_sub(r2, rsa_q, BN_value_one()))
    goto fail;

  /* (p - 1)(q - 1) */
  if (!BN_mul(r0, r1, r2, ctx))
    goto fail;

  if (BN_is_zero(rsa_e)) {
    BIGNUM *pr0 = BN_new();

    if (pr0 == NULL)
      goto fail;

    BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);

    if (!BN_mod_inverse(rsa_e, rsa_d, pr0, ctx)) {
      BN_free(pr0);
      goto fail;
    }

    BN_free(pr0);
  }

  if (BN_is_zero(rsa_d)) {
    BIGNUM *pr0 = BN_new();

    if (pr0 == NULL)
      goto fail;

    BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);

    if (!BN_mod_inverse(rsa_d, rsa_e, pr0, ctx)) {
      BN_free(pr0);
      goto fail;
    }

    BN_free(pr0);
  }

  if (BN_is_zero(rsa_dmp1) || BN_is_zero(rsa_dmq1)) {
    BIGNUM *d = BN_new();

    if (d == NULL)
      goto fail;

    BN_with_flags(d, rsa_d, BN_FLG_CONSTTIME);

    /* calculate d mod (p-1) and d mod (q - 1) */
    if (!BN_mod(rsa_dmp1, d, r1, ctx)
        || !BN_mod(rsa_dmq1, d, r2, ctx)) {
      BN_free(d);
      goto fail;
    }

    BN_free(d);
  }

  if (BN_is_zero(rsa_iqmp)) {
    BIGNUM *p = BN_new();

    if (p == NULL)
      goto fail;

    BN_with_flags(p, rsa_p, BN_FLG_CONSTTIME);

    /* calculate inverse of q mod p */
    if (!BN_mod_inverse(rsa_iqmp, rsa_q, p, ctx)) {
      BN_free(p);
      goto fail;
    }

    BN_free(p);
  }

  rsa_out = RSA_new();

  if (rsa_out == NULL)
    goto fail;

  assert(RSA_set0_key(rsa_out, rsa_n, rsa_e, rsa_d));

  rsa_n = NULL;
  rsa_e = NULL;
  rsa_d = NULL;

  assert(RSA_set0_factors(rsa_out, rsa_p, rsa_q));

  rsa_p = NULL;
  rsa_q = NULL;

  assert(RSA_set0_crt_params(rsa_out, rsa_dmp1, rsa_dmq1, rsa_iqmp));

  rsa_dmp1 = NULL;
  rsa_dmq1 = NULL;
  rsa_iqmp = NULL;

  key = bcrypto_rsa_priv2key(rsa_out);

  if (key == NULL)
    goto fail;

  RSA_free(rsakey);
  BN_CTX_free(ctx);
  BN_free(r0);
  BN_free(r1);
  BN_free(r2);
  RSA_free(rsa_out);

  *out = key;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (rsa_n != NULL)
    BN_free(rsa_n);

  if (rsa_e != NULL)
    BN_free(rsa_e);

  if (rsa_d != NULL)
    BN_clear_free(rsa_d);

  if (rsa_p != NULL)
    BN_clear_free(rsa_p);

  if (rsa_q != NULL)
    BN_clear_free(rsa_q);

  if (rsa_dmp1 != NULL)
    BN_clear_free(rsa_dmp1);

  if (rsa_dmq1 != NULL)
    BN_clear_free(rsa_dmq1);

  if (rsa_iqmp != NULL)
    BN_clear_free(rsa_iqmp);

  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (r0 != NULL)
    BN_free(r0);

  if (r1 != NULL)
    BN_free(r1);

  if (r2 != NULL)
    BN_free(r2);

  if (rsa_out != NULL)
    RSA_free(rsa_out);

  return 0;
}

int
bcrypto_rsa_privkey_verify(const bcrypto_rsa_key_t *priv) {
  RSA *rsakey = NULL;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  rsakey = bcrypto_rsa_key2priv(priv);

  if (rsakey == NULL)
    goto fail;

  if (RSA_check_key(rsakey) <= 0)
    goto fail;

  RSA_free(rsakey);

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  return 0;
}

int
bcrypto_rsa_privkey_export(uint8_t **out,
                           size_t *out_len,
                           const bcrypto_rsa_key_t *priv) {
  RSA *rsakey = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_rsa_sane_privkey(priv))
    return 0;

  rsakey = bcrypto_rsa_key2priv(priv);

  if (!rsakey)
    return 0;

  buf = NULL;
  len = i2d_RSAPrivateKey(rsakey, &buf);

  RSA_free(rsakey);

  if (len <= 0)
    return 0;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  return 1;
}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import(const uint8_t *raw, size_t raw_len) {
  RSA *rsakey = NULL;
  const uint8_t *p = raw;
  bcrypto_rsa_key_t *key = NULL;

  if (d2i_RSAPrivateKey(&rsakey, &p, raw_len) == NULL)
    goto fail;

  key = bcrypto_rsa_priv2key(rsakey);

  if (key == NULL)
    goto fail;

#if 0
  if (!bcrypto_rsa_sane_privkey(key))
    goto fail;
#endif

  RSA_free(rsakey);

  return key;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (key != NULL)
    bcrypto_rsa_key_free(key);

  return NULL;
}

int
bcrypto_rsa_privkey_export_pkcs8(uint8_t **out,
                                 size_t *out_len,
                                 const bcrypto_rsa_key_t *priv) {
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ameth.c#L142 */
  RSA *rsa = NULL;
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  unsigned char *rk = NULL;
  int rklen = 0;
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  rsa = bcrypto_rsa_key2priv(priv);

  if (rsa == NULL)
    goto fail;

  p8 = PKCS8_PRIV_KEY_INFO_new();

  if (p8 == NULL)
    goto fail;

  rk = NULL;
  rklen = i2d_RSAPrivateKey(rsa, &rk);

  if (rklen <= 0)
    goto fail;

  if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_rsaEncryption), 0,
                       V_ASN1_NULL, NULL, rk, rklen)) {
    goto fail;
  }

  rk = NULL;

  buf = NULL;
  len = i2d_PKCS8_PRIV_KEY_INFO(p8, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  RSA_free(rsa);
  PKCS8_PRIV_KEY_INFO_free(p8);

  return 1;

fail:
  if (rsa != NULL)
    RSA_free(rsa);

  if (p8 != NULL)
    PKCS8_PRIV_KEY_INFO_free(p8);

  if (rk != NULL)
    OPENSSL_free(rk);

  return 0;
}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import_pkcs8(const uint8_t *raw, size_t raw_len) {
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ameth.c#L169 */
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  const unsigned char *p = NULL;
  RSA *rsakey = NULL;
  int pklen = 0;
  const X509_ALGOR *alg = NULL;
  const ASN1_OBJECT *algoid = NULL;
  const void *algp = NULL;
  int algptype = 0;
  const uint8_t *pp = raw;
  bcrypto_rsa_key_t *key = NULL;

  if (d2i_PKCS8_PRIV_KEY_INFO(&p8, &pp, raw_len) == NULL)
    goto fail;

  if (!PKCS8_pkey_get0(NULL, &p, &pklen, &alg, p8))
    goto fail;

  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ameth.c#L54 */
  X509_ALGOR_get0(&algoid, &algptype, &algp, alg);

  if (OBJ_obj2nid(algoid) != NID_rsaEncryption)
    goto fail;

  if (algptype != V_ASN1_UNDEF && algptype != V_ASN1_NULL)
    goto fail;

  rsakey = d2i_RSAPrivateKey(NULL, &p, pklen);

  if (rsakey == NULL)
    goto fail;

  key = bcrypto_rsa_priv2key(rsakey);

  if (key == NULL)
    goto fail;

#if 0
  if (!bcrypto_rsa_sane_privkey(key))
    goto fail;
#endif

  PKCS8_PRIV_KEY_INFO_free(p8);
  RSA_free(rsakey);

  return key;

fail:
  if (p8 != NULL)
    PKCS8_PRIV_KEY_INFO_free(p8);

  if (rsakey != NULL)
    RSA_free(rsakey);

  if (key != NULL)
    bcrypto_rsa_key_free(key);

  return NULL;
}

int
bcrypto_rsa_pubkey_verify(const bcrypto_rsa_key_t *pub) {
  return bcrypto_rsa_sane_pubkey(pub);
}

int
bcrypto_rsa_pubkey_export(uint8_t **out,
                          size_t *out_len,
                          const bcrypto_rsa_key_t *pub) {
  RSA *rsakey = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_rsa_sane_pubkey(pub))
    return 0;

  rsakey = bcrypto_rsa_key2pub(pub);

  if (rsakey == NULL)
    return 0;

  buf = NULL;
  len = i2d_RSAPublicKey(rsakey, &buf);

  RSA_free(rsakey);

  if (len <= 0)
    return 0;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  return 1;
}

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import(const uint8_t *raw, size_t raw_len) {
  RSA *rsakey = NULL;
  const uint8_t *p = raw;
  bcrypto_rsa_key_t *key = NULL;

  if (d2i_RSAPublicKey(&rsakey, &p, raw_len) == NULL)
    goto fail;

  key = bcrypto_rsa_pub2key(rsakey);

  if (key == NULL)
    goto fail;

#if 0
  if (!bcrypto_rsa_sane_pubkey(key))
    goto fail;
#endif

  RSA_free(rsakey);

  return key;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (key != NULL)
    bcrypto_rsa_key_free(key);

  return NULL;
}

int
bcrypto_rsa_pubkey_export_spki(uint8_t **out,
                               size_t *out_len,
                               const bcrypto_rsa_key_t *pub) {
  RSA *rsakey = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_rsa_sane_pubkey(pub))
    return 0;

  rsakey = bcrypto_rsa_key2pub(pub);

  if (rsakey == NULL)
    return 0;

  buf = NULL;
  len = i2d_RSA_PUBKEY(rsakey, &buf);

  RSA_free(rsakey);

  if (len <= 0)
    return 0;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  return 1;
}

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import_spki(const uint8_t *raw, size_t raw_len) {
  RSA *rsakey = NULL;
  const uint8_t *p = raw;
  bcrypto_rsa_key_t *key = NULL;

  if (d2i_RSA_PUBKEY(&rsakey, &p, raw_len) == NULL)
    goto fail;

  key = bcrypto_rsa_pub2key(rsakey);

  if (key == NULL)
    goto fail;

#if 0
  if (!bcrypto_rsa_sane_pubkey(key))
    goto fail;
#endif

  RSA_free(rsakey);

  return key;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (key != NULL)
    bcrypto_rsa_key_free(key);

  return NULL;
}

int
bcrypto_rsa_sign(uint8_t **out,
                 size_t *out_len,
                 const char *alg,
                 const uint8_t *msg,
                 size_t msg_len,
                 const bcrypto_rsa_key_t *priv) {
  int type = -1;
  RSA *rsakey = NULL;
  uint8_t *sig = NULL;
  unsigned int sig_len = 0;
  int result = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_hash_size(type))
    goto fail;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  rsakey = bcrypto_rsa_key2priv(priv);

  if (rsakey == NULL)
    goto fail;

  sig_len = (unsigned int)RSA_size(rsakey);
  sig = (uint8_t *)malloc(sig_len);

  if (sig == NULL)
    goto fail;

  bcrypto_poll();

  /* Protect against side-channel attacks. */
  if (!RSA_blinding_on(rsakey, NULL))
    goto fail;

  /* $ man RSA_sign */
  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_sign.c#L69 */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L238 */
  result = RSA_sign(
    type,     /* int type */
    msg,      /* const unsigned char *m */
    msg_len,  /* unsigned int m_len */
    sig,      /* unsigned char *sigret */
    &sig_len, /* unsigned int *siglen */
    rsakey    /* RSA *rsa */
  );

  RSA_blinding_off(rsakey);

  if (!result)
    goto fail;

  assert(sig_len == (unsigned int)RSA_size(rsakey));

  RSA_free(rsakey);

  *out = sig;
  *out_len = (size_t)sig_len;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (sig != NULL)
    free(sig);

  return 0;
}

int
bcrypto_rsa_verify(const char *alg,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len,
                   const bcrypto_rsa_key_t *pub) {
  int type = -1;
  RSA *rsakey = NULL;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_hash_size(type))
    goto fail;

  if (sig == NULL || sig_len != bcrypto_rsa_mod_size(pub))
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  rsakey = bcrypto_rsa_key2pub(pub);

  if (rsakey == NULL)
    goto fail;

  /* flen _must_ be modulus length. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_sign.c#L124 */
  if (RSA_verify(type, msg, msg_len, sig, sig_len, rsakey) <= 0)
    goto fail;

  RSA_free(rsakey);

  return 1;
fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  return 0;
}

int
bcrypto_rsa_encrypt(uint8_t **out,
                    size_t *out_len,
                    const uint8_t *pt,
                    size_t pt_len,
                    const bcrypto_rsa_key_t *pub) {
  RSA *rsakey = NULL;
  uint8_t *c = NULL;
  int c_len = 0;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  rsakey = bcrypto_rsa_key2pub(pub);

  if (rsakey == NULL)
    goto fail;

  c = (uint8_t *)malloc(RSA_size(rsakey));

  if (c == NULL)
    goto fail;

  bcrypto_poll();

  /* $ man RSA_public_encrypt */
  /* flen must be size of modulus. */
  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L67 */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_none.c#L14 */
  c_len = RSA_public_encrypt(
    pt_len,           /* int flen */
    pt,               /* const uint8_t *from */
    c,                /* uint8_t *to */
    rsakey,           /* RSA *rsa */
    RSA_PKCS1_PADDING /* int padding */
  );

  if (c_len <= 0)
    goto fail;

  assert(c_len == RSA_size(rsakey));

  RSA_free(rsakey);

  *out = c;
  *out_len = (size_t)c_len;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (c != NULL)
    free(c);

  return 0;
}

int
bcrypto_rsa_decrypt(uint8_t **out,
                    size_t *out_len,
                    const uint8_t *ct,
                    size_t ct_len,
                    const bcrypto_rsa_key_t *priv) {
  RSA *rsakey = NULL;
  uint8_t *pt = NULL;
  int pt_len = 0;

  if (ct == NULL || ct_len != bcrypto_rsa_mod_size(priv))
    goto fail;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  rsakey = bcrypto_rsa_key2priv(priv);

  if (rsakey == NULL)
    goto fail;

  pt = (uint8_t *)malloc(RSA_size(rsakey));

  if (pt == NULL)
    goto fail;

  bcrypto_poll();

  /* Protect against side-channel attacks. */
  if (!RSA_blinding_on(rsakey, NULL))
    goto fail;

  /* $ man RSA_private_decrypt */
  /* flen can be smaller than modulus. */
  /* tlen is less than modulus size for pkcs1. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L374 */
  pt_len = RSA_private_decrypt(
    ct_len,           /* int flen */
    ct,               /* const uint8_t *from */
    pt,               /* uint8_t *to */
    rsakey,           /* RSA *rsa */
    RSA_PKCS1_PADDING /* int padding */
  );

  RSA_blinding_off(rsakey);

  if (pt_len < 0)
    goto fail;

  if (pt_len == 0) {
    free(pt);
    pt = NULL;
  }

  RSA_free(rsakey);

  *out = pt;
  *out_len = (size_t)pt_len;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (pt != NULL)
    free(pt);

  return 0;
}

int
bcrypto_rsa_encrypt_oaep(uint8_t **out,
                         size_t *out_len,
                         const char *alg,
                         const uint8_t *pt,
                         size_t pt_len,
                         const bcrypto_rsa_key_t *pub,
                         const uint8_t *label,
                         size_t label_len) {
  int type = -1;
  const EVP_MD *md = NULL;
  RSA *rsakey = NULL;
  uint8_t *em = NULL;
  uint8_t *c = NULL;
  int c_len = 0;
  int result = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  md = EVP_get_digestbynid(type);

  if (md == NULL)
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  rsakey = bcrypto_rsa_key2pub(pub);

  if (rsakey == NULL)
    goto fail;

  em = (uint8_t *)malloc(RSA_size(rsakey));

  if (em == NULL)
    goto fail;

  c = (uint8_t *)malloc(RSA_size(rsakey));

  if (c == NULL)
    goto fail;

  memset(em, 0x00, RSA_size(rsakey));

  bcrypto_poll();

  /* $ man RSA_padding_add_PKCS1_OAEP */
  /* https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_oaep.c#L41 */
  result = RSA_padding_add_PKCS1_OAEP_mgf1(
    em,               /* uint8_t *to */
    RSA_size(rsakey), /* int tlen */
    pt,               /* const uint8_t *from */
    pt_len,           /* int flen */
    label,            /* const uint8_t *param */
    label_len,        /* int plen */
    md,               /* const EVP_MD *md */
    md                /* const EVP_MD *mgf1md */
  );

  if (!result)
    goto fail;

  /* $ man RSA_public_encrypt */
  /* flen must be size of modulus. */
  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L67 */
  c_len = RSA_public_encrypt(
    RSA_size(rsakey), /* int flen */
    em,               /* const uint8_t *from */
    c,                /* uint8_t *to */
    rsakey,           /* RSA *rsa */
    RSA_NO_PADDING    /* int padding */
  );

  OPENSSL_cleanse(em, RSA_size(rsakey));

  if (c_len <= 0)
    goto fail;

  assert(c_len == RSA_size(rsakey));

  RSA_free(rsakey);
  free(em);

  *out = c;
  *out_len = (size_t)c_len;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (em != NULL)
    free(em);

  if (c != NULL)
    free(c);

  return 0;
}

int
bcrypto_rsa_decrypt_oaep(uint8_t **out,
                         size_t *out_len,
                         const char *alg,
                         const uint8_t *ct,
                         size_t ct_len,
                         const bcrypto_rsa_key_t *priv,
                         const uint8_t *label,
                         size_t label_len) {
  int type = -1;
  const EVP_MD *md = NULL;
  RSA *rsakey = NULL;
  uint8_t *em = NULL;
  int em_len = 0;
  uint8_t *pt = NULL;
  int pt_len = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  md = EVP_get_digestbynid(type);

  if (md == NULL)
    goto fail;

  if (ct == NULL || ct_len != bcrypto_rsa_mod_size(priv))
    goto fail;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  rsakey = bcrypto_rsa_key2priv(priv);

  if (rsakey == NULL)
    goto fail;

  em = (uint8_t *)malloc(RSA_size(rsakey));

  if (em == NULL)
    goto fail;

  bcrypto_poll();

  /* Protect against side-channel attacks. */
  if (!RSA_blinding_on(rsakey, NULL))
    goto fail;

  memset(em, 0x00, RSA_size(rsakey));

  /* $ man RSA_private_decrypt */
  /* flen can be smaller than modulus. */
  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L374 */
  em_len = RSA_private_decrypt(
    ct_len,        /* int flen */
    ct,            /* const uint8_t *from */
    em,            /* uint8_t *to */
    rsakey,        /* RSA *rsa */
    RSA_NO_PADDING /* int padding */
  );

  RSA_blinding_off(rsakey);

  if (em_len <= 0)
    goto fail;

  assert(em_len == RSA_size(rsakey));

  pt = (uint8_t *)malloc(RSA_size(rsakey));

  if (pt == NULL) {
    OPENSSL_cleanse(em, RSA_size(rsakey));
    goto fail;
  }

  /* https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_oaep.c#L116 */
  pt_len = RSA_padding_check_PKCS1_OAEP_mgf1(
    pt,               /* uint8_t *to */
    RSA_size(rsakey), /* int tlen */
    em,               /* const uint8_t *from */
    em_len,           /* int flen */
    RSA_size(rsakey), /* int num (modulus size) */
    label,            /* const uint8_t *param */
    label_len,        /* int plen */
    md,               /* const EVP_MD *md */
    md                /* const EVP_MD *mgf1md */
  );

  OPENSSL_cleanse(em, RSA_size(rsakey));

  if (pt_len < 0)
    goto fail;

  if (pt_len == 0) {
    free(pt);
    pt = NULL;
  }

  RSA_free(rsakey);
  free(em);

  *out = pt;
  *out_len = (size_t)pt_len;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (em != NULL)
    free(em);

  if (pt != NULL)
    free(pt);

  return 0;
}

int
bcrypto_rsa_sign_pss(uint8_t **out,
                     size_t *out_len,
                     const char *alg,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_rsa_key_t *priv,
                     int salt_len) {
  int type = -1;
  const EVP_MD *md = NULL;
  RSA *rsakey = NULL;
  uint8_t *em = NULL;
  int result = 0;
  uint8_t *sig = NULL;
  int sig_len = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  md = EVP_get_digestbynid(type);

  if (md == NULL)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_hash_size(type))
    goto fail;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  if (salt_len < -1)
    goto fail;

  rsakey = bcrypto_rsa_key2priv(priv);

  if (rsakey == NULL)
    goto fail;

  em = (uint8_t *)malloc(RSA_size(rsakey));

  if (em == NULL)
    goto fail;

  if (salt_len == 0)
    salt_len = -2; /* RSA_PSS_SALTLEN_MAX_SIGN */
  else if (salt_len == -1)
    salt_len = -1; /* RSA_PSS_SALTLEN_DIGEST */

  memset(em, 0x00, RSA_size(rsakey));

  bcrypto_poll();

  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_pss.c#L145 */
  /* https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_pmeth.c#L122 */
  result = RSA_padding_add_PKCS1_PSS_mgf1(
    rsakey,  /* RSA *rsa */
    em,      /* uint8_t *EM */
    msg,     /* const uint8_t *mHash */
    md,      /* const EVP_MD *Hash */
    md,      /* const EVP_MD *mgf1Hash */
    salt_len /* int sLen */
  );

  if (!result)
    goto fail;

  sig = (uint8_t *)malloc(RSA_size(rsakey));

  if (sig == NULL) {
    OPENSSL_cleanse(em, RSA_size(rsakey));
    goto fail;
  }

  /* Protect against side-channel attacks. */
  if (!RSA_blinding_on(rsakey, NULL)) {
    OPENSSL_cleanse(em, RSA_size(rsakey));
    goto fail;
  }

  /* $ man RSA_private_encrypt */
  /* flen must be modulus size. */
  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L238 */
  sig_len = RSA_private_encrypt(
    RSA_size(rsakey), /* int flen */
    em,               /* const uint8_t *from */
    sig,              /* uint8_t *to */
    rsakey,           /* RSA *rsa */
    RSA_NO_PADDING    /* int padding */
  );

  OPENSSL_cleanse(em, RSA_size(rsakey));

  RSA_blinding_off(rsakey);

  if (sig_len <= 0)
    goto fail;

  assert(sig_len == RSA_size(rsakey));

  RSA_free(rsakey);
  free(em);

  *out = sig;
  *out_len = (size_t)sig_len;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (em != NULL)
    free(em);

  if (sig != NULL)
    free(sig);

  return 0;
}

int
bcrypto_rsa_verify_pss(const char *alg,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       const bcrypto_rsa_key_t *pub,
                       int salt_len) {
  int type = 0;
  const EVP_MD *md = NULL;
  RSA *rsakey = NULL;
  uint8_t *em = NULL;
  int em_len = 0;
  int result = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  md = EVP_get_digestbynid(type);

  if (md == NULL)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_hash_size(type))
    goto fail;

  if (sig == NULL || sig_len != bcrypto_rsa_mod_size(pub))
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  rsakey = bcrypto_rsa_key2pub(pub);

  if (rsakey == NULL)
    goto fail;

  em = (uint8_t *)malloc(RSA_size(rsakey));

  if (em == NULL)
    goto fail;

  memset(em, 0x00, RSA_size(rsakey));

  /* $ man RSA_public_decrypt */
  /* flen can be smaller than modulus size. */
  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L507 */
  em_len = RSA_public_decrypt(
    sig_len,       /* int flen */
    sig,           /* const uint8_t *from */
    em,            /* uint8_t *to */
    rsakey,        /* RSA *rsa */
    RSA_NO_PADDING /* int padding */
  );

  if (em_len <= 0)
    goto fail;

  assert(em_len == RSA_size(rsakey));

  if (salt_len == 0)
    salt_len = -2; /* RSA_PSS_SALTLEN_AUTO */
  else if (salt_len == -1)
    salt_len = -1; /* RSA_PSS_SALTLEN_DIGEST */

  /* https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_pss.c#L32 */
  result = RSA_verify_PKCS1_PSS_mgf1(
    rsakey,  /* RSA *rsa */
    msg,     /* const uint8_t *mHash */
    md,      /* const EVP_MD *Hash */
    md,      /* const EVP_MD *mgf1Hash */
    em,      /* const uint8_t *EM */
    salt_len /* int sLen */
  );

  OPENSSL_cleanse(em, RSA_size(rsakey));

  if (!result)
    goto fail;

  RSA_free(rsakey);
  free(em);

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (em != NULL)
    free(em);

  return 0;
}

int
bcrypto_rsa_encrypt_raw(uint8_t **out,
                        size_t *out_len,
                        const uint8_t *pt,
                        size_t pt_len,
                        const bcrypto_rsa_key_t *pub) {
  RSA *rsakey = NULL;
  uint8_t *ct = NULL;
  int ct_len = 0;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  rsakey = bcrypto_rsa_key2pub(pub);

  if (rsakey == NULL)
    goto fail;

  ct = (uint8_t *)malloc(RSA_size(rsakey));

  if (ct == NULL)
    goto fail;

  /* $ man RSA_public_encrypt */
  /* flen must be size of modulus. */
  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L67 */
  ct_len = RSA_public_encrypt(
    pt_len,        /* int flen */
    pt,            /* const uint8_t *from */
    ct,            /* uint8_t *to */
    rsakey,        /* RSA *rsa */
    RSA_NO_PADDING /* int padding */
  );

  if (ct_len <= 0)
    goto fail;

  assert(ct_len == RSA_size(rsakey));

  RSA_free(rsakey);

  *out = ct;
  *out_len = (size_t)ct_len;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (ct != NULL)
    free(ct);

  return 0;
}

int
bcrypto_rsa_decrypt_raw(uint8_t **out,
                        size_t *out_len,
                        const uint8_t *ct,
                        size_t ct_len,
                        const bcrypto_rsa_key_t *priv) {
  RSA *rsakey = NULL;
  uint8_t *pt = NULL;
  int pt_len = 0;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  rsakey = bcrypto_rsa_key2priv(priv);

  if (rsakey == NULL)
    goto fail;

  pt = (uint8_t *)malloc(RSA_size(rsakey));

  if (pt == NULL)
    goto fail;

  bcrypto_poll();

  /* Protect against side-channel attacks. */
  if (!RSA_blinding_on(rsakey, NULL))
    goto fail;

  /* $ man RSA_private_decrypt */
  /* flen can be smaller than modulus. */
  /* tlen is always modulus size. */
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L374 */
  pt_len = RSA_private_decrypt(
    ct_len,        /* int flen */
    ct,            /* const uint8_t *from */
    pt,            /* uint8_t *to */
    rsakey,        /* RSA *rsa */
    RSA_NO_PADDING /* int padding */
  );

  RSA_blinding_off(rsakey);

  if (pt_len <= 0)
    goto fail;

  assert(pt_len == RSA_size(rsakey));

  RSA_free(rsakey);

  *out = pt;
  *out_len = (size_t)pt_len;

  return 1;

fail:
  if (rsakey != NULL)
    RSA_free(rsakey);

  if (pt != NULL)
    free(pt);

  return 0;
}

int
bcrypto_rsa_veil(uint8_t **out,
                 size_t *out_len,
                 const uint8_t *ct,
                 size_t ct_len,
                 size_t bits,
                 const bcrypto_rsa_key_t *pub) {
  int ret = 0;
  BN_CTX *ctx = NULL;
  BIGNUM *c = NULL;
  BIGNUM *n = NULL;
  BIGNUM *vmax = NULL;
  BIGNUM *rmax = NULL;
  BIGNUM *v = NULL;
  BIGNUM *r = NULL;
  uint8_t *veiled = NULL;
  int veiled_len = 0;

  if (ct == NULL || ct_len != bcrypto_rsa_mod_size(pub))
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  /* Can't make ciphertext smaller. */
  if (bits < bcrypto_rsa_mod_bits(pub))
    goto fail;

  ctx = BN_CTX_new();
  c = BN_bin2bn(ct, ct_len, NULL);
  n = BN_bin2bn(pub->nd, pub->nl, NULL);
  vmax = BN_new();
  rmax = BN_new();
  v = BN_new();
  r = BN_new();

  if (ctx == NULL
      || c == NULL
      || n == NULL
      || vmax == NULL
      || rmax == NULL
      || v == NULL
      || r == NULL) {
    goto fail;
  }

  /* Invalid ciphertext. */
  if (BN_cmp(c, n) >= 0)
    goto fail;

  /* vmax = 1 << bits */
  if (!BN_set_word(vmax, 1)
      || !BN_lshift(vmax, vmax, bits)) {
    goto fail;
  }

  /* rmax = (vmax - c + n - 1) / n */
  if (!BN_copy(rmax, vmax)
      || !BN_sub(rmax, rmax, c)
      || !BN_add(rmax, rmax, n)
      || !BN_sub_word(rmax, 1)
      || !BN_div(rmax, NULL, rmax, n, ctx)) {
    goto fail;
  }

  /* rmax > 0 */
  assert(!BN_is_negative(rmax) && !BN_is_zero(rmax));

  /* v = vmax */
  if (!BN_copy(v, vmax))
    goto fail;

  bcrypto_poll();

  /* while v >= vmax */
  while (BN_cmp(v, vmax) >= 0) {
    /* r = random integer in [0,rmax-1] */
    if (!BN_rand_range(r, rmax))
      goto fail;

    /* v = c + r * n */
    if (!BN_mul(r, r, n, ctx))
      goto fail;

    if (!BN_add(v, c, r))
      goto fail;
  }

  if (!BN_mod(r, v, n, ctx))
    goto fail;

  /* v mod n == c */
  assert(BN_cmp(r, c) == 0);
  assert((size_t)BN_num_bits(v) <= bits);

  veiled_len = (bits + 7) / 8;
  veiled = (uint8_t *)malloc(veiled_len);

  if (veiled == NULL)
    goto fail;

  assert(BN_bn2binpad(v, veiled, veiled_len) != -1);

  *out = veiled;
  *out_len = veiled_len;
  veiled = NULL;

  ret = 1;
fail:
  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (c != NULL)
    BN_free(c);

  if (n != NULL)
    BN_free(n);

  if (vmax != NULL)
    BN_free(vmax);

  if (rmax != NULL)
    BN_free(rmax);

  if (v != NULL)
    BN_free(v);

  if (r != NULL)
    BN_free(r);

  if (veiled != NULL)
    free(veiled);

  return ret;
}

int
bcrypto_rsa_unveil(uint8_t **out,
                   size_t *out_len,
                   const uint8_t *veiled,
                   size_t veiled_len,
                   size_t bits,
                   const bcrypto_rsa_key_t *pub) {
  int ret = 0;
  size_t klen = 0;
  BN_CTX *ctx = NULL;
  BIGNUM *v = NULL;
  BIGNUM *n = NULL;
  uint8_t *ct = NULL;
  int ct_len = 0;

  klen = bcrypto_rsa_mod_size(pub);

  if (veiled == NULL || veiled_len < klen)
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  if (bcrypto_count_bits(veiled, veiled_len) > bits)
    goto fail;

  ctx = BN_CTX_new();
  v = BN_bin2bn(veiled, veiled_len, NULL);
  n = BN_bin2bn(pub->nd, pub->nl, NULL);

  if (ctx == NULL || v == NULL || n == NULL)
    goto fail;

  /* c = v % n */
  if (!BN_mod(v, v, n, ctx))
    goto fail;

  assert((size_t)BN_num_bytes(v) <= klen);

  ct_len = klen;
  ct = (uint8_t *)malloc(ct_len);

  if (ct == NULL)
    goto fail;

  assert(BN_bn2binpad(v, ct, ct_len) != -1);

  *out = ct;
  *out_len = ct_len;
  ct = NULL;

  ret = 1;
fail:
  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (v != NULL)
    BN_free(v);

  if (n != NULL)
    BN_free(n);

  if (ct != NULL)
    free(ct);

  return ret;
}

int
bcrypto_rsa_has_hash(const char *alg) {
  int type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    return 0;

  return EVP_get_digestbynid(type) != NULL;
}

#endif
