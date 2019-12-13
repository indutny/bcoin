#include "../compat.h"

#ifdef BCRYPTO_HAS_DSA

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdlib.h>
#include "dsa.h"

#include "openssl/bn.h"
#include "openssl/dsa.h"
#include "openssl/objects.h"
#include "openssl/x509.h"
#include "../random/random.h"

#define BCRYPTO_DSA_DEFAULT_BITS 2048
#define BCRYPTO_DSA_MIN_BITS 512
#define BCRYPTO_DSA_MAX_BITS 10000

void
bcrypto_dsa_key_init(bcrypto_dsa_key_t *key) {
  assert(key != NULL);
  memset((void *)key, 0x00, sizeof(bcrypto_dsa_key_t));
}

void
bcrypto_dsa_key_free(bcrypto_dsa_key_t *key) {
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
bcrypto_cmp(const uint8_t *x, size_t xl, const uint8_t *y, size_t yl, int sub) {
  while (xl > 0 && *x == 0)
    x++, xl--;

  while (yl > 0 && *y == 0)
    y++, yl--;

  if (xl < yl)
    return -1;

  if (xl > yl)
    return 1;

  size_t i = 0;

  if (sub && xl > 0)
    assert((y[xl - 1] & 1) != 0);

  for (; i < xl; i++) {
    uint8_t one = sub && (i == xl - 1) ? 1 : 0;

    if (x[i] < y[i] - one)
      return -1;

    if (x[i] > y[i] - one)
      return 1;
  }

  return 0;
}

static int
bcrypto_dsa_sane_params(const bcrypto_dsa_key_t *params) {
  if (params == NULL)
    return 0;

  size_t pb = bcrypto_count_bits(params->pd, params->pl);
  size_t qb = bcrypto_count_bits(params->qd, params->ql);
  size_t gb = bcrypto_count_bits(params->gd, params->gl);

  if (pb < BCRYPTO_DSA_MIN_BITS || pb > BCRYPTO_DSA_MAX_BITS)
    return 0;

  if (qb != 160 && qb != 224 && qb != 256)
    return 0;

  if (gb < 2 || gb > pb)
    return 0;

  if ((params->pd[params->pl - 1] & 1) == 0)
    return 0;

  if ((params->qd[params->ql - 1] & 1) == 0)
    return 0;

  if (bcrypto_cmp(params->gd, params->gl, params->pd, params->pl, 1) >= 0)
    return 0;

  return 1;
}

static int
bcrypto_dsa_sane_pubkey(const bcrypto_dsa_key_t *key) {
  if (!bcrypto_dsa_sane_params(key))
    return 0;

  size_t pb = bcrypto_count_bits(key->pd, key->pl);
  size_t yb = bcrypto_count_bits(key->yd, key->yl);

  if (yb < 2 || yb > pb)
    return 0;

  if (bcrypto_cmp(key->yd, key->yl, key->pd, key->pl, 1) >= 0)
    return 0;

  return 1;
}

static int
bcrypto_dsa_sane_privkey(const bcrypto_dsa_key_t *key) {
  if (!bcrypto_dsa_sane_pubkey(key))
    return 0;

  size_t qb = bcrypto_count_bits(key->qd, key->ql);
  size_t xb = bcrypto_count_bits(key->xd, key->xl);

  if (xb == 0 || xb > qb)
    return 0;

  if (bcrypto_cmp(key->xd, key->xl, key->qd, key->ql, 0) >= 0)
    return 0;

  return 1;
}

static int
bcrypto_dsa_sane_compute(const bcrypto_dsa_key_t *key) {
  if (key == NULL)
    return 0;

  size_t pb = bcrypto_count_bits(key->pd, key->pl);
  size_t qb = bcrypto_count_bits(key->qd, key->ql);
  size_t gb = bcrypto_count_bits(key->gd, key->gl);
  size_t yb = bcrypto_count_bits(key->yd, key->yl);
  size_t xb = bcrypto_count_bits(key->xd, key->xl);

  if (pb < BCRYPTO_DSA_MIN_BITS || pb > BCRYPTO_DSA_MAX_BITS)
    return 0;

  if (qb != 160 && qb != 224 && qb != 256)
    return 0;

  if (gb < 2 || gb > pb)
    return 0;

  if ((key->pd[key->pl - 1] & 1) == 0)
    return 0;

  if ((key->qd[key->ql - 1] & 1) == 0)
    return 0;

  if (yb > pb)
    return 0;

  if (xb == 0 || xb > qb)
    return 0;

  if (bcrypto_cmp(key->gd, key->gl, key->pd, key->pl, 1) >= 0)
    return 0;

  if (bcrypto_cmp(key->yd, key->yl, key->pd, key->pl, 0) >= 0)
    return 0;

  if (bcrypto_cmp(key->xd, key->xl, key->qd, key->ql, 0) >= 0)
    return 0;

  return 1;
}

static int
bcrypto_dsa_needs_compute(const bcrypto_dsa_key_t *key) {
  if (key == NULL)
    return 0;

  return bcrypto_count_bits(key->yd, key->yl) == 0;
}

static size_t
bcrypto_dsa_subprime_size(const bcrypto_dsa_key_t *key) {
  if (key == NULL)
    return 0;

  return (bcrypto_count_bits(key->qd, key->ql) + 7) / 8;
}

static DSA *
bcrypto_dsa_key2dsa(const bcrypto_dsa_key_t *key, int mode) {
  DSA *dsakey = NULL;
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *g = NULL;
  BIGNUM *y = NULL;
  BIGNUM *x = NULL;

  if (key == NULL)
    goto fail;

  if (mode < 0 || mode > 2)
    goto fail;

  dsakey = DSA_new();

  if (dsakey == NULL)
    goto fail;

  p = BN_bin2bn(key->pd, key->pl, NULL);
  q = BN_bin2bn(key->qd, key->ql, NULL);
  g = BN_bin2bn(key->gd, key->gl, NULL);

  if (p == NULL || q == NULL || g == NULL)
    goto fail;

  if (mode == 1 || mode == 2) {
    y = BN_bin2bn(key->yd, key->yl, NULL);

    if (y == NULL)
      goto fail;
  }

  if (mode == 2) {
    x = BN_bin2bn(key->xd, key->xl, BN_secure_new());

    if (x == NULL)
      goto fail;
  }

  if (!DSA_set0_pqg(dsakey, p, q, g))
    goto fail;

  p = NULL;
  q = NULL;
  g = NULL;

  if (mode == 1 || mode == 2) {
    if (!DSA_set0_key(dsakey, y, x))
      goto fail;
  }

  y = NULL;
  x = NULL;

  return dsakey;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (p != NULL)
    BN_free(p);

  if (q != NULL)
    BN_free(q);

  if (g != NULL)
    BN_free(g);

  if (y != NULL)
    BN_free(y);

  if (x != NULL)
    BN_clear_free(x);

  return NULL;
}

static DSA *
bcrypto_dsa_key2params(const bcrypto_dsa_key_t *params) {
  return bcrypto_dsa_key2dsa(params, 0);
}

static DSA *
bcrypto_dsa_key2pub(const bcrypto_dsa_key_t *pub) {
  return bcrypto_dsa_key2dsa(pub, 1);
}

static DSA *
bcrypto_dsa_key2priv(const bcrypto_dsa_key_t *priv) {
  return bcrypto_dsa_key2dsa(priv, 2);
}

static bcrypto_dsa_key_t *
bcrypto_dsa_dsa2key(const DSA *dsakey, int mode) {
  bcrypto_dsa_key_t *key = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *g = NULL;
  const BIGNUM *y = NULL;
  const BIGNUM *x = NULL;
  uint8_t *slab = NULL;

  if (dsakey == NULL)
    goto fail;

  if (mode < 0 || mode > 2)
    goto fail;

  key = (bcrypto_dsa_key_t *)malloc(sizeof(bcrypto_dsa_key_t));

  if (key == NULL)
    goto fail;

  bcrypto_dsa_key_init(key);

  DSA_get0_pqg(dsakey, &p, &q, &g);

  if (p == NULL || q == NULL || g == NULL)
    goto fail;

  if (mode == 1 || mode == 2) {
    DSA_get0_key(dsakey, &y, NULL);

    if (y == NULL)
      goto fail;
  }

  if (mode == 2) {
    DSA_get0_key(dsakey, NULL, &x);

    if (x == NULL)
      goto fail;
  }

  size_t pl = (size_t)BN_num_bytes(p);
  size_t ql = (size_t)BN_num_bytes(q);
  size_t gl = (size_t)BN_num_bytes(g);
  size_t yl = 0;
  size_t xl = 0;

  if (mode == 1 || mode == 2)
    yl = (size_t)BN_num_bytes(y);

  if (mode == 2)
    xl = (size_t)BN_num_bytes(x);

  size_t size = pl + ql + gl + yl + xl;
  size_t pos = 0;

  /* Align. */
  size += 8 - (size & 7);

  slab = (uint8_t *)malloc(size);

  if (slab == NULL)
    goto fail;

  key->slab = slab;

  key->pd = (uint8_t *)&slab[pos];
  key->pl = pl;
  pos += pl;

  key->qd = (uint8_t *)&slab[pos];
  key->ql = ql;
  pos += ql;

  key->gd = (uint8_t *)&slab[pos];
  key->gl = gl;
  pos += gl;

  if (mode == 1 || mode == 2) {
    key->yd = (uint8_t *)&slab[pos];
    key->yl = yl;
    pos += yl;
  }

  if (mode == 2) {
    key->xd = (uint8_t *)&slab[pos];
    key->xl = xl;
    pos += xl;
  }

  assert(BN_bn2bin(p, key->pd) != -1);
  assert(BN_bn2bin(q, key->qd) != -1);
  assert(BN_bn2bin(g, key->gd) != -1);

  if (mode == 1 || mode == 2)
    assert(BN_bn2bin(y, key->yd) != -1);

  if (mode == 2)
    assert(BN_bn2bin(x, key->xd) != -1);

  return key;

fail:
  if (key != NULL)
    bcrypto_dsa_key_free(key);

  return NULL;
}

static bcrypto_dsa_key_t *
bcrypto_dsa_params2key(const DSA *dsaparams) {
  return bcrypto_dsa_dsa2key(dsaparams, 0);
}

static bcrypto_dsa_key_t *
bcrypto_dsa_pub2key(const DSA *dsakey) {
  return bcrypto_dsa_dsa2key(dsakey, 1);
}

static bcrypto_dsa_key_t *
bcrypto_dsa_priv2key(const DSA *dsakey) {
  return bcrypto_dsa_dsa2key(dsakey, 2);
}

static DSA_SIG *
bcrypto_dsa_rs2sig(const uint8_t *sig, size_t sig_len) {
  DSA_SIG *dsasig = NULL;
  size_t size = 0;
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;

  if (sig == NULL || sig_len == 0)
    goto fail;

  dsasig = DSA_SIG_new();

  if (dsasig == NULL)
    goto fail;

  size = sig_len >> 1;
  r = BN_bin2bn(&sig[0], size, NULL);

  if (r == NULL)
    goto fail;

  s = BN_bin2bn(&sig[size], size, NULL);

  if (s == NULL)
    goto fail;

  if (!DSA_SIG_set0(dsasig, r, s))
    goto fail;

  return dsasig;

fail:
  if (dsasig != NULL)
    DSA_SIG_free(dsasig);

  if (r != NULL)
    BN_free(r);

  if (s != NULL)
    BN_free(s);

  return NULL;
}

static int
bcrypto_dsa_sig2rs(uint8_t **out,
                   size_t *out_len,
                   const DSA *dsakey,
                   const DSA_SIG *dsasig) {
  uint8_t *raw = NULL;
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;
  const BIGNUM *q = NULL;
  int bits = 0;
  size_t size = 0;

  DSA_SIG_get0(dsasig, &r, &s);

  assert(r != NULL && s != NULL);

  DSA_get0_pqg(dsakey, NULL, &q, NULL);

  assert(q != NULL);

  bits = BN_num_bits(q);
  size = ((size_t)bits + 7) / 8;

  assert((size_t)BN_num_bytes(r) <= size);
  assert((size_t)BN_num_bytes(s) <= size);

  raw = (uint8_t *)malloc(size * 2);

  if (raw == NULL)
    goto fail;

  assert(BN_bn2binpad(r, &raw[0], size) > 0);
  assert(BN_bn2binpad(s, &raw[size], size) > 0);

  *out = raw;
  *out_len = size * 2;

  return 1;

fail:
  if (raw != NULL)
    free(raw);

  return 0;
}

static int
mod_exp_const(BIGNUM *r,
              const BIGNUM *a, const BIGNUM *p,
              const BIGNUM *m, BN_CTX *ctx) {
  BIGNUM *c = BN_secure_new();

  if (c == NULL)
    goto fail;

  /* We shouldn't modify the constant time BN. */
  assert(r != p);

  BN_with_flags(c, p, BN_FLG_CONSTTIME);

  if (!BN_mod_exp(r, a, c, m, ctx))
    goto fail;

  /* Note: calling BN_clear_free in combination
     with BN_with_flags seems to cause breakage. */
  BN_free(c);

  return 1;

fail:
  if (c != NULL)
    BN_free(c);

  return 0;
}

bcrypto_dsa_key_t *
bcrypto_dsa_params_generate(int bits) {
  DSA *dsaparams = NULL;
  bcrypto_dsa_key_t *params = NULL;

  if (bits < BCRYPTO_DSA_MIN_BITS || bits > BCRYPTO_DSA_MAX_BITS)
    goto fail;

  dsaparams = DSA_new();

  if (dsaparams == NULL)
    goto fail;

  bcrypto_poll();

  if (!DSA_generate_parameters_ex(dsaparams, bits, NULL, 0, NULL, NULL, NULL))
    goto fail;

  params = bcrypto_dsa_params2key(dsaparams);

  if (params == NULL)
    goto fail;

  DSA_free(dsaparams);

  return params;

fail:
  if (dsaparams != NULL)
    DSA_free(dsaparams);

  return NULL;
}

int
bcrypto_dsa_params_verify(const bcrypto_dsa_key_t *params) {
  DSA *dsaparams = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *g = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *x = NULL;

  if (!bcrypto_dsa_sane_params(params))
    goto fail;

  dsaparams = bcrypto_dsa_key2params(params);

  if (dsaparams == NULL)
    goto fail;

  DSA_get0_pqg(dsaparams, &p, &q, &g);
  assert(p != NULL && q != NULL && g != NULL);

  ctx = BN_CTX_new();
  x = BN_new();

  if (ctx == NULL || x == NULL)
    goto fail;

  /* x = g^q mod p */
  if (!BN_mod_exp(x, g, q, p, ctx))
    goto fail;

  /* x != 1 */
  if (!BN_is_one(x))
    goto fail;

  DSA_free(dsaparams);
  BN_CTX_free(ctx);
  BN_free(x);

  return 1;

fail:
  if (dsaparams != NULL)
    DSA_free(dsaparams);

  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (x != NULL)
    BN_free(x);

  return 0;
}

int
bcrypto_dsa_params_export(uint8_t **out,
                          size_t *out_len,
                          const bcrypto_dsa_key_t *params) {
  DSA *dsaparams = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_dsa_sane_params(params))
    return 0;

  dsaparams = bcrypto_dsa_key2params(params);

  if (dsaparams == NULL)
    return 0;

  buf = NULL;
  len = i2d_DSAparams(dsaparams, &buf);

  DSA_free(dsaparams);

  if (len <= 0)
    return 0;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  return 1;
}

bcrypto_dsa_key_t *
bcrypto_dsa_params_import(const uint8_t *raw, size_t raw_len) {
  DSA *dsaparams = NULL;
  const uint8_t *p = raw;
  bcrypto_dsa_key_t *params = NULL;

  if (d2i_DSAparams(&dsaparams, &p, raw_len) == NULL)
    goto fail;

  params = bcrypto_dsa_params2key(dsaparams);

  if (params == NULL)
    goto fail;

#if 0
  if (!bcrypto_dsa_sane_params(params))
    goto fail;
#endif

  DSA_free(dsaparams);

  return params;

fail:
  if (dsaparams != NULL)
    DSA_free(dsaparams);

  if (params != NULL)
    bcrypto_dsa_key_free(params);

  return NULL;
}

bcrypto_dsa_key_t *
bcrypto_dsa_privkey_create(const bcrypto_dsa_key_t *params) {
  DSA *dsakey = NULL;
  bcrypto_dsa_key_t *priv = NULL;

  if (!bcrypto_dsa_sane_params(params))
    goto fail;

  dsakey = bcrypto_dsa_key2params(params);

  if (dsakey == NULL)
    goto fail;

  bcrypto_poll();

  if (!DSA_generate_key(dsakey))
    goto fail;

  priv = bcrypto_dsa_priv2key(dsakey);

  if (priv == NULL)
    goto fail;

  DSA_free(dsakey);

  return priv;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  return NULL;
}

int
bcrypto_dsa_privkey_compute(uint8_t **out,
                            size_t *out_len,
                            const bcrypto_dsa_key_t *priv) {
  BN_CTX *ctx = NULL;
  BIGNUM *p = NULL;
  BIGNUM *g = NULL;
  BIGNUM *y = NULL;
  BIGNUM *x = NULL;
  size_t size = 0;
  uint8_t *raw = NULL;

  if (!bcrypto_dsa_sane_compute(priv))
    goto fail;

  if (!bcrypto_dsa_needs_compute(priv)) {
    *out = NULL;
    out_len = 0;
    return 1;
  }

  ctx = BN_CTX_new();
  p = BN_bin2bn(priv->pd, priv->pl, NULL);
  g = BN_bin2bn(priv->gd, priv->gl, NULL);
  y = BN_new();
  x = BN_bin2bn(priv->xd, priv->xl, BN_secure_new());

  if (ctx == NULL
      || p == NULL
      || g == NULL
      || y == NULL
      || x == NULL) {
    goto fail;
  }

  if (!mod_exp_const(y, g, x, p, ctx))
    goto fail;

  size = (size_t)BN_num_bytes(y);
  raw = (uint8_t *)malloc(size);

  if (raw == NULL)
    goto fail;

  assert(BN_bn2bin(y, raw) != -1);

  BN_CTX_free(ctx);
  BN_free(p);
  BN_free(g);
  BN_free(y);
  BN_clear_free(x);

  *out = raw;
  *out_len = size;

  return 1;

fail:
  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (p != NULL)
    BN_free(p);

  if (g != NULL)
    BN_free(g);

  if (y != NULL)
    BN_free(y);

  if (x != NULL)
    BN_clear_free(x);

  return 0;
}

int
bcrypto_dsa_privkey_verify(const bcrypto_dsa_key_t *key) {
  DSA *dsakey = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *g = NULL;
  const BIGNUM *x = NULL;
  const BIGNUM *y = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *y2 = NULL;

  if (!bcrypto_dsa_sane_privkey(key))
    goto fail;

  if (!bcrypto_dsa_pubkey_verify(key))
    goto fail;

  dsakey = bcrypto_dsa_key2priv(key);

  if (dsakey == NULL)
    goto fail;

  DSA_get0_pqg(dsakey, &p, NULL, &g);
  DSA_get0_key(dsakey, &y, &x);

  assert(p != NULL && g != NULL);
  assert(y != NULL && x != NULL);

  ctx = BN_CTX_new();
  y2 = BN_new();

  if (ctx == NULL || y2 == NULL)
    goto fail;

  /* y = g^x mod p */
  if (!mod_exp_const(y2, g, x, p, ctx))
    goto fail;

  /* y2 == y1 */
  if (BN_cmp(y2, y) != 0)
    goto fail;

  DSA_free(dsakey);
  BN_CTX_free(ctx);
  BN_free(y2);

  return 1;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (y2 != NULL)
    BN_free(y2);

  return 0;
}

int
bcrypto_dsa_privkey_export(uint8_t **out,
                           size_t *out_len,
                           const bcrypto_dsa_key_t *priv) {
  DSA *dsakey = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_dsa_sane_privkey(priv))
    return 0;

  dsakey = bcrypto_dsa_key2priv(priv);

  if (dsakey == NULL)
    return 0;

  buf = NULL;
  len = i2d_DSAPrivateKey(dsakey, &buf);

  DSA_free(dsakey);

  if (len <= 0)
    return 0;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  return 1;
}

bcrypto_dsa_key_t *
bcrypto_dsa_privkey_import(const uint8_t *raw, size_t raw_len) {
  DSA *dsakey = NULL;
  const uint8_t *p = raw;
  bcrypto_dsa_key_t *key = NULL;

  if (d2i_DSAPrivateKey(&dsakey, &p, raw_len) == NULL)
    goto fail;

  key = bcrypto_dsa_priv2key(dsakey);

  if (key == NULL)
    goto fail;

#if 0
  if (!bcrypto_dsa_sane_privkey(key))
    goto fail;
#endif

  DSA_free(dsakey);

  return key;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (key != NULL)
    bcrypto_dsa_key_free(key);

  return NULL;
}

int
bcrypto_dsa_privkey_export_pkcs8(uint8_t **out,
                                 size_t *out_len,
                                 const bcrypto_dsa_key_t *priv) {
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/dsa/dsa_ameth.c#L203 */
  DSA *dsakey = NULL;
  ASN1_STRING *params = NULL;
  ASN1_INTEGER *prkey = NULL;
  unsigned char *dp = NULL;
  int dplen = 0;
  const BIGNUM *priv_key = NULL;
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_dsa_sane_privkey(priv))
    goto fail;

  dsakey = bcrypto_dsa_key2priv(priv);

  if (dsakey == NULL)
    goto fail;

  params = ASN1_STRING_new();

  if (params == NULL)
    goto fail;

  params->length = i2d_DSAparams(dsakey, &params->data);

  if (params->length <= 0)
    goto fail;

  params->type = V_ASN1_SEQUENCE;

  DSA_get0_key(dsakey, NULL, &priv_key);

  assert(priv_key != NULL);

  prkey = BN_to_ASN1_INTEGER(priv_key, NULL);

  if (prkey == NULL)
    goto fail;

  dp = NULL;
  dplen = i2d_ASN1_INTEGER(prkey, &dp);

  ASN1_STRING_clear_free(prkey);
  prkey = NULL;

  p8 = PKCS8_PRIV_KEY_INFO_new();

  if (p8 == NULL)
    goto fail;

  if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_dsa), 0,
                       V_ASN1_SEQUENCE, params, dp, dplen)) {
    goto fail;
  }

  dp = NULL;
  params = NULL;

  buf = NULL;
  len = i2d_PKCS8_PRIV_KEY_INFO(p8, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  DSA_free(dsakey);
  PKCS8_PRIV_KEY_INFO_free(p8);

  return 1;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (dp != NULL)
    OPENSSL_free(dp);

  if (params != NULL)
    ASN1_STRING_free(params);

  if (prkey != NULL)
    ASN1_STRING_clear_free(prkey);

  if (p8 != NULL)
    PKCS8_PRIV_KEY_INFO_free(p8);

  return 0;
}

bcrypto_dsa_key_t *
bcrypto_dsa_privkey_import_pkcs8(const uint8_t *raw, size_t raw_len) {
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/dsa/dsa_ameth.c#L137 */
  const unsigned char *pt = NULL;
  const unsigned char *pm = NULL;
  int pklen = 0;
  int pmlen = 0;
  int ptype = 0;
  const void *pval = NULL;
  const ASN1_STRING *pstr = NULL;
  const X509_ALGOR *palg = NULL;
  const ASN1_OBJECT *palgoid = NULL;
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  ASN1_INTEGER *privkey = NULL;
  DSA *dsakey = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *y = NULL;
  BIGNUM *x = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *g = NULL;
  bcrypto_dsa_key_t *key = NULL;
  const uint8_t *pp = raw;

  if (d2i_PKCS8_PRIV_KEY_INFO(&p8, &pp, raw_len) == NULL)
    goto fail;

  if (!PKCS8_pkey_get0(NULL, &pt, &pklen, &palg, p8))
    goto fail;

  X509_ALGOR_get0(&palgoid, &ptype, &pval, palg);

  if (OBJ_obj2nid(palgoid) != NID_dsa)
    goto fail;

  privkey = d2i_ASN1_INTEGER(NULL, &pt, pklen);

  if (privkey == NULL)
    goto fail;

  if (privkey->type == V_ASN1_NEG_INTEGER || ptype != V_ASN1_SEQUENCE)
    goto fail;

  pstr = pval;
  pm = pstr->data;
  pmlen = pstr->length;

  dsakey = d2i_DSAparams(NULL, &pm, pmlen);

  if (dsakey == NULL)
    goto fail;

  ctx = BN_CTX_new();
  y = BN_new();
  x = BN_secure_new();

  if (ctx == NULL || y == NULL || x == NULL)
    goto fail;

  if (!ASN1_INTEGER_to_BN(privkey, x))
    goto fail;

  DSA_get0_pqg(dsakey, &p, NULL, &g);

  assert(p != NULL && g != NULL);

  if (!mod_exp_const(y, g, x, p, ctx))
    goto fail;

  assert(DSA_set0_key(dsakey, y, x));

  y = NULL;
  x = NULL;

  key = bcrypto_dsa_priv2key(dsakey);

  if (key == NULL)
    goto fail;

#if 0
  if (!bcrypto_dsa_sane_privkey(key))
    goto fail;
#endif

  PKCS8_PRIV_KEY_INFO_free(p8);
  DSA_free(dsakey);
  ASN1_STRING_clear_free(privkey);
  BN_CTX_free(ctx);

  return key;

fail:
  if (p8 != NULL)
    PKCS8_PRIV_KEY_INFO_free(p8);

  if (dsakey != NULL)
    DSA_free(dsakey);

  if (privkey != NULL)
    ASN1_STRING_clear_free(privkey);

  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (y != NULL)
    BN_free(y);

  if (x != NULL)
    BN_clear_free(x);

  if (key != NULL)
    bcrypto_dsa_key_free(key);

  return NULL;
}

int
bcrypto_dsa_pubkey_verify(const bcrypto_dsa_key_t *key) {
  int ret = 0;
  DSA *dsakey = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *y = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *x = NULL;

  if (!bcrypto_dsa_params_verify(key))
    goto fail;

  if (!bcrypto_dsa_sane_pubkey(key))
    goto fail;

  dsakey = bcrypto_dsa_key2pub(key);

  if (dsakey == NULL)
    goto fail;

  DSA_get0_pqg(dsakey, &p, &q, NULL);
  DSA_get0_key(dsakey, &y, NULL);

  assert(p != NULL && q != NULL);
  assert(y != NULL);

  ctx = BN_CTX_new();

  if (ctx == NULL)
    goto fail;

  x = BN_new();

  if (x == NULL)
    goto fail;

  /* x := y^q mod p */
  if (!BN_mod_exp(x, y, q, p, ctx))
    goto fail;

  if (!BN_is_one(x))
    goto fail;

  ret = 1;
fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (x != NULL)
    BN_free(x);

  return ret;
}

int
bcrypto_dsa_pubkey_export(uint8_t **out,
                          size_t *out_len,
                          const bcrypto_dsa_key_t *pub) {
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_dsa_sane_pubkey(pub))
    return 0;

  DSA *dsakey = bcrypto_dsa_key2pub(pub);

  if (dsakey == NULL)
    return 0;

  buf = NULL;
  len = i2d_DSAPublicKey(dsakey, &buf);

  DSA_free(dsakey);

  if (len <= 0)
    return 0;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  return 1;
}

bcrypto_dsa_key_t *
bcrypto_dsa_pubkey_import(const uint8_t *raw, size_t raw_len) {
  DSA *dsakey = NULL;
  const uint8_t *p = raw;
  bcrypto_dsa_key_t *key = NULL;

  if (d2i_DSAPublicKey(&dsakey, &p, raw_len) == NULL)
    goto fail;

  key = bcrypto_dsa_pub2key(dsakey);

  if (key == NULL)
    goto fail;

#if 0
  if (!bcrypto_dsa_sane_pubkey(key))
    goto fail;
#endif

  DSA_free(dsakey);

  return key;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (key != NULL)
    bcrypto_dsa_key_free(key);

  return NULL;
}

int
bcrypto_dsa_pubkey_export_spki(uint8_t **out,
                               size_t *out_len,
                               const bcrypto_dsa_key_t *pub) {
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_dsa_sane_pubkey(pub))
    return 0;

  DSA *dsakey = bcrypto_dsa_key2pub(pub);

  if (dsakey == NULL)
    return 0;

  buf = NULL;
  len = i2d_DSA_PUBKEY(dsakey, &buf);

  DSA_free(dsakey);

  if (len <= 0)
    return 0;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  return 1;
}

bcrypto_dsa_key_t *
bcrypto_dsa_pubkey_import_spki(const uint8_t *raw, size_t raw_len) {
  DSA *dsakey = NULL;
  const uint8_t *p = raw;
  bcrypto_dsa_key_t *key = NULL;

  if (d2i_DSA_PUBKEY(&dsakey, &p, raw_len) == NULL)
    goto fail;

  key = bcrypto_dsa_pub2key(dsakey);

  if (key == NULL)
    goto fail;

#if 0
  if (!bcrypto_dsa_sane_pubkey(key))
    goto fail;
#endif

  DSA_free(dsakey);

  return key;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (key != NULL)
    bcrypto_dsa_key_free(key);

  return NULL;
}

int
bcrypto_dsa_sig_export(uint8_t **out,
                       size_t *out_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       size_t size) {
  DSA_SIG *dsasig = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  if (size == 0)
    size = sig_len >> 1;

  if (sig == NULL || sig_len != size * 2)
    goto fail;

  dsasig = bcrypto_dsa_rs2sig(sig, sig_len);

  if (dsasig == NULL)
    goto fail;

  buf = NULL;
  len = i2d_DSA_SIG(dsasig, &buf);

  if (len <= 0)
    return 0;

  FIX_BORINGSSL(buf, len);

  DSA_SIG_free(dsasig);

  *out = buf;
  *out_len = (size_t)len;

  return 1;

fail:
  if (dsasig != NULL)
    DSA_SIG_free(dsasig);

  return 0;
}

int
bcrypto_dsa_sig_import(uint8_t **out,
                       size_t *out_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       size_t size) {
  DSA_SIG *dsasig = NULL;
  const uint8_t *p = sig;
  uint8_t *raw = NULL;
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;

  if (sig == NULL || sig_len == 0)
    goto fail;

  if (d2i_DSA_SIG(&dsasig, &p, sig_len) == NULL)
    goto fail;

  DSA_SIG_get0(dsasig, &r, &s);

  assert(r != NULL && s != NULL);

  if ((size_t)BN_num_bytes(r) > size)
    goto fail;

  if ((size_t)BN_num_bytes(s) > size)
    goto fail;

  raw = (uint8_t *)malloc(size * 2);

  if (raw == NULL)
    goto fail;

  assert(BN_bn2binpad(r, &raw[0], size) > 0);
  assert(BN_bn2binpad(s, &raw[size], size) > 0);

  *out = raw;
  *out_len = size * 2;

  DSA_SIG_free(dsasig);

  return 1;

fail:
  if (dsasig != NULL)
    DSA_SIG_free(dsasig);

  return 0;
}

int
bcrypto_dsa_sign(uint8_t **out,
                 size_t *out_len,
                 const uint8_t *msg,
                 size_t msg_len,
                 const bcrypto_dsa_key_t *priv) {
  DSA *dsakey = NULL;
  DSA_SIG *dsasig = NULL;

  if (!bcrypto_dsa_sane_privkey(priv))
    goto fail;

  dsakey = bcrypto_dsa_key2priv(priv);

  if (dsakey == NULL)
    goto fail;

  bcrypto_poll();

  dsasig = DSA_do_sign(msg, msg_len, dsakey);

  if (dsasig == NULL)
    goto fail;

  if (!bcrypto_dsa_sig2rs(out, out_len, dsakey, dsasig))
    goto fail;

  DSA_free(dsakey);
  DSA_SIG_free(dsasig);

  return 1;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (dsasig != NULL)
    DSA_SIG_free(dsasig);

  return 0;
}

int
bcrypto_dsa_sign_der(uint8_t **out,
                     size_t *out_len,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_dsa_key_t *priv) {
  DSA *dsakey = NULL;
  DSA_SIG *dsasig = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  if (!bcrypto_dsa_sane_privkey(priv))
    goto fail;

  dsakey = bcrypto_dsa_key2priv(priv);

  if (dsakey == NULL)
    goto fail;

  bcrypto_poll();

  dsasig = DSA_do_sign(msg, msg_len, dsakey);

  if (dsasig == NULL)
    goto fail;

  buf = NULL;
  len = i2d_DSA_SIG(dsasig, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = len;

  DSA_free(dsakey);
  DSA_SIG_free(dsasig);

  return 1;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (dsasig != NULL)
    DSA_SIG_free(dsasig);

  return 0;
}

int
bcrypto_dsa_verify(const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len,
                   const bcrypto_dsa_key_t *pub) {
  size_t qsize = 0;
  DSA *dsakey = NULL;
  DSA_SIG *dsasig = NULL;

  qsize = bcrypto_dsa_subprime_size(pub);

  if (sig == NULL || sig_len != qsize * 2)
    goto fail;

  if (!bcrypto_dsa_sane_pubkey(pub))
    goto fail;

  dsakey = bcrypto_dsa_key2pub(pub);

  if (dsakey == NULL)
    goto fail;

  dsasig = bcrypto_dsa_rs2sig(sig, sig_len);

  if (dsasig == NULL)
    goto fail;

  if (DSA_do_verify(msg, msg_len, dsasig, dsakey) <= 0)
    goto fail;

  DSA_free(dsakey);
  DSA_SIG_free(dsasig);

  return 1;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (dsasig != NULL)
    DSA_SIG_free(dsasig);

  return 0;
}

int
bcrypto_dsa_verify_der(const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       const bcrypto_dsa_key_t *pub) {
  DSA *dsakey = NULL;
  DSA_SIG *dsasig = NULL;
  const unsigned char *p = sig;

  if (sig == NULL || sig_len == 0)
    goto fail;

  if (!bcrypto_dsa_sane_pubkey(pub))
    goto fail;

  dsakey = bcrypto_dsa_key2pub(pub);

  if (dsakey == NULL)
    goto fail;

  /* Note that openssl's DSA_verify reserializes to
     check for minimal encoding. We don't want that
     (it should be done at a higher level). */
  if (d2i_DSA_SIG(&dsasig, &p, sig_len) == NULL)
    goto fail;

  if (DSA_do_verify(msg, msg_len, dsasig, dsakey) <= 0)
    goto fail;

  DSA_free(dsakey);
  DSA_SIG_free(dsasig);

  return 1;

fail:
  if (dsakey != NULL)
    DSA_free(dsakey);

  if (dsasig != NULL)
    DSA_SIG_free(dsasig);

  return 0;
}

int
bcrypto_dsa_derive(uint8_t **out,
                   size_t *out_len,
                   const bcrypto_dsa_key_t *pub,
                   const bcrypto_dsa_key_t *priv) {
  DSA *dsapub = NULL;
  DSA *dsaprv = NULL;
  const BIGNUM *pp = NULL;
  const BIGNUM *qp = NULL;
  const BIGNUM *gp = NULL;
  const BIGNUM *yp = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *g = NULL;
  const BIGNUM *x = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *secret = NULL;
  uint8_t *raw = NULL;
  size_t size = 0;

  if (!bcrypto_dsa_sane_pubkey(pub))
    goto fail;

  if (!bcrypto_dsa_sane_privkey(priv))
    goto fail;

  dsapub = bcrypto_dsa_key2pub(pub);

  if (dsapub == NULL)
    goto fail;

  dsaprv = bcrypto_dsa_key2priv(priv);

  if (dsaprv == NULL)
    goto fail;

  DSA_get0_pqg(dsapub, &pp, &qp, &gp);
  DSA_get0_key(dsapub, &yp, NULL);

  assert(pp != NULL && qp != NULL
      && gp != NULL && yp != NULL);

  DSA_get0_pqg(dsaprv, &p, &q, &g);
  DSA_get0_key(dsaprv, NULL, &x);

  assert(p != NULL && q != NULL
      && g != NULL && x != NULL);

  if (BN_cmp(pp, p) != 0
      || BN_cmp(qp, q) != 0
      || BN_cmp(gp, g) != 0) {
    goto fail;
  }

  ctx = BN_CTX_new();

  if (ctx == NULL)
    goto fail;

  secret = BN_secure_new();

  if (secret == NULL)
    goto fail;

  if (!BN_mod_exp(secret, yp, q, p, ctx))
    goto fail;

  if (!BN_is_one(secret))
    goto fail;

  /* secret := y^x mod p */
  if (!mod_exp_const(secret, yp, x, p, ctx))
    goto fail;

  size = (size_t)BN_num_bytes(p);
  raw = (uint8_t *)malloc(size);

  if (raw == NULL)
    goto fail;

  assert(BN_bn2binpad(secret, raw, size) != -1);

  DSA_free(dsapub);
  DSA_free(dsaprv);
  BN_CTX_free(ctx);
  BN_clear_free(secret);

  *out = raw;
  *out_len = size;

  return 1;

fail:
  if (dsapub != NULL)
    DSA_free(dsapub);

  if (dsaprv != NULL)
    DSA_free(dsaprv);

  if (ctx != NULL)
    BN_CTX_free(ctx);

  if (secret != NULL)
    BN_clear_free(secret);

  if (raw != NULL)
    free(raw);

  return 0;
}

#endif
