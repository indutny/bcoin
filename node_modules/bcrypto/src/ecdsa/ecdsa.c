#include "../compat.h"

#ifdef BCRYPTO_HAS_ECDSA

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ecdsa.h"

#include "openssl/ecdsa.h"
#include "openssl/objects.h"
#include "openssl/x509.h"
#include "../random/random.h"

/*
 * Helpers
 */

static int
bcrypto_ecdsa_curve(const char *name) {
  int type = -1;

  if (name == NULL)
    return type;

  if (strcmp(name, "P192") == 0)
    type = NID_X9_62_prime192v1;
  else if (strcmp(name, "P224") == 0)
    type = NID_secp224r1;
  else if (strcmp(name, "P256") == 0)
    type = NID_X9_62_prime256v1;
  else if (strcmp(name, "P384") == 0)
    type = NID_secp384r1;
  else if (strcmp(name, "P521") == 0)
    type = NID_secp521r1;
  else if (strcmp(name, "SECP192K1") == 0)
    type = NID_secp192k1;
  else if (strcmp(name, "SECP224K1") == 0)
    type = NID_secp224k1;
  else if (strcmp(name, "SECP256K1") == 0)
    type = NID_secp256k1;
  else if (strcmp(name, "BRAINPOOLP256") == 0)
    type = NID_brainpoolP256r1;
  else if (strcmp(name, "BRAINPOOLP384") == 0)
    type = NID_brainpoolP384r1;
  else if (strcmp(name, "BRAINPOOLP512") == 0)
    type = NID_brainpoolP512r1;

  return type;
}

static int
bcrypto_ecdsa_hash_type(int type) {
  switch (type) {
    case NID_X9_62_prime192v1:
    case NID_secp224r1:
    case NID_X9_62_prime256v1:
    case NID_secp192k1:
    case NID_secp224k1:
    case NID_secp256k1:
    case NID_brainpoolP256r1:
      return NID_sha256;
    case NID_secp384r1:
    case NID_brainpoolP384r1:
      return NID_sha384;
    case NID_secp521r1:
    case NID_brainpoolP512r1:
      return NID_sha512;
  }
  return -1;
}

static int
bcrypto_ecdsa_has_schnorr(int type) {
  switch (type) {
    case NID_X9_62_prime192v1:
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
    case NID_secp521r1:
    case NID_secp192k1:
    case NID_secp256k1:
    case NID_brainpoolP256r1:
    case NID_brainpoolP384r1:
    case NID_brainpoolP512r1:
      return 1;
  }
  return 0;
}

static int
bcrypto_ecdsa_uniform_type(int type) {
  switch (type) {
    case NID_X9_62_prime192v1:
      return BCRYPTO_ECDSA_ICART;
    case NID_secp224r1:
      return BCRYPTO_ECDSA_SSWU;
    case NID_X9_62_prime256v1:
      return BCRYPTO_ECDSA_SSWU;
    case NID_secp384r1:
      return BCRYPTO_ECDSA_ICART;
    case NID_secp521r1:
      return BCRYPTO_ECDSA_SSWU;
    case NID_secp192k1:
      return BCRYPTO_ECDSA_SVDW;
    case NID_secp224k1:
      return BCRYPTO_ECDSA_SVDW;
    case NID_secp256k1:
      return BCRYPTO_ECDSA_SVDW;
    case NID_brainpoolP256r1:
      return BCRYPTO_ECDSA_ICART;
    case NID_brainpoolP384r1:
      return BCRYPTO_ECDSA_SSWU;
    case NID_brainpoolP512r1:
      return BCRYPTO_ECDSA_ICART;
  }
  return -1;
}

static int
bcrypto_ecdsa_uniform_z(int type) {
  switch (type) {
    case NID_X9_62_prime192v1:
      return -5;
    case NID_secp224r1:
      return 31;
    case NID_X9_62_prime256v1:
      return -10;
    case NID_secp384r1:
      return -12;
    case NID_secp521r1:
      return -4;
    case NID_secp192k1:
      return 1;
    case NID_secp224k1:
      return -1;
    case NID_secp256k1:
      return 1;
    case NID_brainpoolP256r1:
      return -2;
    case NID_brainpoolP384r1:
      return -5;
    case NID_brainpoolP512r1:
      return 7;
  }
  return 0;
}

static int
bcrypto_ecdsa_valid_scalar(bcrypto_ecdsa_t *ec, const uint8_t *scalar) {
  if (scalar == NULL)
    return 0;

  return memcmp(scalar, ec->zero, ec->scalar_size) != 0
      && memcmp(scalar, ec->order, ec->scalar_size) < 0;
}

static int
bcrypto_ecdsa_valid_point(bcrypto_ecdsa_t *ec,
                          const uint8_t *raw,
                          size_t raw_len) {
  if (raw == NULL)
    return 0;

  if (raw_len < 1 + ec->size)
    return 0;

  switch (raw[0]) {
    case 0x02:
    case 0x03:
      return raw_len == 1 + ec->size;
    case 0x04:
      return raw_len == 1 + ec->size * 2;
    case 0x06:
    case 0x07:
      return raw_len == 1 + ec->size * 2
          && (raw[0] & 1) == (raw[raw_len - 1] & 1);
    default:
      return 0;
  }
}

/*
 * Public Key
 */

static int
bcrypto_ecdsa_pubkey_from_ec_point(bcrypto_ecdsa_t *ec,
                                   bcrypto_ecdsa_pubkey_t *pub,
                                   const EC_POINT *point);

void
bcrypto_ecdsa_pubkey_encode(bcrypto_ecdsa_t *ec,
                            uint8_t *out,
                            size_t *out_len,
                            const bcrypto_ecdsa_pubkey_t *pub,
                            int compress) {
  if (compress) {
    out[0] = 0x02 | (pub->y[ec->size - 1] & 1);
    memcpy(&out[1], &pub->x[0], ec->size);
    *out_len = 1 + ec->size;
  } else {
    out[0] = 0x04;
    memcpy(&out[1], &pub->x[0], ec->size);
    memcpy(&out[1 + ec->size], &pub->y[0], ec->size);
    *out_len = 1 + ec->size * 2;
  }
}

int
bcrypto_ecdsa_pubkey_decode(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *pub,
                            const uint8_t *raw,
                            size_t raw_len) {
  if (!bcrypto_ecdsa_valid_point(ec, raw, raw_len))
    return 0;

  if (!EC_POINT_oct2point(ec->group, ec->point, raw, raw_len, ec->ctx))
    return 0;

  if (raw[0] >= 0x04) {
    if (EC_POINT_is_on_curve(ec->group, ec->point, ec->ctx) <= 0)
      return 0;
  }

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, pub, ec->point))
    return 0;

  return 1;
}

static EC_POINT *
bcrypto_ecdsa_pubkey_to_ec_point(bcrypto_ecdsa_t *ec,
                                 const bcrypto_ecdsa_pubkey_t *pub) {
  EC_POINT *point = NULL;
  uint8_t raw[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t raw_len = 0;

  point = EC_POINT_new(ec->group);

  if (point == NULL)
    goto fail;

  bcrypto_ecdsa_pubkey_encode(ec, raw, &raw_len, pub, 0);

  if (!EC_POINT_oct2point(ec->group, point, raw, raw_len, ec->ctx))
    goto fail;

  return point;

fail:
  if (point != NULL)
    EC_POINT_free(point);

  return NULL;
}

static EC_KEY *
bcrypto_ecdsa_pubkey_to_ec_key(bcrypto_ecdsa_t *ec,
                               const bcrypto_ecdsa_pubkey_t *pub) {
  EC_KEY *key = NULL;
  uint8_t raw[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t raw_len = 0;

  key = EC_KEY_new_by_curve_name(ec->type);

  if (key == NULL)
    goto fail;

  bcrypto_ecdsa_pubkey_encode(ec, raw, &raw_len, pub, 0);

  if (!EC_KEY_oct2key(key, raw, raw_len, ec->ctx))
    goto fail;

  return key;

fail:
  if (key != NULL)
    EC_KEY_free(key);

  return NULL;
}

static int
bcrypto_ecdsa_pubkey_from_ec_point(bcrypto_ecdsa_t *ec,
                                   bcrypto_ecdsa_pubkey_t *pub,
                                   const EC_POINT *point) {
  point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
  uint8_t raw[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t raw_len = 0;

  if (EC_POINT_is_at_infinity(ec->group, point))
    return 0;

  raw_len = EC_POINT_point2oct(ec->group, point, form, raw,
                               BCRYPTO_ECDSA_MAX_PUB_SIZE, ec->ctx);

  if (raw_len != 1 + ec->size * 2)
    return 0;

  assert(raw[0] == 0x04);

  memcpy(&pub->x[0], &raw[1], ec->size);
  memcpy(&pub->y[0], &raw[1 + ec->size], ec->size);

  return 1;
}

static int
bcrypto_ecdsa_pubkey_from_ec_key(bcrypto_ecdsa_t *ec,
                                 bcrypto_ecdsa_pubkey_t *pub,
                                 const EC_KEY *key) {
  const EC_POINT *point = EC_KEY_get0_public_key(key);
  assert(point != NULL);

  return bcrypto_ecdsa_pubkey_from_ec_point(ec, pub, point);
}

static int
bcrypto_ecdsa_pubkey_equals(bcrypto_ecdsa_t *ec,
                            const bcrypto_ecdsa_pubkey_t *a,
                            const bcrypto_ecdsa_pubkey_t *b) {
  return memcmp(a->x, b->x, ec->size) == 0
      && memcmp(a->y, b->y, ec->size) == 0;
}

/*
 * Signature
 */

void
bcrypto_ecdsa_sig_encode(bcrypto_ecdsa_t *ec,
                         uint8_t *out,
                         const bcrypto_ecdsa_sig_t *sig) {
  memcpy(&out[0], &sig->r[0], ec->scalar_size);
  memcpy(&out[ec->scalar_size], &sig->s[0], ec->scalar_size);
}

int
bcrypto_ecdsa_sig_decode(bcrypto_ecdsa_t *ec,
                         bcrypto_ecdsa_sig_t *sig,
                         const uint8_t *raw) {
  memcpy(&sig->r[0], &raw[0], ec->scalar_size);
  memcpy(&sig->s[0], &raw[ec->scalar_size], ec->scalar_size);

  return memcmp(sig->r, ec->zero, ec->scalar_size) != 0
      && memcmp(sig->s, ec->zero, ec->scalar_size) != 0
      && memcmp(sig->r, ec->order, ec->scalar_size) < 0
      && memcmp(sig->s, ec->order, ec->scalar_size) < 0;
}

int
bcrypto_ecdsa_sig_encode_der(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             size_t *out_len,
                             const bcrypto_ecdsa_sig_t *sig) {
  assert(ec->scalar_size < 0x7d);

  uint8_t r[1 + BCRYPTO_ECDSA_MAX_SCALAR_SIZE] = {0};
  uint8_t *rp = (uint8_t *)&sig->r[0];
  size_t rlen = ec->scalar_size;
  uint8_t s[1 + BCRYPTO_ECDSA_MAX_SCALAR_SIZE] = {0};
  uint8_t *sp = (uint8_t *)&sig->s[0];
  size_t slen = ec->scalar_size;

  while (rlen > 1 && rp[0] == 0)
    rlen--, rp++;

  while (slen > 1 && sp[0] == 0)
    slen--, sp++;

  size_t rn = (rp[0] & 0x80) ? 1 : 0;
  size_t sn = (sp[0] & 0x80) ? 1 : 0;

  memcpy(r + rn, rp, rlen);
  memcpy(s + sn, sp, slen);

  rlen += rn;
  slen += sn;

  size_t seq = 2 + rlen + 2 + slen;
  size_t wide = seq >= 0x80 ? 1 : 0;
  size_t len = 2 + wide + seq;

  if (len > *out_len)
    return 0;

  *(out++) = 0x30;

  if (wide)
    *(out++) = 0x81;

  *(out++) = seq;
  *(out++) = 0x02;
  *(out++) = rlen;

  memcpy(out, r, rlen);
  out += rlen;

  *(out++) = 0x02;
  *(out++) = slen;

  memcpy(out, s, slen);
  out += slen;

  *out_len = len;

  return 1;
}

int
bcrypto_ecdsa_sig_decode_der(bcrypto_ecdsa_t *ec,
                             bcrypto_ecdsa_sig_t *sig,
                             const uint8_t *raw,
                             size_t raw_len) {
  size_t rpos, rlen, spos, slen;
  size_t pos = 0;
  size_t lenbyte;
  int overflow = 0;

  memset(sig->r, 0x00, ec->scalar_size);
  memset(sig->s, 0x00, ec->scalar_size);

  /* Sequence tag byte */
  if (pos == raw_len || raw[pos] != 0x30)
    return 0;

  pos++;

  /* Sequence length bytes */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    pos += lenbyte;
  }

  /* Integer tag byte for R */
  if (pos == raw_len || raw[pos] != 0x02)
    return 0;

  pos++;

  /* Integer length for R */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    while (lenbyte > 0 && raw[pos] == 0) {
      pos++;
      lenbyte--;
    }

    if (lenbyte >= sizeof(size_t))
      return 0;

    rlen = 0;

    while (lenbyte > 0) {
      rlen = (rlen << 8) + raw[pos];
      pos++;
      lenbyte--;
    }
  } else {
    rlen = lenbyte;
  }

  if (rlen > raw_len - pos)
    return 0;

  rpos = pos;
  pos += rlen;

  /* Integer tag byte for S */
  if (pos == raw_len || raw[pos] != 0x02)
    return 0;

  pos++;

  /* Integer length for S */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    while (lenbyte > 0 && raw[pos] == 0) {
      pos++;
      lenbyte--;
    }

    if (lenbyte >= sizeof(size_t))
      return 0;

    slen = 0;

    while (lenbyte > 0) {
      slen = (slen << 8) + raw[pos];
      pos++;
      lenbyte--;
    }
  } else {
    slen = lenbyte;
  }

  if (slen > raw_len - pos)
    return 0;

  spos = pos;
  pos += slen;

  /* Ignore leading zeroes in R */
  while (rlen > 0 && raw[rpos] == 0) {
    rlen--;
    rpos++;
  }

  /* Copy R value */
  if (rlen > ec->scalar_size)
    overflow = 1;
  else
    memcpy(sig->r + ec->scalar_size - rlen, raw + rpos, rlen);

  /* Ignore leading zeroes in S */
  while (slen > 0 && raw[spos] == 0) {
    slen--;
    spos++;
  }

  /* Copy S value */
  if (slen > ec->scalar_size)
    overflow = 1;
  else
    memcpy(sig->s + ec->scalar_size - slen, raw + spos, slen);

  if (!overflow) {
    overflow = memcmp(sig->r, ec->order, ec->scalar_size) >= 0
            || memcmp(sig->s, ec->order, ec->scalar_size) >= 0;
  }

  if (overflow) {
    memset(sig->r, 0x00, ec->scalar_size);
    memset(sig->s, 0x00, ec->scalar_size);
  }

  return 1;
}

static ECDSA_SIG *
bcrypto_ecdsa_sig_to_ecdsa_sig(bcrypto_ecdsa_t *ec,
                               const bcrypto_ecdsa_sig_t *sig) {
  ECDSA_SIG *ecsig = NULL;
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;

  ecsig = ECDSA_SIG_new();

  if (ecsig == NULL)
    goto fail;

  r = BN_bin2bn(sig->r, ec->scalar_size, NULL);

  if (r == NULL)
    goto fail;

  s = BN_bin2bn(sig->s, ec->scalar_size, NULL);

  if (s == NULL)
    goto fail;

  if (BN_is_zero(r) || BN_cmp(r, ec->n) >= 0)
    goto fail;

  if (BN_is_zero(s) || BN_cmp(s, ec->n) >= 0)
    goto fail;

  if (!ECDSA_SIG_set0(ecsig, r, s))
    goto fail;

  return ecsig;

fail:
  if (ecsig != NULL)
    ECDSA_SIG_free(ecsig);

  if (r != NULL)
    BN_free(r);

  if (s != NULL)
    BN_free(s);

  return NULL;
}

static void
bcrypto_ecdsa_sig_from_ecdsa_sig(
  bcrypto_ecdsa_t *ec,
  bcrypto_ecdsa_sig_t *sig,
  const ECDSA_SIG *ecsig
) {
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;

  ECDSA_SIG_get0(ecsig, &r, &s);

  assert(r != NULL && s != NULL);

  assert((size_t)BN_num_bytes(r) <= ec->scalar_size);
  assert((size_t)BN_num_bytes(s) <= ec->scalar_size);

  assert(BN_bn2binpad(r, sig->r, ec->scalar_size) > 0);
  assert(BN_bn2binpad(s, sig->s, ec->scalar_size) > 0);
}

void
bcrypto_ecdsa_sig_normalize(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_sig_t *out,
                            const bcrypto_ecdsa_sig_t *sig) {
  memcpy(out, sig, sizeof(bcrypto_ecdsa_sig_t));

  if (memcmp(out->s, ec->half, ec->scalar_size) <= 0)
    return;

  int carry = 0;
  int i, r;

  for (i = ec->scalar_size - 1; i >= 0; i--) {
    r = (int)ec->order[i] - (int)out->s[i] + carry;
    carry = r >> 8;
    out->s[i] = r & 0xff;
  }

  assert(carry == 0);
}

int
bcrypto_ecdsa_sig_is_low_s(bcrypto_ecdsa_t *ec,
                           const bcrypto_ecdsa_sig_t *sig) {
  return memcmp(sig->s, ec->zero, ec->scalar_size) != 0
      && memcmp(sig->s, ec->half, ec->scalar_size) <= 0;
}

/*
 * ECDSA
 */

int
bcrypto_ecdsa_init(bcrypto_ecdsa_t *ec, const char *name) {
  assert(ec != NULL && name != NULL);
  memset(ec, 0x00, sizeof(bcrypto_ecdsa_t));

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    return 0;

  EC_KEY *key = EC_KEY_new_by_curve_name(type);

  if (key == NULL)
    return 0;

  ec->type = type;

  ec->hash_type = bcrypto_ecdsa_hash_type(type);
  assert(ec->hash_type != -1);

  ec->hash = EVP_get_digestbynid(ec->hash_type);
  assert(ec->hash != NULL);

  ec->hash_size = EVP_MD_size(ec->hash);

  ec->has_schnorr = bcrypto_ecdsa_has_schnorr(ec->type);

  ec->ctx = BN_CTX_new();
  assert(ec->ctx != NULL);

  ec->key = key;

  ec->group = EC_KEY_get0_group(ec->key);
  assert(ec->group != NULL);

  ec->point = EC_POINT_new(ec->group);
  assert(ec->point != NULL);

  ec->bits = (size_t)EC_GROUP_get_degree(ec->group);
  ec->size = (ec->bits + 7) / 8;
  assert(ec->size <= BCRYPTO_ECDSA_MAX_FIELD_SIZE);

  ec->n = BN_new();
  ec->nh = BN_new();
  ec->ns1 = BN_new();
  ec->p = BN_new();
  ec->a = BN_new();
  ec->b = BN_new();
  ec->one = BN_new();
  ec->two = BN_new();
  ec->three = BN_new();

  assert(ec->n != NULL);
  assert(ec->nh != NULL);
  assert(ec->ns1 != NULL);
  assert(ec->p != NULL);
  assert(ec->a != NULL);
  assert(ec->b != NULL);
  assert(ec->one != NULL);
  assert(ec->two != NULL);
  assert(ec->three != NULL);

  assert(EC_GROUP_get_order(ec->group, ec->n, ec->ctx) != 0);
  assert(BN_rshift1(ec->nh, ec->n) != 0);
  assert(BN_sub(ec->ns1, ec->n, BN_value_one()) != 0);

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  assert(EC_GROUP_get_curve(ec->group, ec->p, ec->a, ec->b, ec->ctx) != 0);
#else
  assert(EC_GROUP_get_curve_GFp(ec->group, ec->p, ec->a, ec->b, ec->ctx) != 0);
#endif

  assert(BN_set_word(ec->one, 1) != 0);
  assert(BN_set_word(ec->two, 2) != 0);
  assert(BN_set_word(ec->three, 3) != 0);

  ec->g = EC_GROUP_get0_generator(ec->group);
  assert(ec->g != NULL);

  ec->scalar_bits = (size_t)BN_num_bits(ec->n);
  ec->scalar_size = (ec->scalar_bits + 7) >> 3;
  ec->sig_size = ec->scalar_size * 2;
  ec->schnorr_size = ec->size + ec->scalar_size;

  assert(ec->scalar_size <= BCRYPTO_ECDSA_MAX_SCALAR_SIZE);

  assert(BN_bn2binpad(ec->p, &ec->prime[0], ec->size) > 0);
  memset(&ec->zero[0], 0x00, ec->scalar_size);
  assert(BN_bn2binpad(ec->n, &ec->order[0], ec->scalar_size) > 0);
  assert(BN_bn2binpad(ec->nh, &ec->half[0], ec->scalar_size) > 0);

  ec->initialized = 1;

  return 1;
}

void
bcrypto_ecdsa_uninit(bcrypto_ecdsa_t *ec) {
  assert(ec != NULL);

  if (!ec->initialized)
    return;

  BN_CTX_free(ec->ctx);
  EC_KEY_free(ec->key);
  EC_POINT_free(ec->point);
  BN_free(ec->n);
  BN_free(ec->nh);
  BN_free(ec->ns1);
  BN_free(ec->p);
  BN_free(ec->a);
  BN_free(ec->b);
  BN_free(ec->one);
  BN_free(ec->two);
  BN_free(ec->three);

  ec->ctx = NULL;
  ec->key = NULL;
  ec->group = NULL;
  ec->point = NULL;
  ec->n = NULL;
  ec->nh = NULL;
  ec->ns1 = NULL;
  ec->p = NULL;
  ec->a = NULL;
  ec->b = NULL;
  ec->one = NULL;
  ec->two = NULL;
  ec->three = NULL;
  ec->g = NULL;
  ec->initialized = 0;
}

int
bcrypto_ecdsa_privkey_generate(bcrypto_ecdsa_t *ec, uint8_t *priv) {
  do {
    if (!bcrypto_random(priv, ec->scalar_size))
      return 0;
  } while (!bcrypto_ecdsa_valid_scalar(ec, priv));

  return 1;
}

int
bcrypto_ecdsa_privkey_verify(bcrypto_ecdsa_t *ec, const uint8_t *priv) {
  return bcrypto_ecdsa_valid_scalar(ec, priv);
}

int
bcrypto_ecdsa_privkey_export(bcrypto_ecdsa_t *ec,
                             uint8_t **out,
                             size_t *out_len,
                             const uint8_t *priv,
                             int flags) {
  EC_KEY *eckey = NULL;
  EC_POINT *point = NULL;
  const BIGNUM *scalar = NULL;
  uint8_t *buf = NULL;
  int compress = flags & 1;
  int no_params = (flags >> 1) & 1;
  int len = 0;

  if (!bcrypto_ecdsa_valid_scalar(ec, priv))
    goto fail;

  eckey = EC_KEY_new_by_curve_name(ec->type);

  if (eckey == NULL)
    goto fail;

  if (!EC_KEY_oct2priv(eckey, priv, ec->scalar_size))
    goto fail;

  point = EC_POINT_new(ec->group);

  if (point == NULL)
    goto fail;

  scalar = EC_KEY_get0_private_key(eckey);
  assert(scalar != NULL);

  if (!EC_POINT_mul(ec->group, point, scalar, NULL, NULL, ec->ctx))
    goto fail;

  if (!EC_KEY_set_public_key(eckey, point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  EC_KEY_set_conv_form(eckey, form);

  if (no_params) {
    EC_KEY_set_enc_flags(eckey,
      EC_KEY_get_enc_flags(eckey) | EC_PKEY_NO_PARAMETERS);
  }

  EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

  buf = NULL;
  len = i2d_ECPrivateKey(eckey, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  EC_KEY_free(eckey);
  EC_POINT_free(point);

  return 1;

fail:
  if (eckey != NULL)
    EC_KEY_free(eckey);

  if (point != NULL)
    EC_POINT_free(point);

  return 0;
}

int
bcrypto_ecdsa_privkey_import(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *raw,
                             size_t raw_len) {
  EC_KEY *eckey = NULL;
  const BIGNUM *scalar = NULL;
  const uint8_t *p = raw;

  eckey = EC_KEY_new_by_curve_name(ec->type);

  if (eckey == NULL)
    goto fail;

  EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

  if (d2i_ECPrivateKey(&eckey, &p, raw_len) == NULL)
    goto fail;

  scalar = EC_KEY_get0_private_key(eckey);
  assert(scalar != NULL);

  if (BN_is_zero(scalar) || BN_cmp(scalar, ec->n) >= 0)
    goto fail;

  assert((size_t)BN_num_bytes(scalar) <= ec->scalar_size);

  assert(BN_bn2binpad(scalar, out, ec->scalar_size) > 0);

  EC_KEY_free(eckey);

  return 1;

fail:
  if (eckey != NULL)
    EC_KEY_free(eckey);

  return 0;
}

int
bcrypto_ecdsa_privkey_export_pkcs8(bcrypto_ecdsa_t *ec,
                                   uint8_t **out,
                                   size_t *out_len,
                                   const uint8_t *priv,
                                   int compress) {
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/ec/ec_ameth.c#L217 */
  uint8_t *ep = NULL;
  size_t eplen = 0;
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  uint8_t *buf = NULL;
  int flags = compress | 2;
  int len = 0;

  if (!bcrypto_ecdsa_privkey_export(ec, &ep, &eplen, priv, flags))
    goto fail;

  p8 = PKCS8_PRIV_KEY_INFO_new();

  if (p8 == NULL)
    goto fail;

  if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), 0,
                       V_ASN1_OBJECT, OBJ_nid2obj(ec->type), ep, (int)eplen)) {
    goto fail;
  }

  ep = NULL;

  buf = NULL;
  len = i2d_PKCS8_PRIV_KEY_INFO(p8, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  PKCS8_PRIV_KEY_INFO_free(p8);

  return 1;

fail:
  if (ep != NULL)
    OPENSSL_free(ep);

  if (p8 != NULL)
    PKCS8_PRIV_KEY_INFO_free(p8);

  return 0;
}

int
bcrypto_ecdsa_privkey_import_pkcs8(bcrypto_ecdsa_t *ec,
                                   uint8_t *out,
                                   const uint8_t *raw,
                                   size_t raw_len) {
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/ec/ec_ameth.c#L184 */
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  const unsigned char *p = NULL;
  const void *pval = NULL;
  int ptype = 0;
  int pklen = 0;
  const X509_ALGOR *palg = NULL;
  const ASN1_OBJECT *palgoid = NULL;
  const uint8_t *pp = raw;

  if (d2i_PKCS8_PRIV_KEY_INFO(&p8, &pp, raw_len) == NULL)
    goto fail;

  if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
    goto fail;

  X509_ALGOR_get0(&palgoid, &ptype, &pval, palg);

  if (OBJ_obj2nid(palgoid) != NID_X9_62_id_ecPublicKey)
    goto fail;

  if (ptype == V_ASN1_OBJECT) {
    if (OBJ_obj2nid(pval) != ec->type)
      goto fail;
  } else if (ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL) {
    goto fail;
  }

  if (!bcrypto_ecdsa_privkey_import(ec, out, p, pklen))
    goto fail;

  PKCS8_PRIV_KEY_INFO_free(p8);

  return 1;

fail:
  if (p8 != NULL)
    PKCS8_PRIV_KEY_INFO_free(p8);

  return 0;
}

int
bcrypto_ecdsa_privkey_tweak_add(bcrypto_ecdsa_t *ec,
                                uint8_t *out,
                                const uint8_t *priv,
                                const uint8_t *tweak) {
  BIGNUM *scalar = NULL;
  BIGNUM *tweak_bn = NULL;

  scalar = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());

  if (scalar == NULL)
    goto fail;

  if (BN_is_zero(scalar) || BN_cmp(scalar, ec->n) >= 0)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, ec->scalar_size, BN_secure_new());

  if (tweak_bn == NULL)
    goto fail;

  if (BN_cmp(tweak_bn, ec->n) >= 0)
    goto fail;

  if (!BN_mod_add(scalar, scalar, tweak_bn, ec->n, ec->ctx))
    goto fail;

  if (BN_is_zero(scalar))
    goto fail;

  assert((size_t)BN_num_bytes(scalar) <= ec->scalar_size);

  assert(BN_bn2binpad(scalar, out, ec->scalar_size) > 0);

  BN_clear_free(scalar);
  BN_clear_free(tweak_bn);

  return 1;

fail:
  if (scalar != NULL)
    BN_clear_free(scalar);

  if (tweak_bn != NULL)
    BN_clear_free(tweak_bn);

  return 0;
}

int
bcrypto_ecdsa_privkey_tweak_mul(bcrypto_ecdsa_t *ec,
                                uint8_t *out,
                                const uint8_t *priv,
                                const uint8_t *tweak) {
  BIGNUM *scalar = NULL;
  BIGNUM *tweak_bn = NULL;

  scalar = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());

  if (scalar == NULL)
    goto fail;

  if (BN_is_zero(scalar) || BN_cmp(scalar, ec->n) >= 0)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, ec->scalar_size, BN_secure_new());

  if (tweak_bn == NULL)
    goto fail;

  if (BN_is_zero(tweak_bn) || BN_cmp(tweak_bn, ec->n) >= 0)
    goto fail;

  if (!BN_mod_mul(scalar, scalar, tweak_bn, ec->n, ec->ctx))
    goto fail;

  if (BN_is_zero(scalar))
    goto fail;

  assert((size_t)BN_num_bytes(scalar) <= ec->scalar_size);

  assert(BN_bn2binpad(scalar, out, ec->scalar_size) > 0);

  BN_clear_free(scalar);
  BN_clear_free(tweak_bn);

  return 1;

fail:
  if (scalar != NULL)
    BN_clear_free(scalar);

  if (tweak_bn != NULL)
    BN_clear_free(tweak_bn);

  return 0;
}

int
bcrypto_ecdsa_privkey_reduce(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *priv,
                             size_t priv_len) {
  BIGNUM *scalar = NULL;

  if (priv_len > ec->scalar_size)
    priv_len = ec->scalar_size;

  scalar = BN_bin2bn(priv, priv_len, BN_secure_new());

  if (scalar == NULL)
    goto fail;

  if (!BN_mod(scalar, scalar, ec->n, ec->ctx))
    goto fail;

  if (BN_is_zero(scalar))
    goto fail;

  assert((size_t)BN_num_bytes(scalar) <= ec->scalar_size);

  assert(BN_bn2binpad(scalar, out, ec->scalar_size) > 0);

  BN_clear_free(scalar);

  return 1;

fail:
  if (scalar != NULL)
    BN_clear_free(scalar);

  return 0;
}

int
bcrypto_ecdsa_privkey_negate(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *priv) {
  BIGNUM *scalar = NULL;

  scalar = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());

  if (scalar == NULL)
    goto fail;

  if (BN_cmp(scalar, ec->n) >= 0)
    goto fail;

  if (!BN_mod_sub(scalar, ec->n, scalar, ec->n, ec->ctx))
    goto fail;

  assert((size_t)BN_num_bytes(scalar) <= ec->scalar_size);

  assert(BN_bn2binpad(scalar, out, ec->scalar_size) > 0);

  BN_clear_free(scalar);

  return 1;

fail:
  if (scalar != NULL)
    BN_clear_free(scalar);

  return 0;
}

int
bcrypto_ecdsa_privkey_invert(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *priv) {
  BIGNUM *scalar = NULL;

  scalar = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());

  if (scalar == NULL)
    goto fail;

  if (BN_is_zero(scalar) || BN_cmp(scalar, ec->n) >= 0)
    goto fail;

  if (!BN_mod_inverse(scalar, scalar, ec->n, ec->ctx))
    goto fail;

  assert((size_t)BN_num_bytes(scalar) <= ec->scalar_size);

  assert(BN_bn2binpad(scalar, out, ec->scalar_size) > 0);

  BN_clear_free(scalar);

  return 1;

fail:
  if (scalar != NULL)
    BN_clear_free(scalar);

  return 0;
}

int
bcrypto_ecdsa_pubkey_create(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *pub,
                            const uint8_t *priv) {
  BIGNUM *scalar = NULL;
  EC_POINT *point = NULL;

  scalar = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());

  if (scalar == NULL)
    goto fail;

  if (BN_is_zero(scalar) || BN_cmp(scalar, ec->n) >= 0)
    goto fail;

  point = EC_POINT_new(ec->group);

  if (point == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, point, scalar, NULL, NULL, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, pub, point))
    goto fail;

  BN_clear_free(scalar);
  EC_POINT_free(point);

  return 1;

fail:
  if (scalar != NULL)
    BN_clear_free(scalar);

  if (point != NULL)
    EC_POINT_free(point);

  return 0;
}

static EC_POINT *
bcrypto_ecdsa_point_from_uniform(bcrypto_ecdsa_t *ec, const BIGNUM *u);

int
bcrypto_ecdsa_pubkey_from_uniform(bcrypto_ecdsa_t *ec,
                                  bcrypto_ecdsa_pubkey_t *out,
                                  const uint8_t *bytes) {
  BIGNUM *u = NULL;
  EC_POINT *P = NULL;

  u = BN_bin2bn(bytes, ec->size, BN_secure_new());

  if (u == NULL)
    goto fail;

  if ((size_t)BN_num_bits(u) > ec->bits) {
    if (!BN_mask_bits(u, ec->bits))
      goto fail;
  }

  if (!BN_mod(u, u, ec->p, ec->ctx))
    goto fail;

  P = bcrypto_ecdsa_point_from_uniform(ec, u);

  if (P == NULL)
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, P))
    goto fail;

  BN_clear_free(u);
  EC_POINT_clear_free(P);

  return 1;

fail:
  if (u != NULL)
    BN_clear_free(u);

  if (P != NULL)
    EC_POINT_clear_free(P);

  return 0;
}

static BIGNUM *
bcrypto_ecdsa_point_to_uniform(bcrypto_ecdsa_t *ec,
                               const EC_POINT *P,
                               unsigned int hint);

int
bcrypto_ecdsa_pubkey_to_uniform(bcrypto_ecdsa_t *ec,
                                uint8_t *bytes,
                                const bcrypto_ecdsa_pubkey_t *pub,
                                unsigned int hint) {
  EC_POINT *P = NULL;
  BIGNUM *u = NULL;

  P = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);

  if (P == NULL)
    goto fail;

  u = bcrypto_ecdsa_point_to_uniform(ec, P, hint);

  if (u == NULL)
    goto fail;

  assert(BN_bn2binpad(u, bytes, ec->size) != -1);

  if (ec->bits & 7) {
    size_t fill = 8 - (ec->bits & 7);
    unsigned char r;

    if (!bcrypto_random(&r, sizeof(unsigned char)))
      goto fail;

    r &= (1 << fill) - 1;
    r <<= ec->bits & 7;

    bytes[0] |= r;
  }

  EC_POINT_clear_free(P);
  BN_clear_free(u);

  return 1;
fail:
  if (P != NULL)
    EC_POINT_clear_free(P);

  if (u != NULL)
    BN_clear_free(u);

  return 0;
}

int
bcrypto_ecdsa_pubkey_from_hash(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_pubkey_t *out,
                               const uint8_t *bytes) {
  BIGNUM *u1 = NULL;
  BIGNUM *u2 = NULL;
  EC_POINT *P1 = NULL;
  EC_POINT *P2 = NULL;

  u1 = BN_bin2bn(bytes, ec->size, BN_secure_new());

  if (u1 == NULL)
    goto fail;

  if ((size_t)BN_num_bits(u1) > ec->bits) {
    if (!BN_mask_bits(u1, ec->bits))
      goto fail;
  }

  if (!BN_mod(u1, u1, ec->p, ec->ctx))
    goto fail;

  u2 = BN_bin2bn(bytes + ec->size, ec->size, BN_secure_new());

  if (u2 == NULL)
    goto fail;

  if ((size_t)BN_num_bits(u2) > ec->bits) {
    if (!BN_mask_bits(u2, ec->bits))
      goto fail;
  }

  if (!BN_mod(u2, u2, ec->p, ec->ctx))
    goto fail;

  P1 = bcrypto_ecdsa_point_from_uniform(ec, u1);

  if (P1 == NULL)
    goto fail;

  P2 = bcrypto_ecdsa_point_from_uniform(ec, u2);

  if (P2 == NULL)
    goto fail;

  if (!EC_POINT_add(ec->group, P1, P1, P2, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, P1))
    goto fail;

  BN_clear_free(u1);
  BN_clear_free(u2);
  EC_POINT_clear_free(P1);
  EC_POINT_clear_free(P2);

  return 1;

fail:
  if (u1 != NULL)
    BN_clear_free(u1);

  if (u2 != NULL)
    BN_clear_free(u2);

  if (P1 != NULL)
    EC_POINT_clear_free(P1);

  if (P2 != NULL)
    EC_POINT_clear_free(P2);

  return 0;
}

int
bcrypto_ecdsa_pubkey_to_hash(bcrypto_ecdsa_t *ec,
                             uint8_t *bytes,
                             const bcrypto_ecdsa_pubkey_t *pub) {
  EC_POINT *P = NULL;
  EC_POINT *P1 = NULL;
  EC_POINT *P2 = NULL;
  BIGNUM *u1 = NULL;
  BIGNUM *u2 = NULL;
  unsigned int hint;
  int ret = 0;

#ifdef BCRYPTO_ECDSA_WITH_ICART
  if (bcrypto_ecdsa_uniform_type(ec->type) == BCRYPTO_ECDSA_ICART)
    return 0;
#endif

  u1 = BN_new();
  P2 = EC_POINT_new(ec->group);

  if (u1 == NULL || P2 == NULL)
    goto fail;

  P = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);

  if (P == NULL)
    goto fail;

  bcrypto_poll();

  for (;;) {
    if (!BN_rand_range(u1, ec->p))
      goto fail;

    P1 = bcrypto_ecdsa_point_from_uniform(ec, u1);

    if (P1 == NULL)
      goto fail;

    if (!EC_POINT_invert(ec->group, P1, ec->ctx))
      goto fail;

    if (!EC_POINT_add(ec->group, P2, P, P1, ec->ctx))
      goto fail;

    if (!bcrypto_random(&hint, sizeof(unsigned int)))
      goto fail;

    u2 = bcrypto_ecdsa_point_to_uniform(ec, P2, hint);

    if (u2 != NULL)
      break;

    EC_POINT_clear_free(P1);
    P1 = NULL;
  }

  assert(BN_bn2binpad(u1, bytes, ec->size) != -1);
  assert(BN_bn2binpad(u2, bytes + ec->size, ec->size) != -1);

  if (ec->bits & 7) {
    size_t fill = 8 - (ec->bits & 7);
    unsigned char r1, r2;

    if (!bcrypto_random(&r1, sizeof(unsigned char)))
      goto fail;

    if (!bcrypto_random(&r2, sizeof(unsigned char)))
      goto fail;

    r1 &= (1 << fill) - 1;
    r1 <<= ec->bits & 7;
    r2 &= (1 << fill) - 1;
    r2 <<= ec->bits & 7;

    bytes[0] |= r1;
    bytes[ec->size] |= r2;
  }

  ret = 1;
fail:
  if (P != NULL)
    EC_POINT_clear_free(P);

  if (P1 != NULL)
    EC_POINT_clear_free(P1);

  if (P2 != NULL)
    EC_POINT_clear_free(P2);

  if (u1 != NULL)
    BN_clear_free(u1);

  if (u2 != NULL)
    BN_clear_free(u2);

  return ret;
}

int
bcrypto_ecdsa_pubkey_export_spki(bcrypto_ecdsa_t *ec,
                                 uint8_t **out,
                                 size_t *out_len,
                                 const bcrypto_ecdsa_pubkey_t *pub,
                                 int compress) {
  EC_KEY *eckey = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  eckey = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub);

  if (eckey == NULL)
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  EC_KEY_set_conv_form(eckey, form);
  EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

  buf = NULL;
  len = i2d_EC_PUBKEY(eckey, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  EC_KEY_free(eckey);

  return 1;

fail:
  if (eckey != NULL)
    EC_KEY_free(eckey);

  return 0;
}

int
bcrypto_ecdsa_pubkey_import_spki(bcrypto_ecdsa_t *ec,
                                 bcrypto_ecdsa_pubkey_t *out,
                                 const uint8_t *raw,
                                 size_t raw_len) {
  EC_KEY *eckey = NULL;
  const uint8_t *p = raw;

  eckey = EC_KEY_new_by_curve_name(ec->type);

  if (eckey == NULL)
    goto fail;

  EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

  if (d2i_EC_PUBKEY(&eckey, &p, raw_len) == NULL)
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_key(ec, out, eckey))
    goto fail;

  EC_KEY_free(eckey);

  return 1;

fail:
  if (eckey != NULL)
    EC_KEY_free(eckey);

  return 0;
}

int
bcrypto_ecdsa_pubkey_tweak_add(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_pubkey_t *out,
                               const bcrypto_ecdsa_pubkey_t *pub,
                               const uint8_t *tweak) {
  EC_POINT *point = NULL;
  BIGNUM *tweak_bn = NULL;
  EC_POINT *tweak_point = NULL;

  point = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);

  if (point == NULL)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, ec->scalar_size, BN_secure_new());

  if (tweak_bn == NULL)
    goto fail;

  if (BN_cmp(tweak_bn, ec->n) >= 0)
    goto fail;

  tweak_point = EC_POINT_new(ec->group);

  if (tweak_point == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, tweak_point, tweak_bn, NULL, NULL, ec->ctx))
    goto fail;

  if (!EC_POINT_add(ec->group, point, point, tweak_point, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, point))
    goto fail;

  EC_POINT_free(point);
  BN_clear_free(tweak_bn);
  EC_POINT_free(tweak_point);

  return 1;

fail:
  if (point != NULL)
    EC_POINT_free(point);

  if (tweak_bn != NULL)
    BN_clear_free(tweak_bn);

  if (tweak_point != NULL)
    EC_POINT_free(tweak_point);

  return 0;
}

int
bcrypto_ecdsa_pubkey_tweak_mul(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_pubkey_t *out,
                               const bcrypto_ecdsa_pubkey_t *pub,
                               const uint8_t *tweak) {
  return bcrypto_ecdsa_derive(ec, out, pub, tweak);
}

int
bcrypto_ecdsa_pubkey_add(bcrypto_ecdsa_t *ec,
                         bcrypto_ecdsa_pubkey_t *out,
                         const bcrypto_ecdsa_pubkey_t *pub1,
                         const bcrypto_ecdsa_pubkey_t *pub2) {
  EC_POINT *point1 = NULL;
  EC_POINT *point2 = NULL;

  point1 = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub1);

  if (point1 == NULL)
    goto fail;

  point2 = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub2);

  if (point2 == NULL)
    goto fail;

  if (!EC_POINT_add(ec->group, point1, point1, point2, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, point1))
    goto fail;

  EC_POINT_free(point1);
  EC_POINT_free(point2);

  return 1;

fail:
  if (point1 != NULL)
    EC_POINT_free(point1);

  if (point2 != NULL)
    EC_POINT_free(point2);

  return 0;
}

int
bcrypto_ecdsa_pubkey_combine(bcrypto_ecdsa_t *ec,
                             bcrypto_ecdsa_pubkey_t *out,
                             const bcrypto_ecdsa_pubkey_t *pubs,
                             size_t length) {
  EC_POINT *result = NULL;
  EC_POINT *point = NULL;
  size_t i = 0;
  int r = 0;

  result = EC_POINT_new(ec->group);

  if (result == NULL)
    goto fail;

  for (; i < length; i++) {
    const bcrypto_ecdsa_pubkey_t *pub = &pubs[i];

    point = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);

    if (point == NULL)
      goto fail;

    if (!EC_POINT_add(ec->group, result, result, point, ec->ctx))
      goto fail;

    EC_POINT_free(point);
    point = NULL;
  }

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, result))
    goto fail;

  r = 1;
fail:
  if (result != NULL)
    EC_POINT_free(result);

  if (point != NULL)
    EC_POINT_free(point);

  return r;
}

int
bcrypto_ecdsa_pubkey_negate(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *out,
                            const bcrypto_ecdsa_pubkey_t *pub) {
  EC_POINT *point = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);

  if (point == NULL)
    goto fail;

  if (!EC_POINT_invert(ec->group, point, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, point))
    goto fail;

  EC_POINT_free(point);

  return 1;

fail:
  if (point != NULL)
    EC_POINT_free(point);

  return 0;
}

int
bcrypto_ecdsa_sign(bcrypto_ecdsa_t *ec,
                   bcrypto_ecdsa_sig_t *sig,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *priv) {
  EC_KEY *eckey = NULL;
  ECDSA_SIG *ecsig = NULL;

  if (!bcrypto_ecdsa_valid_scalar(ec, priv))
    goto fail;

  eckey = EC_KEY_new_by_curve_name(ec->type);

  if (eckey == NULL)
    goto fail;

  if (!EC_KEY_oct2priv(eckey, priv, ec->scalar_size))
    goto fail;

  bcrypto_poll();

  ecsig = ECDSA_do_sign(msg, msg_len, eckey);

  if (ecsig == NULL)
    goto fail;

  bcrypto_ecdsa_sig_from_ecdsa_sig(ec, sig, ecsig);

  bcrypto_ecdsa_sig_normalize(ec, sig, sig);

  EC_KEY_free(eckey);
  ECDSA_SIG_free(ecsig);

  return 1;

fail:
  if (eckey != NULL)
    EC_KEY_free(eckey);

  if (ecsig != NULL)
    ECDSA_SIG_free(ecsig);

  return 0;
}

int
bcrypto_ecdsa_sign_recoverable(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_sig_t *sig,
                               const uint8_t *msg,
                               size_t msg_len,
                               const uint8_t *priv) {
  bcrypto_ecdsa_pubkey_t A, Q;
  int i = 0;

  if (!bcrypto_ecdsa_sign(ec, sig, msg, msg_len, priv))
    return 0;

  if (!bcrypto_ecdsa_pubkey_create(ec, &A, priv))
    return 0;

  for (; i < 4; i++) {
    if (!bcrypto_ecdsa_recover(ec, &Q, msg, msg_len, sig, i))
      continue;

    if (!bcrypto_ecdsa_pubkey_equals(ec, &Q, &A))
      continue;

    sig->param = i;

    return 1;
  }

  return 0;
}

int
bcrypto_ecdsa_verify(bcrypto_ecdsa_t *ec,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_ecdsa_sig_t *sig,
                     const bcrypto_ecdsa_pubkey_t *pub) {
  ECDSA_SIG *ecsig = NULL;
  EC_KEY *eckey = NULL;

  ecsig = bcrypto_ecdsa_sig_to_ecdsa_sig(ec, sig);

  if (ecsig == NULL)
    goto fail;

  eckey = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub);

  if (eckey == NULL)
    goto fail;

  if (ECDSA_do_verify(msg, msg_len, ecsig, eckey) <= 0)
    goto fail;

  ECDSA_SIG_free(ecsig);
  EC_KEY_free(eckey);

  return 1;

fail:
  if (ecsig != NULL)
    ECDSA_SIG_free(ecsig);

  if (eckey != NULL)
    EC_KEY_free(eckey);

  return 0;
}

int
bcrypto_ecdsa_recover(bcrypto_ecdsa_t *ec,
                      bcrypto_ecdsa_pubkey_t *pub,
                      const uint8_t *msg,
                      size_t msg_len,
                      const bcrypto_ecdsa_sig_t *sig,
                      int param) {
  int sign = 0;
  int high = 0;
  ECDSA_SIG *ecsig = NULL;
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;
  BIGNUM *x = NULL;
  BIGNUM *pn = NULL;
  EC_POINT *R = NULL;
  BIGNUM *ri = NULL;
  BIGNUM *s1 = NULL;
  BIGNUM *s2 = NULL;
  BIGNUM *m = NULL;
  int d = 0;
  EC_POINT *A = NULL;

  if (param < 0 || (param & 3) != param)
    goto fail;

  sign = param & 1;
  high = param >> 1;

  ecsig = bcrypto_ecdsa_sig_to_ecdsa_sig(ec, sig);

  if (ecsig == NULL)
    goto fail;

  ECDSA_SIG_get0(ecsig, &r, &s);

  assert(r != NULL && s != NULL);

  if (BN_is_zero(r) || BN_cmp(r, ec->n) >= 0)
    goto fail;

  if (BN_is_zero(s) || BN_cmp(s, ec->n) >= 0)
    goto fail;

  x = BN_new();

  if (x == NULL)
    goto fail;

  if (!BN_copy(x, r))
    goto fail;

  if (high) {
    pn = BN_new();

    if (pn == NULL)
      goto fail;

    if (!BN_mod(pn, ec->p, ec->n, ec->ctx))
      goto fail;

    if (BN_cmp(r, pn) >= 0)
      goto fail;

    if (!BN_mod_add(x, x, ec->n, ec->p, ec->ctx))
      goto fail;

    BN_free(pn);
  }

  R = EC_POINT_new(ec->group);

  if (R == NULL)
    goto fail;

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  if (!EC_POINT_set_compressed_coordinates(ec->group, R, x, sign, ec->ctx))
#else
  if (!EC_POINT_set_compressed_coordinates_GFp(ec->group, R, x, sign, ec->ctx))
#endif
    goto fail;

  ri = BN_new();

  if (ri == NULL)
    goto fail;

  if (!BN_mod_inverse(ri, r, ec->n, ec->ctx))
    goto fail;

  if (msg_len > ec->scalar_size)
    msg_len = ec->scalar_size;

  m = BN_bin2bn(msg, msg_len, NULL);

  if (m == NULL)
    goto fail;

  d = (int)msg_len * 8 - (int)ec->scalar_bits;

  if (d > 0) {
    if (!BN_rshift(m, m, d))
      goto fail;
  }

  if (!BN_mod(m, m, ec->n, ec->ctx))
    goto fail;

  s1 = BN_new();

  if (s1 == NULL)
    goto fail;

  if (!BN_mod_mul(s1, m, ri, ec->n, ec->ctx))
    goto fail;

  if (!BN_mod_sub(s1, ec->n, s1, ec->n, ec->ctx))
    goto fail;

  s2 = BN_new();

  if (s2 == NULL)
    goto fail;

  if (!BN_mod_mul(s2, s, ri, ec->n, ec->ctx))
    goto fail;

  A = EC_POINT_new(ec->group);

  if (A == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, A, s1, R, s2, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, pub, A))
    goto fail;

  ECDSA_SIG_free(ecsig);
  BN_free(x);
  EC_POINT_free(R);
  BN_free(ri);
  BN_free(s1);
  BN_free(s2);
  BN_free(m);
  EC_POINT_free(A);

  return 1;

fail:
  if (ecsig != NULL)
    ECDSA_SIG_free(ecsig);

  if (x != NULL)
    BN_free(x);

  if (pn != NULL)
    BN_free(pn);

  if (R != NULL)
    EC_POINT_free(R);

  if (ri != NULL)
    BN_free(ri);

  if (s1 != NULL)
    BN_free(s1);

  if (s2 != NULL)
    BN_free(s2);

  if (m != NULL)
    BN_free(m);

  if (A != NULL)
    EC_POINT_free(A);

  return 0;
}

int
bcrypto_ecdsa_derive(bcrypto_ecdsa_t *ec,
                     bcrypto_ecdsa_pubkey_t *out,
                     const bcrypto_ecdsa_pubkey_t *pub,
                     const uint8_t *priv) {
  BIGNUM *scalar = NULL;
  EC_POINT *point = NULL;
  EC_POINT *secret = NULL;

  scalar = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());

  if (scalar == NULL)
    goto fail;

  if (BN_is_zero(scalar) || BN_cmp(scalar, ec->n) >= 0)
    goto fail;

  point = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);

  if (point == NULL)
    goto fail;

  secret = EC_POINT_new(ec->group);

  if (secret == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, secret, NULL, point, scalar, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, secret))
    goto fail;

  BN_clear_free(scalar);
  EC_POINT_free(point);
  EC_POINT_clear_free(secret);

  return 1;

fail:
  if (scalar != NULL)
    BN_clear_free(scalar);

  if (point != NULL)
    EC_POINT_free(point);

  if (secret != NULL)
    EC_POINT_clear_free(secret);

  return 0;
}

/*
 * Schnorr
 */

void
bcrypto_schnorr_sig_encode(bcrypto_ecdsa_t *ec,
                         uint8_t *out,
                         const bcrypto_ecdsa_sig_t *sig) {
  memcpy(&out[0], &sig->r[0], ec->size);
  memcpy(&out[ec->size], &sig->s[0], ec->scalar_size);
}

int
bcrypto_schnorr_sig_decode(bcrypto_ecdsa_t *ec,
                         bcrypto_ecdsa_sig_t *sig,
                         const uint8_t *raw) {
  memcpy(&sig->r[0], &raw[0], ec->size);
  memcpy(&sig->s[0], &raw[ec->size], ec->scalar_size);

  return memcmp(sig->r, ec->prime, ec->size) < 0
      && memcmp(sig->s, ec->order, ec->scalar_size) < 0;
}

static BIGNUM *
schnorr_hash_am(bcrypto_ecdsa_t *ec,
                const uint8_t *key,
                const uint8_t *msg) {
  uint8_t out[EVP_MAX_MD_SIZE];
  EVP_MD_CTX *ctx = NULL;
  BIGNUM *k = NULL;
  unsigned int hash_size;

  ctx = EVP_MD_CTX_new();

  if (ctx == NULL)
    goto fail;

  if (!EVP_DigestInit(ctx, ec->hash))
    goto fail;

  if (!EVP_DigestUpdate(ctx, key, ec->scalar_size))
    goto fail;

  if (!EVP_DigestUpdate(ctx, msg, 32))
    goto fail;

  if (!EVP_DigestFinal(ctx, out, &hash_size))
    goto fail;

  k = BN_bin2bn(out, hash_size, BN_secure_new());

  if (k == NULL)
    goto fail;

  if (!BN_mod(k, k, ec->n, ec->ctx)) {
    BN_clear_free(k);
    k = NULL;
    goto fail;
  }

fail:
  if (ctx != NULL)
    EVP_MD_CTX_free(ctx);

  return k;
}

static BIGNUM *
schnorr_hash_ram(bcrypto_ecdsa_t *ec,
                 const uint8_t *r,
                 const bcrypto_ecdsa_pubkey_t *pub,
                 const uint8_t *msg) {
  uint8_t raw[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  uint8_t out[EVP_MAX_MD_SIZE];
  EVP_MD_CTX *ctx = NULL;
  BIGNUM *e = NULL;
  size_t pub_size;
  unsigned int hash_size;

  ctx = EVP_MD_CTX_new();

  if (ctx == NULL)
    goto fail;

  if (!EVP_DigestInit(ctx, ec->hash))
    goto fail;

  if (!EVP_DigestUpdate(ctx, r, ec->size))
    goto fail;

  bcrypto_ecdsa_pubkey_encode(ec, raw, &pub_size, pub, 1);

  if (!EVP_DigestUpdate(ctx, raw, pub_size))
    goto fail;

  if (!EVP_DigestUpdate(ctx, msg, 32))
    goto fail;

  if (!EVP_DigestFinal(ctx, out, &hash_size))
    goto fail;

  e = BN_bin2bn(out, hash_size, NULL);

  if (e == NULL)
    goto fail;

  if (!BN_mod(e, e, ec->n, ec->ctx)) {
    BN_free(e);
    e = NULL;
    goto fail;
  }

fail:
  if (ctx != NULL)
    EVP_MD_CTX_free(ctx);

  return e;
}

static int
schnorr_lift_x(bcrypto_ecdsa_t *ec,
               EC_POINT *R,
               const BIGNUM *x,
               BIGNUM *ax,
               BIGNUM *y) {
  if (!BN_mod_mul(ax, ec->a, x, ec->p, ec->ctx))
    return 0;

  if (!BN_mod_sqr(y, x, ec->p, ec->ctx))
    return 0;

  if (!BN_mod_mul(y, y, x, ec->p, ec->ctx))
    return 0;

  if (!BN_mod_add(y, y, ax, ec->p, ec->ctx))
    return 0;

  if (!BN_mod_add(y, y, ec->b, ec->p, ec->ctx))
    return 0;

  if (!BN_mod_sqrt(y, y, ec->p, ec->ctx))
    return 0;

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  /* Note: should be present with 1.1.1b */
  if (!EC_POINT_set_affine_coordinates(ec->group, R, x, y, ec->ctx))
#else
  if (!EC_POINT_set_affine_coordinates_GFp(ec->group, R, x, y, ec->ctx))
#endif
    return 0;

  return 1;
}

int
bcrypto_schnorr_sign(bcrypto_ecdsa_t *ec,
                     bcrypto_ecdsa_sig_t *sig,
                     const uint8_t *msg,
                     const uint8_t *priv) {
  BIGNUM *a = NULL;
  BIGNUM *k = NULL;
  EC_POINT *R = NULL;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  EC_POINT *A = NULL;
  bcrypto_ecdsa_pubkey_t pub;
  BIGNUM *e = NULL;
  int ret = 0;
  int j;

  if (!bcrypto_ecdsa_valid_scalar(ec, priv))
    goto fail;

  a = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());

  if (a == NULL || BN_is_zero(a) || BN_cmp(a, ec->n) >= 0)
    goto fail;

  k = schnorr_hash_am(ec, priv, msg);

  if (k == NULL || BN_is_zero(k))
    goto fail;

  R = EC_POINT_new(ec->group);

  if (R == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, R, k, NULL, NULL, ec->ctx))
    goto fail;

  x = BN_new();
  y = BN_new();

  if (x == NULL || y == NULL)
    goto fail;

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  /* Note: should be present with 1.1.1b */
  if (!EC_POINT_get_affine_coordinates(ec->group, R, x, y, ec->ctx))
#else
  if (!EC_POINT_get_affine_coordinates_GFp(ec->group, R, x, y, ec->ctx))
#endif
    goto fail;

  assert(BN_bn2binpad(x, sig->r, ec->size) != -1);

  A = EC_POINT_new(ec->group);

  if (A == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, A, a, NULL, NULL, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, &pub, A))
    goto fail;

  e = schnorr_hash_ram(ec, sig->r, &pub, msg);

  if (e == NULL)
    goto fail;

  j = BN_kronecker(y, ec->p, ec->ctx);

  if (j < -1)
    goto fail;

  if (j != 1)
    BN_sub(k, ec->n, k);

  if (!BN_mod_mul(e, e, a, ec->n, ec->ctx))
    goto fail;

  if (!BN_mod_add(e, k, e, ec->n, ec->ctx))
    goto fail;

  assert(BN_bn2binpad(e, sig->s, ec->scalar_size) != -1);

  ret = 1;
fail:
  if (a != NULL)
    BN_clear_free(a);

  if (k != NULL)
    BN_clear_free(k);

  if (R != NULL)
    EC_POINT_free(R);

  if (x != NULL)
    BN_free(x);

  if (y != NULL)
    BN_free(y);

  if (A != NULL)
    EC_POINT_free(A);

  if (e != NULL)
    BN_free(e);

  return ret;
}

int
bcrypto_schnorr_verify(bcrypto_ecdsa_t *ec,
                       const uint8_t *msg,
                       const bcrypto_ecdsa_sig_t *sig,
                       const bcrypto_ecdsa_pubkey_t *pub) {
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;
  EC_POINT *A = NULL;
  BIGNUM *e = NULL;
  EC_POINT *R = NULL;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  BIGNUM *z = NULL;
  int ret = 0;

  r = BN_bin2bn(sig->r, ec->size, NULL);
  s = BN_bin2bn(sig->s, ec->scalar_size, NULL);
  A = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);
  e = schnorr_hash_ram(ec, sig->r, pub, msg);
  R = EC_POINT_new(ec->group);

  if (r == NULL || s == NULL || A == NULL || e == NULL || R == NULL)
    goto fail;

  if (BN_cmp(r, ec->p) >= 0 || BN_cmp(s, ec->n) >= 0)
    goto fail;

  if (!BN_is_zero(e)) {
    if (!BN_sub(e, ec->n, e))
      goto fail;
  }

  if (!EC_POINT_mul(ec->group, R, s, A, e, ec->ctx))
    goto fail;

  x = BN_new();
  y = BN_new();
  z = BN_new();

  if (x == NULL || y == NULL || z == NULL)
    goto fail;

  if (!EC_POINT_get_Jprojective_coordinates_GFp(ec->group, R, x, y, z, ec->ctx))
    goto fail;

  if (BN_is_zero(z))
    goto fail;

  if (!BN_mod_mul(e, y, z, ec->p, ec->ctx))
    goto fail;

  if (BN_kronecker(e, ec->p, ec->ctx) != 1)
    goto fail;

  if (!BN_mod_sqr(e, z, ec->p, ec->ctx))
    goto fail;

  if (!BN_mod_mul(e, r, e, ec->p, ec->ctx))
    goto fail;

  if (BN_ucmp(x, e) != 0)
    goto fail;

  ret = 1;
fail:
  if (r != NULL)
    BN_free(r);

  if (s != NULL)
    BN_free(s);

  if (A != NULL)
    EC_POINT_free(A);

  if (e != NULL)
    BN_free(e);

  if (R != NULL)
    EC_POINT_free(R);

  if (x != NULL)
    BN_free(x);

  if (y != NULL)
    BN_free(y);

  if (z != NULL)
    BN_free(z);

  return ret;
}

int
bcrypto_schnorr_verify_batch(bcrypto_ecdsa_t *ec,
                             const uint8_t **msgs,
                             const bcrypto_ecdsa_sig_t *sigs,
                             const bcrypto_ecdsa_pubkey_t *pubs,
                             size_t length) {
  EC_POINT **points = NULL;
  BIGNUM **coeffs = NULL;
  BIGNUM *sum = NULL;
  BIGNUM *r_tmp = NULL;
  BIGNUM *s_tmp = NULL;
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;
  EC_POINT *A = NULL;
  BIGNUM *e = NULL;
  EC_POINT *R = NULL;
  BIGNUM *a = NULL;
  BIGNUM *ax = NULL;
  BIGNUM *y = NULL;
  EC_POINT *res = NULL;
  int ret = 0;
  size_t i = 0;

  if (length == 0)
    return 1;

  points = (EC_POINT **)OPENSSL_malloc(2 * length * sizeof(EC_POINT *));
  coeffs = (BIGNUM **)OPENSSL_malloc(2 * length * sizeof(BIGNUM *));
  sum = BN_new();
  r_tmp = BN_new();
  s_tmp = BN_new();
  ax = BN_new();
  y = BN_new();
  res = EC_POINT_new(ec->group);

  if (points == NULL || coeffs == NULL
      || sum == NULL || r_tmp == NULL
      || s_tmp == NULL || ax == NULL
      || y == NULL || res == NULL) {
    goto fail;
  }

  BN_zero(sum);

  bcrypto_poll();

  for (; i < length; i++) {
    const uint8_t *msg = msgs[i];
    const bcrypto_ecdsa_sig_t *sig = &sigs[i];
    const bcrypto_ecdsa_pubkey_t *pub = &pubs[i];

    r = BN_bin2bn(sig->r, ec->size, r_tmp);
    s = BN_bin2bn(sig->s, ec->scalar_size, s_tmp);
    A = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);
    e = schnorr_hash_ram(ec, sig->r, pub, msg);
    R = EC_POINT_new(ec->group);
    a = BN_new();

    if (r == NULL || s == NULL || A == NULL
        || e == NULL || R == NULL || a == NULL) {
      goto fail;
    }

    if (BN_cmp(r, ec->p) >= 0 || BN_cmp(s, ec->n) >= 0)
      goto fail;

    if (!schnorr_lift_x(ec, R, r, ax, y))
      goto fail;

    if (i == 0) {
      if (!BN_set_word(a, 1))
        goto fail;
    } else {
      if (!BN_rand_range(a, ec->ns1))
        goto fail;

      if (!BN_add_word(a, 1))
        goto fail;

      if (!BN_mod_mul(e, e, a, ec->n, ec->ctx))
        goto fail;

      if (!BN_mod_mul(s, s, a, ec->n, ec->ctx))
        goto fail;
    }

    if (!BN_mod_add(sum, sum, s, ec->n, ec->ctx))
      goto fail;

    points[i * 2 + 0] = R;
    coeffs[i * 2 + 0] = a;
    points[i * 2 + 1] = A;
    coeffs[i * 2 + 1] = e;

    R = NULL;
    a = NULL;
    A = NULL;
    e = NULL;
  }

  if (!BN_is_zero(sum)) {
    if (!BN_sub(sum, ec->n, sum))
      goto fail;
  }

  if (!EC_POINTs_mul(ec->group, res, sum, length * 2,
                     (const EC_POINT **)points,
                     (const BIGNUM **)coeffs,
                     ec->ctx)) {
    goto fail;
  }

  if (!EC_POINT_is_at_infinity(ec->group, res))
    goto fail;

  ret = 1;
fail:
  if (sum != NULL)
    BN_free(sum);

  if (r_tmp != NULL)
    BN_free(r_tmp);

  if (s_tmp != NULL)
    BN_free(s_tmp);

  if (A != NULL)
    EC_POINT_free(A);

  if (e != NULL)
    BN_free(e);

  if (R != NULL)
    EC_POINT_free(R);

  if (a != NULL)
    BN_free(a);

  if (ax != NULL)
    BN_free(ax);

  if (y != NULL)
    BN_free(y);

  if (res != NULL)
    EC_POINT_free(res);

  while (i > 0) {
    EC_POINT_free(points[(i - 1) * 2 + 0]);
    EC_POINT_free(points[(i - 1) * 2 + 1]);
    BN_free(coeffs[(i - 1) * 2 + 0]);
    BN_free(coeffs[(i - 1) * 2 + 1]);
    i -= 1;
  }

  if (points != NULL)
    OPENSSL_free(points);

  if (coeffs != NULL)
    OPENSSL_free(coeffs);

  return ret;
}

/*
 * Curve Mappings
 */

static int
bn_mod_fermat(BIGNUM *r, BIGNUM *a, const BIGNUM *n, BN_CTX *ctx) {
  BIGNUM *e = BN_new();
  int ret = 0;

  if (e == NULL)
    return 0;

  /* e = n - 2 */
  if (!BN_copy(e, n))
    goto fail;

  if (!BN_sub_word(e, 2))
    goto fail;

  if (!BN_mod_exp(r, a, e, n, ctx))
    goto fail;

  ret = 1;
fail:
  BN_free(e);
  return ret;
}

static int
bn_legendre(const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx) {
  BIGNUM *e = BN_new();
  BIGNUM *r = BN_new();

  if (e == NULL || r == NULL)
    goto fail;

  /* e = (n - 1) / 2 */
  if (!BN_copy(e, n))
    goto fail;

  if (!BN_sub_word(e, 1))
    goto fail;

  if (!BN_rshift1(e, e))
    goto fail;

  if (!BN_mod_exp(r, a, e, n, ctx))
    goto fail;

  int x = !!BN_is_one(r);
  int y = (!BN_is_zero(r)) & (!BN_is_one(r));

  BN_free(e);
  BN_free(r);

  return x - y;
fail:
  if (e != NULL)
    BN_free(e);

  if (r != NULL)
    BN_free(r);

  return -2;
}

static int
bn_is_square(const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx) {
  return bn_legendre(a, n, ctx) >= 0;
}

#ifdef BCRYPTO_ECDSA_WITH_ICART
static EC_POINT *
bcrypto_ecdsa_icart(bcrypto_ecdsa_t *ec, const BIGNUM *r) {
  BIGNUM *c1 = BN_new();
  BIGNUM *c2 = BN_new();
  BIGNUM *c3 = BN_new();
  BIGNUM *c4 = BN_new();
  BIGNUM *u = BN_new();
  BIGNUM *u2 = BN_new();
  BIGNUM *u4 = BN_new();
  BIGNUM *u6 = BN_new();
  BIGNUM *v = BN_new();
  BIGNUM *t1 = BN_new();
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  EC_POINT *P = EC_POINT_new(ec->group);
  int ret = 0;

  if (c1 == NULL || c2 == NULL || c3 == NULL || c4 == NULL
      || u == NULL || u2 == NULL || u4 == NULL || u6 == NULL
      || t1 == NULL || x == NULL || y == NULL || P == NULL) {
    goto fail;
  }

  /*
   * Icart Method
   * https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
   *
   * c1 = (2 * p - 1) / 3
   * c2 = 1 / 3
   * c3 = c2^3
   * c4 = 3 * A
   * e = u == 0
   * u = CMOV(u, 1, e)
   * u2 = u^2
   * u4 = u2^2
   * v = c4 - u4
   * t1 = 6 * u
   * t1 = inv0(t1)
   * v = v * t1
   * x = v^2
   * x = x - B
   * u6 = u4 * c3
   * u6 = u6 * u2
   * x = x - u6
   * x = x^c1
   * t1 = u2 * c2
   * x = x + t1
   * y = u * x
   * y = y + v
   * P = (x, y)
   */

#define F(x) if (!(x)) goto fail

  F(BN_copy(c1, ec->p));
  F(BN_mul_word(c1, 2));
  F(BN_sub_word(c1, 1));
  F(BN_div_word(c1, 3) != (BN_ULONG)-1);

  F(BN_set_word(c2, 3));
  F(BN_mod_inverse(c2, c2, ec->p, ec->ctx));

  F(BN_mod_sqr(c3, c2, ec->p, ec->ctx));
  F(BN_mod_mul(c3, c3, c2, ec->p, ec->ctx));

  F(BN_set_word(c4, 3));
  F(BN_mod_mul(c4, c4, ec->a, ec->p, ec->ctx));

  F(BN_copy(u, r));

  if (BN_is_zero(u))
    F(BN_set_word(u, 1));

  F(BN_mod_sqr(u2, u, ec->p, ec->ctx));
  F(BN_mod_sqr(u4, u2, ec->p, ec->ctx));
  F(BN_mod_sub(v, c4, u4, ec->p, ec->ctx));
  F(BN_set_word(t1, 6));
  F(BN_mod_mul(t1, u, t1, ec->p, ec->ctx));
  F(bn_mod_fermat(t1, t1, ec->p, ec->ctx));
  F(BN_mod_mul(v, v, t1, ec->p, ec->ctx));
  F(BN_mod_sqr(x, v, ec->p, ec->ctx));
  F(BN_mod_sub(x, x, ec->b, ec->p, ec->ctx));
  F(BN_mod_mul(u6, u4, c3, ec->p, ec->ctx));
  F(BN_mod_mul(u6, u6, u2, ec->p, ec->ctx));
  F(BN_mod_sub(x, x, u6, ec->p, ec->ctx));
  F(BN_mod_exp(x, x, c1, ec->p, ec->ctx));
  F(BN_mod_mul(t1, u2, c2, ec->p, ec->ctx));
  F(BN_mod_add(x, x, t1, ec->p, ec->ctx));
  F(BN_mod_mul(y, u, x, ec->p, ec->ctx));
  F(BN_mod_add(y, y, v, ec->p, ec->ctx));

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  /* Note: should be present with 1.1.1b */
  F(EC_POINT_set_affine_coordinates(ec->group, P, x, y, ec->ctx));
#else
  F(EC_POINT_set_affine_coordinates_GFp(ec->group, P, x, y, ec->ctx));
#endif

#undef F

  ret = 1;
fail:
  if (c1 != NULL) BN_free(c1);
  if (c2 != NULL) BN_free(c2);
  if (c3 != NULL) BN_free(c3);
  if (c4 != NULL) BN_free(c4);
  if (u != NULL) BN_free(u);
  if (u2 != NULL) BN_free(u2);
  if (u4 != NULL) BN_free(u4);
  if (u6 != NULL) BN_free(u6);
  if (v != NULL) BN_free(v);
  if (t1 != NULL) BN_free(t1);
  if (x != NULL) BN_free(x);
  if (y != NULL) BN_free(y);

  if (!ret && P != NULL) {
    EC_POINT_free(P);
    P = NULL;
  }

  return P;
}
#endif

static EC_POINT *
bcrypto_ecdsa_sswu(bcrypto_ecdsa_t *ec, const BIGNUM *r) {
  BIGNUM *z = BN_new();
  BIGNUM *c1 = BN_new();
  BIGNUM *c2 = BN_new();
  BIGNUM *u = BN_new();
  BIGNUM *t1 = BN_new();
  BIGNUM *t2 = BN_new();
  BIGNUM *x1 = BN_new();
  BIGNUM *x2 = BN_new();
  BIGNUM *gx1 = BN_new();
  BIGNUM *gx2 = BN_new();
  BIGNUM *y2 = BN_new();
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  EC_POINT *P = EC_POINT_new(ec->group);
  int ret = 0;
  int Z, e1, e2, e3;

  if (z == NULL || c1 == NULL || c2 == NULL || u == NULL
      || t1 == NULL || t2 == NULL || x1 == NULL || x2 == NULL
      || gx1 == NULL || gx2 == NULL || y2 == NULL || x == NULL
      || y == NULL || P == NULL) {
    goto fail;
  }

#define F(x) if (!(x)) goto fail

  Z = bcrypto_ecdsa_uniform_z(ec->type);

  if (Z < 0) {
    F(BN_copy(z, ec->p));
    F(BN_sub_word(z, -Z));
  } else {
    F(BN_set_word(z, Z));
  }

  /*
   * Simplified Shallue-van de Woestijne-Ulas Method
   * https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
   *
   * c1 = -B / A
   * c2 = -1 / Z
   * t1 = Z * u^2
   * t2 = t1^2
   * x1 = t1 + t2
   * x1 = inv0(x1)
   * e1 = x1 == 0
   * x1 = x1 + 1
   * x1 = CMOV(x1, c2, e1)
   * x1 = x1 * c1
   * gx1 = x1^2
   * gx1 = gx1 + A
   * gx1 = gx1 * x1
   * gx1 = gx1 + B
   * x2 = t1 * x1
   * t2 = t1 * t2
   * gx2 = gx1 * t2
   * e2 = is_square(gx1)
   * x = CMOV(x2, x1, e2)
   * y2 = CMOV(gx2, gx1, e2)
   * y = sqrt(y2)
   * e3 = sgn0(u) == sgn0(y)
   * y = CMOV(-y, y, e3)
   * P = (x, y)
   */

  F(BN_mod_inverse(c1, ec->a, ec->p, ec->ctx));
  F(BN_mod_mul(c1, ec->b, c1, ec->p, ec->ctx));
  F(BN_mod_sub(c1, ec->p, c1, ec->p, ec->ctx));

  F(BN_mod_inverse(c2, z, ec->p, ec->ctx));
  F(BN_mod_sub(c2, ec->p, c2, ec->p, ec->ctx));

  F(BN_copy(u, r));

  F(BN_mod_sqr(t1, u, ec->p, ec->ctx));
  F(BN_mod_mul(t1, z, t1, ec->p, ec->ctx));
  F(BN_mod_sqr(t2, t1, ec->p, ec->ctx));
  F(BN_mod_add(x1, t1, t2, ec->p, ec->ctx));
  F(bn_mod_fermat(x1, x1, ec->p, ec->ctx));
  e1 = BN_is_zero(x1);
  F(BN_mod_add(x1, x1, ec->one, ec->p, ec->ctx));
  if (e1) F(BN_copy(x1, c2));
  F(BN_mod_mul(x1, x1, c1, ec->p, ec->ctx));
  F(BN_mod_sqr(gx1, x1, ec->p, ec->ctx));
  F(BN_mod_add(gx1, gx1, ec->a, ec->p, ec->ctx));
  F(BN_mod_mul(gx1, gx1, x1, ec->p, ec->ctx));
  F(BN_mod_add(gx1, gx1, ec->b, ec->p, ec->ctx));
  F(BN_mod_mul(x2, t1, x1, ec->p, ec->ctx));
  F(BN_mod_mul(t2, t1, t2, ec->p, ec->ctx));
  F(BN_mod_mul(gx2, gx1, t2, ec->p, ec->ctx));
  e2 = bn_is_square(gx1, ec->p, ec->ctx);
  F(BN_copy(x, e2 ? x1 : x2));
  F(BN_copy(y2, e2 ? gx1 : gx2));
  F(BN_mod_sqrt(y, y2, ec->p, ec->ctx));
  e3 = BN_is_odd(y) == BN_is_odd(u);
  if (!e3) F(BN_mod_sub(y, ec->p, y, ec->p, ec->ctx));

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  /* Note: should be present with 1.1.1b */
  F(EC_POINT_set_affine_coordinates(ec->group, P, x, y, ec->ctx));
#else
  F(EC_POINT_set_affine_coordinates_GFp(ec->group, P, x, y, ec->ctx));
#endif

#undef F

  ret = 1;
fail:
  if (z != NULL) BN_free(z);
  if (c1 != NULL) BN_free(c1);
  if (c2 != NULL) BN_free(c2);
  if (u != NULL) BN_free(u);
  if (t1 != NULL) BN_free(t1);
  if (t2 != NULL) BN_free(t2);
  if (x1 != NULL) BN_free(x1);
  if (x2 != NULL) BN_free(x2);
  if (gx1 != NULL) BN_free(gx1);
  if (gx2 != NULL) BN_free(gx2);
  if (y2 != NULL) BN_free(y2);
  if (x != NULL) BN_free(x);
  if (y != NULL) BN_free(y);

  if (!ret && P != NULL) {
    EC_POINT_free(P);
    P = NULL;
  }

  return P;
}

static BIGNUM *
bcrypto_ecdsa_sswui(bcrypto_ecdsa_t *ec, const EC_POINT *P, unsigned int hint) {
  BIGNUM *z = BN_new();
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  BIGNUM *i2 = BN_new();
  BIGNUM *a2 = BN_new();
  BIGNUM *b2 = BN_new();
  BIGNUM *t0 = BN_new();
  BIGNUM *t1 = BN_new();
  BIGNUM *t2 = BN_new();
  BIGNUM *t3 = BN_new();
  BIGNUM *t4 = BN_new();
  BIGNUM *u1 = BN_new();
  BIGNUM *u2 = BN_new();
  BIGNUM *u3 = BN_new();
  BIGNUM *u4 = BN_new();
  BIGNUM *u = BN_new();
  int r = hint & 3;
  int Z, s0, s1;
  int ret = 0;

  /*
   * Map:
   *
   *   t0 = a * x * z + b * z
   *   t1 = b * z
   *   t2 = sqrt(a^2 * x^2 - 2 * a * b * x - 3 * b^2)
   *   t3 = t2 / 2
   *   t4 = (-a / 2) * x - (b / 2)
   *   u1 = +-sqrt((t4 + t3) / t0)
   *   u2 = +-sqrt((t4 - t3) / t0)
   *   u3 = +-sqrt((t4 + t3) / t1)
   *   u4 = +-sqrt((t4 - t3) / t1)
   */

  if (z == NULL || x == NULL || y == NULL || i2 == NULL
      || a2 == NULL || b2 == NULL || t0 == NULL || t1 == NULL
      || t2 == NULL || t3 == NULL || t4 == NULL || u1 == NULL
      || u2 == NULL || u3 == NULL || u4 == NULL || u == NULL) {
    goto fail;
  }

#define F(x) if (!(x)) goto fail

  Z = bcrypto_ecdsa_uniform_z(ec->type);

  if (Z < 0) {
    F(BN_copy(z, ec->p));
    F(BN_sub_word(z, -Z));
  } else {
    F(BN_set_word(z, Z));
  }

  F(!EC_POINT_is_at_infinity(ec->group, P));

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  /* Note: should be present with 1.1.1b */
  F(EC_POINT_get_affine_coordinates(ec->group, P, x, y, ec->ctx));
#else
  F(EC_POINT_get_affine_coordinates_GFp(ec->group, P, x, y, ec->ctx));
#endif

  /* i2 = 1 / 2 */
  F(BN_set_word(i2, 2));
  F(BN_mod_inverse(i2, i2, ec->p, ec->ctx));

  /* a2 = -a / 2 */
  F(BN_mod_sub(a2, ec->p, ec->a, ec->p, ec->ctx));
  F(BN_mod_mul(a2, a2, i2, ec->p, ec->ctx));

  /* b2 = b / 2 */
  F(BN_mod_mul(b2, ec->b, i2, ec->p, ec->ctx));

  /* t1 = b * z */
  F(BN_mod_mul(t1, ec->b, z, ec->p, ec->ctx));

  /* t0 = a * x * z + b * z */
  F(BN_mod_mul(t0, ec->a, x, ec->p, ec->ctx));
  F(BN_mod_mul(t0, t0, z, ec->p, ec->ctx));
  F(BN_mod_add(t0, t0, t1, ec->p, ec->ctx));

  /* t1 = 1 / t1 */
  F(BN_mod_inverse(t1, t1, ec->p, ec->ctx));

  /* t2 = sqrt(a^2 * x^2 - 2 * a * b * x - 3 * b^2) */
  F(BN_mod_sqr(t2, ec->a, ec->p, ec->ctx));
  F(BN_mod_sqr(t3, x, ec->p, ec->ctx));
  F(BN_mod_mul(t2, t2, t3, ec->p, ec->ctx));

  F(BN_mod_mul(t3, ec->a, ec->b, ec->p, ec->ctx));
  F(BN_mod_mul(t3, t3, x, ec->p, ec->ctx));
  F(BN_mod_mul(t3, t3, ec->two, ec->p, ec->ctx));
  F(BN_mod_sub(t2, t2, t3, ec->p, ec->ctx));

  F(BN_mod_sqr(t3, ec->b, ec->p, ec->ctx));
  F(BN_mod_mul(t3, t3, ec->three, ec->p, ec->ctx));
  F(BN_mod_sub(t2, t2, t3, ec->p, ec->ctx));

  s0 = BN_mod_sqrt(t2, t2, ec->p, ec->ctx) != 0;

  /* t3 = t2 / 2 */
  F(BN_mod_mul(t3, t2, i2, ec->p, ec->ctx));

  /* t4 = (-a / 2) * x - (b / 2) */
  F(BN_mod_mul(t4, a2, x, ec->p, ec->ctx));
  F(BN_mod_sub(t4, t4, b2, ec->p, ec->ctx));

  /* t0 = 1 / t0 */
  F(bn_mod_fermat(t0, t0, ec->p, ec->ctx));

  /* u1 = (t4 + t3) / t0 */
  F(BN_mod_add(u1, t4, t3, ec->p, ec->ctx));
  F(BN_mod_mul(u1, u1, t0, ec->p, ec->ctx));

  /* u2 = (t4 - t3) / t0 */
  F(BN_mod_sub(u2, t4, t3, ec->p, ec->ctx));
  F(BN_mod_mul(u2, u2, t0, ec->p, ec->ctx));

  /* u3 = (t4 + t3) / t1 */
  F(BN_mod_add(u3, t4, t3, ec->p, ec->ctx));
  F(BN_mod_mul(u3, u3, t1, ec->p, ec->ctx));

  /* u4 = (t4 - t3) / t1 */
  F(BN_mod_sub(u4, t4, t3, ec->p, ec->ctx));
  F(BN_mod_mul(u4, u4, t1, ec->p, ec->ctx));

  /* u = sqrt(ur) */
  BIGNUM *U[4] = { u1, u2, u3, u4 };

  s1 = BN_mod_sqrt(u, U[r], ec->p, ec->ctx) != 0;

  if (BN_is_odd(u) ^ BN_is_odd(y))
    F(BN_mod_sub(u, ec->p, u, ec->p, ec->ctx));

  F(s0 & s1);
#undef F

  ret = 1;
fail:
  if (z != NULL) BN_free(z);
  if (x != NULL) BN_free(x);
  if (y != NULL) BN_free(y);
  if (i2 != NULL) BN_free(i2);
  if (a2 != NULL) BN_free(a2);
  if (b2 != NULL) BN_free(b2);
  if (t0 != NULL) BN_free(t0);
  if (t1 != NULL) BN_free(t1);
  if (t2 != NULL) BN_free(t2);
  if (t3 != NULL) BN_free(t3);
  if (t4 != NULL) BN_free(t4);
  if (u1 != NULL) BN_free(u1);
  if (u2 != NULL) BN_free(u2);
  if (u3 != NULL) BN_free(u3);
  if (u4 != NULL) BN_free(u4);

  if (!ret && u != NULL) {
    BN_free(u);
    u = NULL;
  }

  return u;
}

static EC_POINT *
bcrypto_ecdsa_svdw(bcrypto_ecdsa_t *ec, const BIGNUM *r) {
  BIGNUM *z = BN_new();
  BIGNUM *c1 = BN_new();
  BIGNUM *c2 = BN_new();
  BIGNUM *c3 = BN_new();
  BIGNUM *c4 = BN_new();
  BIGNUM *c5 = BN_new();
  BIGNUM *u = BN_new();
  BIGNUM *t1 = BN_new();
  BIGNUM *t2 = BN_new();
  BIGNUM *t3 = BN_new();
  BIGNUM *t4 = BN_new();
  BIGNUM *x1 = BN_new();
  BIGNUM *gx1 = BN_new();
  BIGNUM *x2 = BN_new();
  BIGNUM *gx2 = BN_new();
  BIGNUM *x3 = BN_new();
  BIGNUM *gx3 = BN_new();
  BIGNUM *x = BN_new();
  BIGNUM *gx = BN_new();
  BIGNUM *y = BN_new();
  BIGNUM *i2 = BN_new();
  EC_POINT *P = EC_POINT_new(ec->group);
  int ret = 0;
  int Z, e1, e2, e3, e4;

  if (z == NULL || c1 == NULL || c2 == NULL || c3 == NULL
      || c4 == NULL || c5 == NULL || u == NULL || t1 == NULL
      || t2 == NULL || t3 == NULL || t4 == NULL || x1 == NULL
      || gx1 == NULL || x2 == NULL || gx2 == NULL || x3 == NULL
      || gx3 == NULL || x == NULL || gx == NULL || y == NULL
      || i2 == NULL || P == NULL) {
    goto fail;
  }

#define F(x) if (!(x)) goto fail

  Z = bcrypto_ecdsa_uniform_z(ec->type);

  if (Z < 0) {
    F(BN_copy(z, ec->p));
    F(BN_sub_word(z, -Z));
  } else {
    F(BN_set_word(z, Z));
  }

  /*
   * Shallue-van de Woestijne Method
   * https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
   *
   * c1 = g(Z)
   * c2 = sqrt(-3 * Z^2)
   * c3 = (sqrt(-3 * Z^2) - Z) / 2
   * c4 = (sqrt(-3 * Z^2) + Z) / 2
   * c5 = 1 / (3 * Z^2)
   * t1 = u^2
   * t2 = t1 + c1
   * t3 = t1 * t2
   * t4 = inv0(t3)
   * t3 = t1^2
   * t3 = t3 * t4
   * t3 = t3 * c2
   * x1 = c3 - t3
   * gx1 = x1^2
   * gx1 = gx1 * x1
   * gx1 = gx1 + B
   * e1 = is_square(gx1)
   * x2 = t3 - c4
   * gx2 = x2^2
   * gx2 = gx2 * x2
   * gx2 = gx2 + B
   * e2 = is_square(gx2)
   * e3 = e1 OR e2
   * x3 = t2^2
   * x3 = x3 * t2
   * x3 = x3 * t4
   * x3 = x3 * c5
   * x3 = Z - x3
   * gx3 = x3^2
   * gx3 = gx3 * x3
   * gx3 = gx3 + B
   * x = CMOV(x2, x1, e1)
   * gx = CMOV(gx2, gx1, e1)
   * x = CMOV(x3, x, e3)
   * gx = CMOV(gx3, gx, e3)
   * y = sqrt(gx)
   * e4 = sgn0(u) == sgn0(y)
   * y = CMOV(-y, y, e4)
   * P = (x, y)
   */

  F(BN_set_word(i2, 2));
  F(BN_mod_inverse(i2, i2, ec->p, ec->ctx));

  F(BN_mod_sqr(c1, z, ec->p, ec->ctx));
  F(BN_mod_mul(c1, c1, z, ec->p, ec->ctx));
  F(BN_mod_add(c1, c1, ec->b, ec->p, ec->ctx));

  F(BN_mod_sqr(c2, z, ec->p, ec->ctx));
  F(BN_mod_mul(c2, c2, ec->three, ec->p, ec->ctx));
  F(BN_mod_sub(c2, ec->p, c2, ec->p, ec->ctx));
  F(BN_mod_sqrt(c2, c2, ec->p, ec->ctx));

  F(BN_mod_sub(c3, c2, z, ec->p, ec->ctx));
  F(BN_mod_mul(c3, c3, i2, ec->p, ec->ctx));

  F(BN_mod_add(c4, c2, z, ec->p, ec->ctx));
  F(BN_mod_mul(c4, c4, i2, ec->p, ec->ctx));

  F(BN_mod_sqr(c5, z, ec->p, ec->ctx));
  F(BN_mod_mul(c5, c5, ec->three, ec->p, ec->ctx));
  F(BN_mod_inverse(c5, c5, ec->p, ec->ctx));

  F(BN_copy(u, r));

  F(BN_mod_sqr(t1, u, ec->p, ec->ctx));
  F(BN_mod_add(t2, t1, c1, ec->p, ec->ctx));
  F(BN_mod_mul(t3, t1, t2, ec->p, ec->ctx));
  F(bn_mod_fermat(t4, t3, ec->p, ec->ctx));
  F(BN_mod_sqr(t3, t1, ec->p, ec->ctx));
  F(BN_mod_mul(t3, t3, t4, ec->p, ec->ctx));
  F(BN_mod_mul(t3, t3, c2, ec->p, ec->ctx));
  F(BN_mod_sub(x1, c3, t3, ec->p, ec->ctx));
  F(BN_mod_sqr(gx1, x1, ec->p, ec->ctx));
  F(BN_mod_mul(gx1, gx1, x1, ec->p, ec->ctx));
  F(BN_mod_add(gx1, gx1, ec->b, ec->p, ec->ctx));
  e1 = bn_is_square(gx1, ec->p, ec->ctx);
  F(BN_mod_sub(x2, t3, c4, ec->p, ec->ctx));
  F(BN_mod_sqr(gx2, x2, ec->p, ec->ctx));
  F(BN_mod_mul(gx2, gx2, x2, ec->p, ec->ctx));
  F(BN_mod_add(gx2, gx2, ec->b, ec->p, ec->ctx));
  e2 = bn_is_square(gx2, ec->p, ec->ctx);
  e3 = e1 | e2;
  F(BN_mod_sqr(x3, t2, ec->p, ec->ctx));
  F(BN_mod_mul(x3, x3, t2, ec->p, ec->ctx));
  F(BN_mod_mul(x3, x3, t4, ec->p, ec->ctx));
  F(BN_mod_mul(x3, x3, c5, ec->p, ec->ctx));
  F(BN_mod_sub(x3, z, x3, ec->p, ec->ctx));
  F(BN_mod_sqr(gx3, x3, ec->p, ec->ctx));
  F(BN_mod_mul(gx3, gx3, x3, ec->p, ec->ctx));
  F(BN_mod_add(gx3, gx3, ec->b, ec->p, ec->ctx));
  F(BN_copy(x, e1 ? x1 : x2));
  F(BN_copy(gx, e1 ? gx1 : gx2));
  F(BN_copy(x, e3 ? x : x3));
  F(BN_copy(gx, e3 ? gx : gx3));
  F(BN_mod_sqrt(y, gx, ec->p, ec->ctx));
  e4 = BN_is_odd(y) == BN_is_odd(u);
  if (!e4) F(BN_mod_sub(y, ec->p, y, ec->p, ec->ctx));

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  /* Note: should be present with 1.1.1b */
  F(EC_POINT_set_affine_coordinates(ec->group, P, x, y, ec->ctx));
#else
  F(EC_POINT_set_affine_coordinates_GFp(ec->group, P, x, y, ec->ctx));
#endif

#undef F

  ret = 1;
fail:
  if (z != NULL) BN_free(z);
  if (c1 != NULL) BN_free(c1);
  if (c2 != NULL) BN_free(c2);
  if (c3 != NULL) BN_free(c3);
  if (c4 != NULL) BN_free(c4);
  if (c5 != NULL) BN_free(c5);
  if (u != NULL) BN_free(u);
  if (t1 != NULL) BN_free(t1);
  if (t2 != NULL) BN_free(t2);
  if (t3 != NULL) BN_free(t3);
  if (t4 != NULL) BN_free(t4);
  if (x1 != NULL) BN_free(x1);
  if (gx1 != NULL) BN_free(gx1);
  if (x2 != NULL) BN_free(x2);
  if (gx2 != NULL) BN_free(gx2);
  if (x3 != NULL) BN_free(x3);
  if (gx3 != NULL) BN_free(gx3);
  if (x != NULL) BN_free(x);
  if (gx != NULL) BN_free(gx);
  if (y != NULL) BN_free(y);
  if (i2 != NULL) BN_free(i2);

  if (!ret && P != NULL) {
    EC_POINT_free(P);
    P = NULL;
  }

  return P;
}

static BIGNUM *
bcrypto_ecdsa_svdwi(bcrypto_ecdsa_t *ec, const EC_POINT *P, unsigned int hint) {
  BIGNUM *z = BN_new();
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  BIGNUM *i2 = BN_new();
  BIGNUM *z2 = BN_new();
  BIGNUM *z3 = BN_new();
  BIGNUM *z4 = BN_new();
  BIGNUM *gz = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *t0 = BN_new();
  BIGNUM *t1 = BN_new();
  BIGNUM *t2 = BN_new();
  BIGNUM *t3 = BN_new();
  BIGNUM *t4 = BN_new();
  BIGNUM *t5 = BN_new();
  BIGNUM *x2z = BN_new();
  BIGNUM *c1 = BN_new();
  BIGNUM *c2 = BN_new();
  BIGNUM *c3 = BN_new();
  BIGNUM *d1 = BN_new();
  BIGNUM *d2 = BN_new();
  BIGNUM *u1 = BN_new();
  BIGNUM *u2 = BN_new();
  BIGNUM *u3 = BN_new();
  BIGNUM *u4 = BN_new();
  EC_POINT *Q = EC_POINT_new(ec->group);
  BIGNUM *x0 = BN_new();
  BIGNUM *u = BN_new();
  size_t shift = sizeof(unsigned int) * 8 - 1;
  unsigned int r = hint & 3;
  unsigned int s0, s1, s2, s3;
  int Z;
  int ret = 0;

  /*
   * Map:
   *
   *   g(x) = x^3 + b
   *   c = sqrt(-3 * z^2)
   *   t0 = 9 * (x^2 * z^2 + z^4)
   *   t1 = 18 * x * z^3
   *   t2 = 12 * g(z) * (x - z)
   *   t3 = sqrt(t0 - t1 + t2)
   *   t4 = t3 / 2 * z
   *   u1 = +-sqrt(g(z) * (c - 2 * x - z) / (c + 2 * x + z))
   *   u2 = +-sqrt(g(z) * (c + 2 * x + z) / (c - 2 * x - z))
   *   u3 = +-sqrt(((-x * z^2 + z^3) * 3) / 2 - g(z) + t4)
   *   u4 = +-sqrt(((-x * z^2 + z^3) * 3) / 2 - g(z) - t4)
   */

  if (z == NULL || x == NULL || y == NULL || i2 == NULL
      || z2 == NULL || z3 == NULL || z4 == NULL || gz == NULL
      || c == NULL || t0 == NULL || t1 == NULL || t2 == NULL
      || t3 == NULL || t4 == NULL || t5 == NULL || x2z == NULL
      || c1 == NULL || c2 == NULL || c3 == NULL || d1 == NULL
      || d2 == NULL || u1 == NULL || u2 == NULL || u3 == NULL
      || u4 == NULL || Q == NULL || x0 == NULL || u == NULL) {
    goto fail;
  }

#define F(x) if (!(x)) goto fail

  Z = bcrypto_ecdsa_uniform_z(ec->type);

  if (Z < 0) {
    F(BN_copy(z, ec->p));
    F(BN_sub_word(z, -Z));
  } else {
    F(BN_set_word(z, Z));
  }

  F(!EC_POINT_is_at_infinity(ec->group, P));

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  /* Note: should be present with 1.1.1b */
  F(EC_POINT_get_affine_coordinates(ec->group, P, x, y, ec->ctx));
#else
  F(EC_POINT_get_affine_coordinates_GFp(ec->group, P, x, y, ec->ctx));
#endif

  /* i2 = 1 / 2 */
  F(BN_set_word(i2, 2));
  F(BN_mod_inverse(i2, i2, ec->p, ec->ctx));

  F(BN_mod_sqr(z2, z, ec->p, ec->ctx));
  F(BN_mod_mul(z3, z2, z, ec->p, ec->ctx));
  F(BN_mod_sqr(z4, z2, ec->p, ec->ctx));

  /* gz = z^3 + b */
  F(BN_mod_add(gz, z3, ec->b, ec->p, ec->ctx));

  /* c = sqrt(-3 * z^2) */
  F(BN_mod_sqr(c, z, ec->p, ec->ctx));
  F(BN_mod_mul(c, c, ec->three, ec->p, ec->ctx));
  F(BN_mod_sub(c, ec->p, c, ec->p, ec->ctx));
  F(BN_mod_sqrt(c, c, ec->p, ec->ctx));

  /* t0 = 9 * (x^2 * z^2 + z^4) */
  F(BN_mod_sqr(t0, x, ec->p, ec->ctx));
  F(BN_mod_mul(t0, t0, z2, ec->p, ec->ctx));
  F(BN_mod_add(t0, t0, z4, ec->p, ec->ctx));
  F(BN_mul_word(t0, 9));
  F(BN_mod(t0, t0, ec->p, ec->ctx));

  /* t1 = 18 * x * z^3 */
  F(BN_mod_mul(t1, x, z3, ec->p, ec->ctx));
  F(BN_mul_word(t1, 18));
  F(BN_mod(t1, t1, ec->p, ec->ctx));

  /* t2 = 12 * g(z) * (x - z) */
  F(BN_mod_sub(t2, x, z, ec->p, ec->ctx));
  F(BN_mod_mul(t2, t2, gz, ec->p, ec->ctx));
  F(BN_mul_word(t2, 12));
  F(BN_mod(t2, t2, ec->p, ec->ctx));

  /* t3 = sqrt(t0 - t1 + t2) */
  F(BN_mod_sub(t3, t0, t1, ec->p, ec->ctx));
  F(BN_mod_add(t3, t3, t2, ec->p, ec->ctx));
  s0 = BN_mod_sqrt(t3, t3, ec->p, ec->ctx) != 0;
  s1 = ((r - 2) >> shift) | s0;

  /* t4 = t3 / 2 * z */
  F(BN_mod_mul(t4, t3, i2, ec->p, ec->ctx));
  F(BN_mod_mul(t4, t4, z, ec->p, ec->ctx));

  /* t5 = ((-x * z^2 + z^3) * 3) / 2 - g(z) */
  F(BN_mod_mul(t5, x, z2, ec->p, ec->ctx));
  F(BN_mod_sub(t5, ec->p, t5, ec->p, ec->ctx));
  F(BN_mod_add(t5, t5, z3, ec->p, ec->ctx));
  F(BN_mod_mul(t5, t5, ec->three, ec->p, ec->ctx));
  F(BN_mod_mul(t5, t5, i2, ec->p, ec->ctx));
  F(BN_mod_sub(t5, t5, gz, ec->p, ec->ctx));

  /* x2z = 2 * x - z */
  F(BN_mod_mul(x2z, x, ec->two, ec->p, ec->ctx));
  F(BN_mod_add(x2z, x2z, z, ec->p, ec->ctx));

  /* c1 = c - 2 * x - z */
  F(BN_mod_sub(c1, c, x2z, ec->p, ec->ctx));

  /* c2 = c + 2 * x + z */
  F(BN_mod_add(c2, c, x2z, ec->p, ec->ctx));

  /* compute denominators */
  F(BN_mod_mul(c3, c1, c2, ec->p, ec->ctx));
  F(bn_mod_fermat(c3, c3, ec->p, ec->ctx));
  F(BN_mod_mul(d1, c3, c1, ec->p, ec->ctx));
  F(BN_mod_mul(d2, c3, c2, ec->p, ec->ctx));

  /* u1 = g(z) * (c - 2 * x - z) / (c + 2 * x + z) */
  F(BN_mod_mul(u1, gz, c1, ec->p, ec->ctx));
  F(BN_mod_mul(u1, u1, d1, ec->p, ec->ctx));

  /* u2 = g(z) * (c + 2 * x + z) / (c - 2 * x - z) */
  F(BN_mod_mul(u2, gz, c2, ec->p, ec->ctx));
  F(BN_mod_mul(u2, u2, d2, ec->p, ec->ctx));

  /* u3 = ((-x * z^2 + z^3) * 3) / 2 - g(z) + t4 */
  F(BN_mod_add(u3, t5, t4, ec->p, ec->ctx));

  /* u4 = ((-x * z^2 + z^3) * 3) / 2 - g(z) - t4 */
  F(BN_mod_sub(u4, t5, t4, ec->p, ec->ctx));

  /* u = sqrt(ur) */
  BIGNUM *U[4] = { u1, u2, u3, u4 };

  s2 = BN_mod_sqrt(u, U[r], ec->p, ec->ctx) != 0;
  F(Q = bcrypto_ecdsa_svdw(ec, u));

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  /* Note: should be present with 1.1.1b */
  F(EC_POINT_get_affine_coordinates(ec->group, Q, x0, NULL, ec->ctx));
#else
  F(EC_POINT_get_affine_coordinates_GFp(ec->group, Q, x0, NULL, ec->ctx));
#endif

  s3 = BN_cmp(x0, x) == 0;

  if (BN_is_odd(u) ^ BN_is_odd(y))
    F(BN_mod_sub(u, ec->p, u, ec->p, ec->ctx));

  F(s1 & s2 & s3);
#undef F

  ret = 1;
fail:
  if (z != NULL) BN_free(z);
  if (x != NULL) BN_free(x);
  if (y != NULL) BN_free(y);
  if (i2 != NULL) BN_free(i2);
  if (z2 != NULL) BN_free(z2);
  if (z3 != NULL) BN_free(z3);
  if (z4 != NULL) BN_free(z4);
  if (gz != NULL) BN_free(gz);
  if (c != NULL) BN_free(c);
  if (t0 != NULL) BN_free(t0);
  if (t1 != NULL) BN_free(t1);
  if (t2 != NULL) BN_free(t2);
  if (t3 != NULL) BN_free(t3);
  if (t4 != NULL) BN_free(t4);
  if (t5 != NULL) BN_free(t5);
  if (x2z != NULL) BN_free(x2z);
  if (c1 != NULL) BN_free(c1);
  if (c2 != NULL) BN_free(c2);
  if (c3 != NULL) BN_free(c3);
  if (d1 != NULL) BN_free(d1);
  if (d2 != NULL) BN_free(d2);
  if (u1 != NULL) BN_free(u1);
  if (u2 != NULL) BN_free(u2);
  if (u3 != NULL) BN_free(u3);
  if (u4 != NULL) BN_free(u4);
  if (Q != NULL) EC_POINT_free(Q);
  if (x0 != NULL) BN_free(x0);

  if (!ret && u != NULL) {
    BN_free(u);
    u = NULL;
  }

  return u;
}

static EC_POINT *
bcrypto_ecdsa_point_from_uniform(bcrypto_ecdsa_t *ec, const BIGNUM *u) {
  switch (bcrypto_ecdsa_uniform_type(ec->type)) {
    case BCRYPTO_ECDSA_ICART:
#ifdef BCRYPTO_ECDSA_WITH_ICART
      return bcrypto_ecdsa_icart(ec, u);
#endif
    case BCRYPTO_ECDSA_SSWU:
      return bcrypto_ecdsa_sswu(ec, u);
    case BCRYPTO_ECDSA_SVDW:
      return bcrypto_ecdsa_svdw(ec, u);
    default:
      return NULL;
  }
}

static BIGNUM *
bcrypto_ecdsa_point_to_uniform(bcrypto_ecdsa_t *ec,
                               const EC_POINT *P,
                               unsigned int hint) {
  switch (bcrypto_ecdsa_uniform_type(ec->type)) {
    case BCRYPTO_ECDSA_ICART:
#ifdef BCRYPTO_ECDSA_WITH_ICART
      return NULL;
#endif
    case BCRYPTO_ECDSA_SSWU:
      return bcrypto_ecdsa_sswui(ec, P, hint);
    case BCRYPTO_ECDSA_SVDW:
      return bcrypto_ecdsa_svdwi(ec, P, hint);
    default:
      return NULL;
  }
}

#endif
