#ifndef _BCRYPTO_ECDSA_H
#define _BCRYPTO_ECDSA_H

#include "../compat.h"

#ifdef BCRYPTO_HAS_ECDSA

#include <stdint.h>
#include <stdlib.h>
#include "openssl/ecdsa.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define BCRYPTO_HAS_ECDSA
#define BCRYPTO_ECDSA_MAX_FIELD_SIZE 66
#define BCRYPTO_ECDSA_MAX_SCALAR_SIZE 66
#define BCRYPTO_ECDSA_MAX_PUB_SIZE (1 + BCRYPTO_ECDSA_MAX_FIELD_SIZE * 2)
#define BCRYPTO_ECDSA_MAX_SIG_SIZE \
  (BCRYPTO_ECDSA_MAX_FIELD_SIZE + BCRYPTO_ECDSA_MAX_SCALAR_SIZE)
#define BCRYPTO_ECDSA_MAX_DER_SIZE (9 + BCRYPTO_ECDSA_MAX_SIG_SIZE)

#define BCRYPTO_ECDSA_ICART 0
#define BCRYPTO_ECDSA_SSWU 1
#define BCRYPTO_ECDSA_SVDW 2

typedef struct bcrypto_ecdsa_pubkey_s {
  uint8_t x[BCRYPTO_ECDSA_MAX_FIELD_SIZE];
  uint8_t y[BCRYPTO_ECDSA_MAX_FIELD_SIZE];
} bcrypto_ecdsa_pubkey_t;

typedef struct bcrypto_ecdsa_sig_s {
  uint8_t r[BCRYPTO_ECDSA_MAX_FIELD_SIZE];
  uint8_t s[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];
  int param;
} bcrypto_ecdsa_sig_t;

typedef struct bcrypto_ecdsa_s {
  int type;
  int hash_type;
  const EVP_MD *hash;
  size_t hash_size;
  int has_schnorr;
  BN_CTX *ctx;
  EC_KEY *key;
  const EC_GROUP *group;
  EC_POINT *point;
  size_t bits;
  size_t size;
  BIGNUM *n;
  BIGNUM *nh;
  BIGNUM *ns1;
  BIGNUM *p;
  BIGNUM *a;
  BIGNUM *b;
  BIGNUM *one;
  BIGNUM *two;
  BIGNUM *three;
  const EC_POINT *g;
  size_t scalar_bits;
  size_t scalar_size;
  size_t sig_size;
  size_t schnorr_size;
  uint8_t prime[BCRYPTO_ECDSA_MAX_FIELD_SIZE];
  uint8_t zero[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];
  uint8_t order[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];
  uint8_t half[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];
  int initialized;
} bcrypto_ecdsa_t;

/*
 * Public Key
 */

void
bcrypto_ecdsa_pubkey_encode(bcrypto_ecdsa_t *ec,
                            uint8_t *out,
                            size_t *out_len,
                            const bcrypto_ecdsa_pubkey_t *pub,
                            int compress);

int
bcrypto_ecdsa_pubkey_decode(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *pub,
                            const uint8_t *raw,
                            size_t raw_len);

/*
 * Signature
 */

void
bcrypto_ecdsa_sig_encode(bcrypto_ecdsa_t *ec,
                         uint8_t *out,
                         const bcrypto_ecdsa_sig_t *sig);

int
bcrypto_ecdsa_sig_decode(bcrypto_ecdsa_t *ec,
                         bcrypto_ecdsa_sig_t *sig,
                         const uint8_t *raw);

int
bcrypto_ecdsa_sig_encode_der(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             size_t *out_len,
                             const bcrypto_ecdsa_sig_t *sig);

int
bcrypto_ecdsa_sig_decode_der(bcrypto_ecdsa_t *ec,
                             bcrypto_ecdsa_sig_t *sig,
                             const uint8_t *raw,
                             size_t raw_len);

void
bcrypto_ecdsa_sig_normalize(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_sig_t *out,
                            const bcrypto_ecdsa_sig_t *sig);

int
bcrypto_ecdsa_sig_is_low_s(bcrypto_ecdsa_t *ec,
                           const bcrypto_ecdsa_sig_t *sig);

/*
 * ECDSA
 */

int
bcrypto_ecdsa_init(bcrypto_ecdsa_t *ec, const char *name);

void
bcrypto_ecdsa_uninit(bcrypto_ecdsa_t *ec);

int
bcrypto_ecdsa_privkey_generate(bcrypto_ecdsa_t *ec, uint8_t *priv);

int
bcrypto_ecdsa_privkey_verify(bcrypto_ecdsa_t *ec, const uint8_t *priv);

int
bcrypto_ecdsa_privkey_export(bcrypto_ecdsa_t *ec,
                             uint8_t **out,
                             size_t *out_len,
                             const uint8_t *priv,
                             int flags);

int
bcrypto_ecdsa_privkey_import(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *raw,
                             size_t raw_len);

int
bcrypto_ecdsa_privkey_export_pkcs8(bcrypto_ecdsa_t *ec,
                                   uint8_t **out,
                                   size_t *out_len,
                                   const uint8_t *priv,
                                   int compress);

int
bcrypto_ecdsa_privkey_import_pkcs8(bcrypto_ecdsa_t *ec,
                                   uint8_t *out,
                                   const uint8_t *raw,
                                   size_t raw_len);

int
bcrypto_ecdsa_privkey_tweak_add(bcrypto_ecdsa_t *ec,
                                uint8_t *out,
                                const uint8_t *priv,
                                const uint8_t *tweak);

int
bcrypto_ecdsa_privkey_tweak_mul(bcrypto_ecdsa_t *ec,
                                uint8_t *out,
                                const uint8_t *priv,
                                const uint8_t *tweak);

int
bcrypto_ecdsa_privkey_reduce(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *priv,
                             size_t priv_len);

int
bcrypto_ecdsa_privkey_negate(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *priv);

int
bcrypto_ecdsa_privkey_invert(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *priv);

int
bcrypto_ecdsa_pubkey_create(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *pub,
                            const uint8_t *priv);

int
bcrypto_ecdsa_pubkey_from_uniform(bcrypto_ecdsa_t *ec,
                                  bcrypto_ecdsa_pubkey_t *out,
                                  const uint8_t *bytes);

int
bcrypto_ecdsa_pubkey_to_uniform(bcrypto_ecdsa_t *ec,
                                uint8_t *bytes,
                                const bcrypto_ecdsa_pubkey_t *pub,
                                unsigned int hint);

int
bcrypto_ecdsa_pubkey_from_hash(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_pubkey_t *out,
                               const uint8_t *bytes);

int
bcrypto_ecdsa_pubkey_to_hash(bcrypto_ecdsa_t *ec,
                             uint8_t *bytes,
                             const bcrypto_ecdsa_pubkey_t *pub);

int
bcrypto_ecdsa_pubkey_export_spki(bcrypto_ecdsa_t *ec,
                                 uint8_t **out,
                                 size_t *out_len,
                                 const bcrypto_ecdsa_pubkey_t *pub,
                                 int compress);

int
bcrypto_ecdsa_pubkey_import_spki(bcrypto_ecdsa_t *ec,
                                 bcrypto_ecdsa_pubkey_t *out,
                                 const uint8_t *raw,
                                 size_t raw_len);

int
bcrypto_ecdsa_pubkey_tweak_add(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_pubkey_t *out,
                               const bcrypto_ecdsa_pubkey_t *pub,
                               const uint8_t *tweak);

int
bcrypto_ecdsa_pubkey_tweak_mul(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_pubkey_t *out,
                               const bcrypto_ecdsa_pubkey_t *pub,
                               const uint8_t *tweak);

int
bcrypto_ecdsa_pubkey_add(bcrypto_ecdsa_t *ec,
                         bcrypto_ecdsa_pubkey_t *out,
                         const bcrypto_ecdsa_pubkey_t *pub1,
                         const bcrypto_ecdsa_pubkey_t *pub2);

int
bcrypto_ecdsa_pubkey_combine(bcrypto_ecdsa_t *ec,
                             bcrypto_ecdsa_pubkey_t *out,
                             const bcrypto_ecdsa_pubkey_t *pubs,
                             size_t length);

int
bcrypto_ecdsa_pubkey_negate(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *out,
                            const bcrypto_ecdsa_pubkey_t *pub);

int
bcrypto_ecdsa_sign(bcrypto_ecdsa_t *ec,
                   bcrypto_ecdsa_sig_t *sig,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *priv);

int
bcrypto_ecdsa_sign_recoverable(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_sig_t *sig,
                               const uint8_t *msg,
                               size_t msg_len,
                               const uint8_t *priv);

int
bcrypto_ecdsa_verify(bcrypto_ecdsa_t *ec,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_ecdsa_sig_t *sig,
                     const bcrypto_ecdsa_pubkey_t *pub);

int
bcrypto_ecdsa_recover(bcrypto_ecdsa_t *ec,
                      bcrypto_ecdsa_pubkey_t *pub,
                      const uint8_t *msg,
                      size_t msg_len,
                      const bcrypto_ecdsa_sig_t *sig,
                      int param);

int
bcrypto_ecdsa_derive(bcrypto_ecdsa_t *ec,
                     bcrypto_ecdsa_pubkey_t *out,
                     const bcrypto_ecdsa_pubkey_t *pub,
                     const uint8_t *priv);

/*
 * Signature
 */

void
bcrypto_schnorr_sig_encode(bcrypto_ecdsa_t *ec,
                           uint8_t *out,
                           const bcrypto_ecdsa_sig_t *sig);

int
bcrypto_schnorr_sig_decode(bcrypto_ecdsa_t *ec,
                           bcrypto_ecdsa_sig_t *sig,
                           const uint8_t *raw);

/*
 * Schnorr
 */

int
bcrypto_schnorr_sign(bcrypto_ecdsa_t *ec,
                     bcrypto_ecdsa_sig_t *sig,
                     const uint8_t *msg,
                     const uint8_t *priv);

int
bcrypto_schnorr_verify(bcrypto_ecdsa_t *ec,
                       const uint8_t *msg,
                       const bcrypto_ecdsa_sig_t *sig,
                       const bcrypto_ecdsa_pubkey_t *pub);

int
bcrypto_schnorr_verify_batch(bcrypto_ecdsa_t *ec,
                             const uint8_t **msgs,
                             const bcrypto_ecdsa_sig_t *sigs,
                             const bcrypto_ecdsa_pubkey_t *pubs,
                             size_t length);

#if defined(__cplusplus)
}
#endif

#endif

#endif
