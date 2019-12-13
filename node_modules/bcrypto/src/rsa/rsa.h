#ifndef _BCRYPTO_RSA_H
#define _BCRYPTO_RSA_H

#include "../compat.h"

#ifdef BCRYPTO_HAS_RSA

#include <stdlib.h>
#include <stdint.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct bcrypto_rsa_key_s {
  uint8_t *slab;
  uint8_t *nd;
  size_t nl;
  uint8_t *ed;
  size_t el;
  uint8_t *dd;
  size_t dl;
  uint8_t *pd;
  size_t pl;
  uint8_t *qd;
  size_t ql;
  uint8_t *dpd;
  size_t dpl;
  uint8_t *dqd;
  size_t dql;
  uint8_t *qid;
  size_t qil;
} bcrypto_rsa_key_t;

void
bcrypto_rsa_key_init(bcrypto_rsa_key_t *key);

void
bcrypto_rsa_key_free(bcrypto_rsa_key_t *key);

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_generate(int bits, unsigned long long exponent);

int
bcrypto_rsa_privkey_compute(bcrypto_rsa_key_t **out,
                            const bcrypto_rsa_key_t *priv);

int
bcrypto_rsa_privkey_verify(const bcrypto_rsa_key_t *priv);

int
bcrypto_rsa_privkey_export(uint8_t **out,
                           size_t *out_len,
                           const bcrypto_rsa_key_t *priv);

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import(const uint8_t *raw, size_t raw_len);

int
bcrypto_rsa_privkey_export_pkcs8(uint8_t **out,
                                 size_t *out_len,
                                 const bcrypto_rsa_key_t *priv);

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import_pkcs8(const uint8_t *raw, size_t raw_len);

int
bcrypto_rsa_pubkey_verify(const bcrypto_rsa_key_t *pub);

int
bcrypto_rsa_pubkey_export(uint8_t **out,
                          size_t *out_len,
                          const bcrypto_rsa_key_t *pub);

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import(const uint8_t *raw, size_t raw_len);

int
bcrypto_rsa_pubkey_export_spki(uint8_t **out,
                               size_t *out_len,
                               const bcrypto_rsa_key_t *pub);

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import_spki(const uint8_t *raw, size_t raw_len);

int
bcrypto_rsa_sign(uint8_t **out,
                 size_t *out_len,
                 const char *alg,
                 const uint8_t *msg,
                 size_t msg_len,
                 const bcrypto_rsa_key_t *priv);

int
bcrypto_rsa_verify(const char *alg,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len,
                   const bcrypto_rsa_key_t *pub);

int
bcrypto_rsa_encrypt(uint8_t **out,
                    size_t *out_len,
                    const uint8_t *pt,
                    size_t pt_len,
                    const bcrypto_rsa_key_t *pub);

int
bcrypto_rsa_decrypt(uint8_t **out,
                    size_t *out_len,
                    const uint8_t *ct,
                    size_t ct_len,
                    const bcrypto_rsa_key_t *priv);

int
bcrypto_rsa_encrypt_oaep(uint8_t **out,
                         size_t *out_len,
                         const char *alg,
                         const uint8_t *pt,
                         size_t pt_len,
                         const bcrypto_rsa_key_t *pub,
                         const uint8_t *label,
                         size_t label_len);

int
bcrypto_rsa_decrypt_oaep(uint8_t **out,
                         size_t *out_len,
                         const char *alg,
                         const uint8_t *ct,
                         size_t ct_len,
                         const bcrypto_rsa_key_t *priv,
                         const uint8_t *label,
                         size_t label_len);

int
bcrypto_rsa_sign_pss(uint8_t **out,
                     size_t *out_len,
                     const char *alg,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_rsa_key_t *priv,
                     int salt_len);

int
bcrypto_rsa_verify_pss(const char *alg,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       const bcrypto_rsa_key_t *pub,
                       int salt_len);

int
bcrypto_rsa_encrypt_raw(uint8_t **out,
                        size_t *out_len,
                        const uint8_t *pt,
                        size_t pt_len,
                        const bcrypto_rsa_key_t *pub);

int
bcrypto_rsa_decrypt_raw(uint8_t **out,
                        size_t *out_len,
                        const uint8_t *ct,
                        size_t ct_len,
                        const bcrypto_rsa_key_t *priv);

int
bcrypto_rsa_veil(uint8_t **out,
                 size_t *out_len,
                 const uint8_t *ct,
                 size_t ct_len,
                 size_t bits,
                 const bcrypto_rsa_key_t *pub);

int
bcrypto_rsa_unveil(uint8_t **out,
                   size_t *out_len,
                   const uint8_t *veiled,
                   size_t veiled_len,
                   size_t bits,
                   const bcrypto_rsa_key_t *pub);

int
bcrypto_rsa_has_hash(const char *alg);

#if defined(__cplusplus)
}
#endif

#endif

#endif
