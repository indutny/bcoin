#ifndef _BCRYPTO_DSA_H
#define _BCRYPTO_DSA_H

#include "../compat.h"

#ifdef BCRYPTO_HAS_DSA

#include <stdlib.h>
#include <stdint.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct bcrypto_dsa_key_s {
  uint8_t *slab;
  uint8_t *pd;
  size_t pl;
  uint8_t *qd;
  size_t ql;
  uint8_t *gd;
  size_t gl;
  uint8_t *yd;
  size_t yl;
  uint8_t *xd;
  size_t xl;
} bcrypto_dsa_key_t;

void
bcrypto_dsa_key_init(bcrypto_dsa_key_t *key);

void
bcrypto_dsa_key_free(bcrypto_dsa_key_t *key);

bcrypto_dsa_key_t *
bcrypto_dsa_params_generate(int bits);

int
bcrypto_dsa_params_verify(const bcrypto_dsa_key_t *params);

int
bcrypto_dsa_params_export(uint8_t **out,
                          size_t *out_len,
                          const bcrypto_dsa_key_t *params);

bcrypto_dsa_key_t *
bcrypto_dsa_params_import(const uint8_t *raw, size_t raw_len);

bcrypto_dsa_key_t *
bcrypto_dsa_privkey_create(const bcrypto_dsa_key_t *params);

int
bcrypto_dsa_privkey_compute(uint8_t **out,
                            size_t *out_len,
                            const bcrypto_dsa_key_t *priv);

int
bcrypto_dsa_privkey_verify(const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_privkey_export(uint8_t **out,
                           size_t *out_len,
                           const bcrypto_dsa_key_t *priv);

bcrypto_dsa_key_t *
bcrypto_dsa_privkey_import(const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_privkey_export_pkcs8(uint8_t **out,
                                 size_t *out_len,
                                 const bcrypto_dsa_key_t *priv);

bcrypto_dsa_key_t *
bcrypto_dsa_privkey_import_pkcs8(const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_pubkey_verify(const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_pubkey_export(uint8_t **out,
                          size_t *out_len,
                          const bcrypto_dsa_key_t *pub);

bcrypto_dsa_key_t *
bcrypto_dsa_pubkey_import(const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_pubkey_export_spki(uint8_t **out,
                               size_t *out_len,
                               const bcrypto_dsa_key_t *pub);

bcrypto_dsa_key_t *
bcrypto_dsa_pubkey_import_spki(const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_sig_export(uint8_t **out,
                       size_t *out_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       size_t size);

int
bcrypto_dsa_sig_import(uint8_t **out,
                       size_t *out_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       size_t size);

int
bcrypto_dsa_sign(uint8_t **out,
                 size_t *out_len,
                 const uint8_t *msg,
                 size_t msg_len,
                 const bcrypto_dsa_key_t *priv);

int
bcrypto_dsa_sign_der(uint8_t **out,
                     size_t *out_len,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_dsa_key_t *priv);

int
bcrypto_dsa_verify(const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len,
                   const bcrypto_dsa_key_t *pub);

int
bcrypto_dsa_verify_der(const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       const bcrypto_dsa_key_t *pub);

int
bcrypto_dsa_derive(uint8_t **out,
                   size_t *out_len,
                   const bcrypto_dsa_key_t *pub,
                   const bcrypto_dsa_key_t *priv);

#if defined(__cplusplus)
}
#endif

#endif

#endif
