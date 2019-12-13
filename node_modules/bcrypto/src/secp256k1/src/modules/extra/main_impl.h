/*
 * main_impl.h - helpers module for libsecp256k1
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013, Pieter Wuille
 *   https://github.com/bitcoin-core/secp256k1
 */

#ifndef SECP256K1_MODULE_EXTRA_MAIN_H
#define SECP256K1_MODULE_EXTRA_MAIN_H

#include "../../../include/secp256k1_extra.h"

/* Use this until #668 gets merged: */
/* https://github.com/bitcoin-core/secp256k1/pull/668 */
int
secp256k1_ec_privkey_negate_safe(const secp256k1_context *ctx,
                                 unsigned char *seckey) {
  secp256k1_scalar sec;
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(seckey != NULL);

  secp256k1_scalar_set_b32(&sec, seckey, &overflow);

  if (overflow || secp256k1_scalar_is_zero(&sec))
    return 0;

  secp256k1_scalar_negate(&sec, &sec);
  secp256k1_scalar_get_b32(seckey, &sec);
  secp256k1_scalar_clear(&sec);

  return 1;
}

int
secp256k1_ec_privkey_invert(const secp256k1_context *ctx,
                            unsigned char *seckey) {
  secp256k1_scalar sec;
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(seckey != NULL);

  secp256k1_scalar_set_b32(&sec, seckey, &overflow);

  if (overflow || secp256k1_scalar_is_zero(&sec))
    return 0;

  secp256k1_scalar_inverse(&sec, &sec);
  secp256k1_scalar_get_b32(seckey, &sec);
  secp256k1_scalar_clear(&sec);

  return 1;
}

int
secp256k1_ec_privkey_reduce(const secp256k1_context* ctx,
                            unsigned char *output,
                            const unsigned char *bytes,
                            size_t len) {
  secp256k1_scalar sec;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(output != NULL);

  if (len > 32)
    len = 32;

  memset(output, 0x00, 32 - len);
  memcpy(output + 32 - len, bytes, len);

  secp256k1_scalar_set_b32(&sec, output, NULL);

  if (secp256k1_scalar_is_zero(&sec))
    return 0;

  secp256k1_scalar_get_b32(output, &sec);
  secp256k1_scalar_clear(&sec);

  return 1;
}

#endif /* SECP256K1_MODULE_EXTRA_MAIN_H */
