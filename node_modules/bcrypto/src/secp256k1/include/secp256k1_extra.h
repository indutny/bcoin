#ifndef SECP256K1_EXTRA_H
#define SECP256K1_EXTRA_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Negates a private key in place.
 *
 *  Returns: 1 if seckey was successfully negated and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  In/Out: seckey:     pointer to the 32-byte private key to be negated. The private
 *                      key should be valid according to secp256k1_ec_seckey_verify
 *                      (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_negate_safe(const secp256k1_context *ctx,
                                 unsigned char *seckey) SECP256K1_ARG_NONNULL(1)
                                                        SECP256K1_ARG_NONNULL(2);

/** Inverts a private key in place.
 *
 *  Returns: 1 if seckey was successfully inverted and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  In/Out: seckey:     pointer to the 32-byte private key to be inverted. The private
 *                      key should be valid according to secp256k1_ec_seckey_verify
 *                      (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_invert(const secp256k1_context *ctx,
                            unsigned char *seckey) SECP256K1_ARG_NONNULL(1)
                                                   SECP256K1_ARG_NONNULL(2);

/** Reduces an arbitrary sized byte array to a private key.
 *
 *  Returns: 1 if bytes were successfully reduced and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    output:     pointer to a 32-byte array to be filled by the function
 *  In:     bytes:      pointer to an arbitrary sized byte array
 *          len:        byte array length
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_reduce(const secp256k1_context *ctx,
                            unsigned char *output,
                            const unsigned char *bytes,
                            size_t len) SECP256K1_ARG_NONNULL(1)
                                        SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_EXTRA_H */
