#ifndef _BCRYPTO_PBKDF2_H
#define _BCRYPTO_PBKDF2_H

#include <stdint.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

int
bcrypto_pbkdf2(uint8_t *key,
               const char *name,
               const uint8_t *pass,
               size_t passlen,
               const uint8_t *salt,
               size_t saltlen,
               uint32_t iter,
               size_t keylen);

int
bcrypto_pbkdf2_has_hash(const char *name);

#if defined(__cplusplus)
}
#endif

#endif
