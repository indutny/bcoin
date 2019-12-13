#ifndef _BCRYPTO_BASE58_H
#define _BCRYPTO_BASE58_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

int
bcrypto_base58_encode(char **str, size_t *strlen,
                      const uint8_t *data, size_t datalen);

int
bcrypto_base58_decode(uint8_t **data, size_t *datalen,
                      const char *str, size_t strlen);

int
bcrypto_base58_test(const char *str, size_t strlen);

#if defined(__cplusplus)
}
#endif

#endif
