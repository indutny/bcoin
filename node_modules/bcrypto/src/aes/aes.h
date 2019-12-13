#ifndef _BCRYPTO_CIPHER_H
#define _BCRYPTO_CIPHER_H

#define BCRYPTO_AES_ENCIPHER_SIZE(len) ((len) + (16 - ((len) % 16)));
#define BCRYPTO_AES_DECIPHER_SIZE(len) (len)

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

int
bcrypto_aes_encipher(uint8_t *out,
                     size_t *outlen,
                     const uint8_t *data,
                     const size_t datalen,
                     const uint8_t *key,
                     const uint8_t *iv);

int
bcrypto_aes_decipher(uint8_t *out,
                     size_t *outlen,
                     const uint8_t *data,
                     const size_t datalen,
                     const uint8_t *key,
                     const uint8_t *iv);

#if defined(__cplusplus)
}
#endif

#endif
