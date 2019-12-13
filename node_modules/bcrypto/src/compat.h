#ifndef _BCRYPTO_COMPAT_HH
#define _BCRYPTO_COMPAT_HH

#include "openssl/opensslv.h"

#if OPENSSL_VERSION_NUMBER >= 0x1010008fL
#define BCRYPTO_HAS_DSA
#define BCRYPTO_HAS_RSA
#define BCRYPTO_HAS_ECDSA
#endif

#ifdef OPENSSL_IS_BORINGSSL
// BoringSSL uses a custom allocator.
// Switch to the regular libc allocator.
#define FIX_BORINGSSL(data, len) do { \
  if ((data) != NULL && (len) != 0) {    \
    void *__boring_ptr = malloc(len);    \
                                         \
    assert(__boring_ptr != NULL);        \
                                         \
    memcpy(__boring_ptr, (data), (len)); \
    OPENSSL_free((data));                \
                                         \
    (data) = __boring_ptr;               \
  }                                      \
} while (0)
#else
#define FIX_BORINGSSL(data, len) do { } while (0)
#endif

#endif
