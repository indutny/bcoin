#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include "openssl/rand.h"
#include "random.h"

void
bcrypto_poll(void) {
  for (;;) {
    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/rand_lib.c#L792
    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/drbg_lib.c#L988
    int status = RAND_status();

    assert(status >= 0);

    if (status != 0)
      break;

    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/rand_lib.c#L376
    // https://github.com/openssl/openssl/blob/32f803d/crypto/rand/drbg_lib.c#L471
    if (RAND_poll() == 0)
      break;
  }
}

int
bcrypto_random(void *dst, size_t len) {
  if (len > (size_t)INT_MAX)
    return 0;

  bcrypto_poll();

  return RAND_bytes((unsigned char *)dst, (int)len) == 1;
}
