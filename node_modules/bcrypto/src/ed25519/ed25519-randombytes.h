#include "../random/random.h"

int
bcrypto_ed25519_randombytes(void *p, size_t len) {
  return bcrypto_random(p, len);
}
