#!/bin/sh

# GMP support checking
# Copyright (c) 2019, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/bcrypto
#
# Tested with shells: bash, dash, busybox
# Tested with compilers: gcc, clang
#
# We try to compile some code specifically
# written to fail if the compiler is linking
# to mini-gmp instead of gmp.

if test -z "$CC"; then
  CC='gcc'
fi

CODE=`
  echo '#include <gmp.h>'
  echo ''
  echo 'int main(void) {'
  echo '  mpz_t x, y;'
  echo '  mpz_inits(x, y, NULL);'
  echo '  mpz_set_ui(x, 0);'
  echo '  mpz_set_ui(y, 3);'
  echo '  return mpz_jacobi(x, y);'
  echo '}'
`

if echo "$CODE" | "$CC" -o /dev/null -lgmp -xc - > /dev/null 2>& 1; then
  echo 'true'
else
  echo 'false'
fi

exit 0
