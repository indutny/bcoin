/*
  Public domain by Andrew M. <liquidsun@gmail.com>
  See: https://github.com/floodyberry/curve25519-donna

  Curve25519 implementation agnostic helpers
*/

static const bignum25519 ALIGN(16) ge25519_sqrtneg1;

/*
 * In:  b =   2^5 - 2^0
 * Out: b = 2^250 - 2^0
 */
static void
curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b) {
  bignum25519 ALIGN(16) t0,c;

  /* 2^5  - 2^0 */ /* b */
  /* 2^10 - 2^5 */ curve25519_square_times(t0, b, 5);
  /* 2^10 - 2^0 */ curve25519_mul_noinline(b, t0, b);
  /* 2^20 - 2^10 */ curve25519_square_times(t0, b, 10);
  /* 2^20 - 2^0 */ curve25519_mul_noinline(c, t0, b);
  /* 2^40 - 2^20 */ curve25519_square_times(t0, c, 20);
  /* 2^40 - 2^0 */ curve25519_mul_noinline(t0, t0, c);
  /* 2^50 - 2^10 */ curve25519_square_times(t0, t0, 10);
  /* 2^50 - 2^0 */ curve25519_mul_noinline(b, t0, b);
  /* 2^100 - 2^50 */ curve25519_square_times(t0, b, 50);
  /* 2^100 - 2^0 */ curve25519_mul_noinline(c, t0, b);
  /* 2^200 - 2^100 */ curve25519_square_times(t0, c, 100);
  /* 2^200 - 2^0 */ curve25519_mul_noinline(t0, t0, c);
  /* 2^250 - 2^50 */ curve25519_square_times(t0, t0, 50);
  /* 2^250 - 2^0 */ curve25519_mul_noinline(b, t0, b);
}

/*
 * z^(p - 2) = z(2^255 - 21)
 */
static void
curve25519_recip(bignum25519 out, const bignum25519 z) {
  bignum25519 ALIGN(16) a,t0,b;

  /* 2 */ curve25519_square_times(a, z, 1); /* a = 2 */
  /* 8 */ curve25519_square_times(t0, a, 2);
  /* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
  /* 11 */ curve25519_mul_noinline(a, b, a); /* a = 11 */
  /* 22 */ curve25519_square_times(t0, a, 1);
  /* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
  /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
  /* 2^255 - 2^5 */ curve25519_square_times(b, b, 5);
  /* 2^255 - 21 */ curve25519_mul_noinline(out, b, a);
}

/*
 * z^((p-5)/8) = z^(2^252 - 3)
 */
static void
curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z) {
  bignum25519 ALIGN(16) b,c,t0;

  /* 2 */ curve25519_square_times(c, z, 1); /* c = 2 */
  /* 8 */ curve25519_square_times(t0, c, 2); /* t0 = 8 */
  /* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
  /* 11 */ curve25519_mul_noinline(c, b, c); /* c = 11 */
  /* 22 */ curve25519_square_times(t0, c, 1);
  /* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
  /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
  /* 2^252 - 2^2 */ curve25519_square_times(b, b, 2);
  /* 2^252 - 3 */ curve25519_mul_noinline(two252m3, b, z);
}

/*
 * z^((p+3)/8) = z^(2^252 - 2)
 */
static void
curve25519_pow_two252m2(bignum25519 two252m2, const bignum25519 z) {
  bignum25519 ALIGN(16) b,c,t0;

  /* 2 */ curve25519_square_times(c, z, 1); /* c = 2 */
  /* 8 */ curve25519_square_times(t0, c, 2); /* t0 = 8 */
  /* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
  /* 11 */ curve25519_mul_noinline(c, b, c); /* c = 11 */
  /* 22 */ curve25519_square_times(t0, c, 1);
  /* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
  /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
  /* 2^252 - 2^1 */ curve25519_square_times(b, b, 1);
  /* 2^252 - 2 */ curve25519_mul_noinline(b, b, z);
  /* 2^252 - 2 */ curve25519_square_times(two252m2, b, 1);
}

static void
curve25519_reduce(bignum25519 r, const bignum25519 x) {
  unsigned char out[32];
  curve25519_contract(out, x);
  curve25519_expand(r, out);
}

static int
curve25519_is_zero(const bignum25519 a) {
  unsigned char out[32];
  unsigned int c = 0;
  int i;

  curve25519_contract(out, a);

  for (i = 0; i < 32; i++)
    c |= (unsigned int)out[i];

  return (c - 1) >> (sizeof(unsigned int) * 8 - 1);
}

static int
curve25519_is_equal(const bignum25519 a, const bignum25519 b) {
  unsigned char x[32];
  unsigned char y[32];
  unsigned int c = 0;
  int i;

  curve25519_contract(x, a);
  curve25519_contract(y, b);

  for (i = 0; i < 32; i++)
    c |= (unsigned int)x[i] ^ (unsigned int)y[i];

  return (c - 1) >> (sizeof(unsigned int) * 8 - 1);
}

static void
curve25519_neg_conditional(bignum25519 out, const bignum25519 x, int negate) {
  bignum25519 z;
  curve25519_copy(out, x);
  curve25519_neg(z, x);
  curve25519_swap_conditional(out, z, negate);
}

static int
curve25519_is_odd(const bignum25519 a) {
  unsigned char out[32];
  curve25519_contract(out, a);
  return out[0] & 1;
}

static int
curve25519_sqrt(bignum25519 out, const bignum25519 x) {
  bignum25519 ALIGN(16) a, b, c;
  int r;

  curve25519_pow_two252m2(a, x);
  curve25519_mul(b, a, ge25519_sqrtneg1);

  curve25519_square(c, a);
  r = curve25519_is_equal(c, x);

  curve25519_swap_conditional(a, b, r ^ 1);

  curve25519_square(c, a);
  r = curve25519_is_equal(c, x);

  curve25519_copy(out, a);

  return r;
}

static int
curve25519_is_square(const bignum25519 x) {
  bignum25519 ALIGN(16) r;
  return curve25519_sqrt(r, x);
}

static int
curve25519_isqrt(bignum25519 out, const bignum25519 u, const bignum25519 v) {
  bignum25519 ALIGN(16) v3, x, c;
  int css, fss;

  /* V3 = V^2 * V */
  curve25519_square(c, v);
  curve25519_mul(v3, c, v);

  /* V7 = V3^2 * V */
  curve25519_square(c, v3);
  curve25519_mul(c, c, v);

  /* P = (U * V7)^((p - 5) / 8) */
  curve25519_mul(x, u, c);
  curve25519_pow_two252m3(x, x);

  /* X = U * V3 * P */
  curve25519_mul(x, x, v3);
  curve25519_mul(x, x, u);

  /* C = V * X^2 */
  curve25519_square(c, x);
  curve25519_mul(c, c, v);

  /* C = U */
  css = curve25519_is_equal(c, u);

  /* C = -U */
  curve25519_neg(c, c);
  fss = curve25519_is_equal(c, u);

  /* X = X * I if C = -U */
  curve25519_mul(c, x, ge25519_sqrtneg1);
  curve25519_swap_conditional(x, c, fss);
  curve25519_copy(out, x);

  return css | fss;
}

static void
curve25519_solve_y2(bignum25519 out, const bignum25519 x) {
  /* y^2 = x^3 + a * x^2 + x */
  static const bignum25519 a = {486662};
  bignum25519 ALIGN(16) x2, x3, y2;

  curve25519_square(x2, x);
  curve25519_mul(x3, x2, x);
  curve25519_add_reduce(y2, x3, x);
  curve25519_mul(x3, x2, a);
  curve25519_add(out, y2, x3);
}

static int
curve25519_solve_y(bignum25519 out, const bignum25519 x) {
  curve25519_solve_y2(out, x);
  return curve25519_sqrt(out, out);
}

static int
curve25519_valid_x(const bignum25519 x) {
  bignum25519 ALIGN(16) y2;
  curve25519_solve_y2(y2, x);
  return curve25519_is_square(y2);
}

static int
curve25519_unpack(bignum25519 x, bignum25519 y,
                  const unsigned char raw[32]) {
  curve25519_expand(x, raw);
  return curve25519_solve_y(y, x);
}

static void
curve25519_double(
  bignum25519 x0,
  bignum25519 z0,
  const bignum25519 x1,
  const bignum25519 z1
) {
  bignum25519 ALIGN(16) a, aa, b, bb, c;
  static const bignum25519 a24 = {121666};

  /* A = X1 + Z1 */
  curve25519_add_reduce(a, x1, z1);

  /* AA = A^2 */
  curve25519_square(aa, a);

  /* B = X1 - Z1 */
  curve25519_sub_reduce(b, x1, z1);

  /* BB = B^2 */
  curve25519_square(bb, b);

  /* C = AA - BB */
  curve25519_sub(c, aa, bb);

  /* X3 = AA * BB */
  curve25519_mul(x0, aa, bb);

  /* Z3 = C * (BB + a24 * C) */
  curve25519_mul(a, c, a24);
  curve25519_add(a, a, bb);
  curve25519_mul(z0, c, a);
}

static void
curve25519_ladder(
  bignum25519 x0,
  bignum25519 z0,
  const bignum25519 x,
  const unsigned char k[32]
) {
  bignum25519 ALIGN(16) x1, x2, z2, x3, z3, t1, t2;
  static const bignum25519 a24 = {121666};
  int swap = 0;
  int i, b;

  curve25519_reduce(x1, x);
  curve25519_set_word(x2, 1);
  curve25519_set_word(z2, 0);
  curve25519_copy(x3, x1);
  curve25519_set_word(z3, 1);

  for (i = 255 - 1; i >= 0; i--) {
    b = (k[i >> 3] >> (i & 7)) & 1;

    swap ^= b;

    curve25519_swap_conditional(x2, x3, swap);
    curve25519_swap_conditional(z2, z3, swap);

    swap = b;

    curve25519_sub(t1, x3, z3);
    curve25519_sub(t2, x2, z2);
    curve25519_add(x2, x2, z2);
    curve25519_add(z2, x3, z3);
    curve25519_mul(z3, t1, x2);
    curve25519_mul(z2, z2, t2);
    curve25519_square(t1, t2);
    curve25519_square(t2, x2);
    curve25519_add(x3, z3, z2);
    curve25519_sub(z2, z3, z2);
    curve25519_mul(x2, t2, t1);
    curve25519_sub(t2, t2, t1);
    curve25519_square(z2, z2);
    curve25519_mul(z3, t2, a24);
    curve25519_square(x3, x3);
    curve25519_add(t1, t1, z3);
    curve25519_mul(z3, x1, z2);
    curve25519_mul(z2, t2, t1);
  }

  curve25519_swap_conditional(x2, x3, swap);
  curve25519_swap_conditional(z2, z3, swap);

  curve25519_copy(x0, x2);
  curve25519_copy(z0, z2);
}

static void
curve25519_elligator2(bignum25519 x, bignum25519 y,
                      const unsigned char bytes[32]) {
  static const bignum25519 z = {2};
  static const bignum25519 a = {486662};
  bignum25519 ALIGN(16) u, x1, x2, y1, y2;
  bignum25519 one = {1};
  int alpha, flip;

  curve25519_expand(u, bytes);

  /* x1 = -a / (1 + z * u^2) */
  curve25519_square(x1, u);
  curve25519_mul(x1, x1, z);
  curve25519_add(x1, x1, one);
  curve25519_swap_conditional(x1, one, curve25519_is_zero(x1));
  curve25519_recip(x1, x1);
  curve25519_mul(x1, a, x1);
  curve25519_neg(x1, x1);

  /* x2 = -x1 - a */
  curve25519_neg(x2, x1);
  curve25519_sub(x2, x2, a);

  /* compute y coordinate */
  alpha = curve25519_solve_y(y1, x1);
  curve25519_solve_y(y2, x2);

  /* x = cmov(x1, x2, f(g(x1)) != 1) */
  curve25519_swap_conditional(x1, x2, alpha ^ 1);
  curve25519_swap_conditional(y1, y2, alpha ^ 1);

  /* adjust sign */
  flip = curve25519_is_odd(y1) ^ curve25519_is_odd(u);
  curve25519_neg_conditional(y1, y1, flip);

  curve25519_copy(x, x1);
  curve25519_copy(y, y1);
}

int
bcrypto_ed25519_randombytes(void *p, size_t len);

static int
curve25519_invert2(unsigned char out[32],
                   const bignum25519 x,
                   const bignum25519 y,
                   unsigned int hint) {
  static const bignum25519 z = {2};
  static const bignum25519 a = {486662};
  bignum25519 ALIGN(16) n, d, u;
  unsigned char bit = 0;
  int ret = 1;
  int flip;

  /* u = sqrt(-n / (d * z)) */
  curve25519_add_reduce(n, x, a);
  curve25519_copy(d, x);
  curve25519_swap_conditional(n, d, hint & 1);
  curve25519_neg(n, n);
  curve25519_mul(d, d, z);
  ret &= curve25519_isqrt(u, n, d);

  /* adjust sign */
  flip = curve25519_is_odd(u) ^ curve25519_is_odd(y);
  curve25519_neg_conditional(u, u, flip);

  /* output */
  curve25519_contract(out, u);

  /* randomize the top bit */
  ret &= bcrypto_ed25519_randombytes(&bit, sizeof(unsigned char));

  out[31] |= (bit & 1) << 7;

  return ret;
}
