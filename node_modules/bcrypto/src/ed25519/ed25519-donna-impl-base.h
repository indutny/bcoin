static void
ge25519_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1);

/*
  conversions
*/

DONNA_INLINE static void
ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p) {
  curve25519_mul(r->x, p->x, p->t);
  curve25519_mul(r->y, p->y, p->z);
  curve25519_mul(r->z, p->z, p->t);
}

DONNA_INLINE static void
ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p) {
  curve25519_mul(r->x, p->x, p->t);
  curve25519_mul(r->y, p->y, p->z);
  curve25519_mul(r->z, p->z, p->t);
  curve25519_mul(r->t, p->x, p->y);
}

static void
ge25519_full_to_pniels(ge25519_pniels *p, const ge25519 *r) {
  curve25519_sub(p->ysubx, r->y, r->x);
  curve25519_add(p->xaddy, r->y, r->x);
  curve25519_copy(p->z, r->z);
  curve25519_mul(p->t2d, r->t, ge25519_ec2d);
}

/*
  adding & doubling
*/

static void
ge25519_add_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519 *q) {
  bignum25519 a,b,c,d,t,u;

  curve25519_sub(a, p->y, p->x);
  curve25519_add(b, p->y, p->x);
  curve25519_sub(t, q->y, q->x);
  curve25519_add(u, q->y, q->x);
  curve25519_mul(a, a, t);
  curve25519_mul(b, b, u);
  curve25519_mul(c, p->t, q->t);
  curve25519_mul(c, c, ge25519_ec2d);
  curve25519_mul(d, p->z, q->z);
  curve25519_add(d, d, d);
  curve25519_sub(r->x, b, a);
  curve25519_add(r->y, b, a);
  curve25519_add_after_basic(r->z, d, c);
  curve25519_sub_after_basic(r->t, d, c);
}


static void
ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p) {
  bignum25519 a,b,c;

  curve25519_square(a, p->x);
  curve25519_square(b, p->y);
  curve25519_square(c, p->z);
  curve25519_add_reduce(c, c, c);
  curve25519_add(r->x, p->x, p->y);
  curve25519_square(r->x, r->x);
  curve25519_add(r->y, b, a);
  curve25519_sub(r->z, b, a);
  curve25519_sub_after_basic(r->x, r->x, r->y);
  curve25519_sub_after_basic(r->t, c, r->z);
}

static void
ge25519_nielsadd2_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_niels *q, unsigned char signbit) {
  const bignum25519 *qb = (const bignum25519 *)q;
  bignum25519 *rb = (bignum25519 *)r;
  bignum25519 a,b,c;

  curve25519_sub(a, p->y, p->x);
  curve25519_add(b, p->y, p->x);
  curve25519_mul(a, a, qb[signbit]); /* x for +, y for - */
  curve25519_mul(r->x, b, qb[signbit^1]); /* y for +, x for - */
  curve25519_add(r->y, r->x, a);
  curve25519_sub(r->x, r->x, a);
  curve25519_mul(c, p->t, q->t2d);
  curve25519_add_reduce(r->t, p->z, p->z);
  curve25519_copy(r->z, r->t);
  curve25519_add(rb[2+signbit], rb[2+signbit], c); /* z for +, t for - */
  curve25519_sub(rb[2+(signbit^1)], rb[2+(signbit^1)], c); /* t for +, z for - */
}

static void
ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_pniels *q, unsigned char signbit) {
  const bignum25519 *qb = (const bignum25519 *)q;
  bignum25519 *rb = (bignum25519 *)r;
  bignum25519 a,b,c;

  curve25519_sub(a, p->y, p->x);
  curve25519_add(b, p->y, p->x);
  curve25519_mul(a, a, qb[signbit]); /* ysubx for +, xaddy for - */
  curve25519_mul(r->x, b, qb[signbit^1]); /* xaddy for +, ysubx for - */
  curve25519_add(r->y, r->x, a);
  curve25519_sub(r->x, r->x, a);
  curve25519_mul(c, p->t, q->t2d);
  curve25519_mul(r->t, p->z, q->z);
  curve25519_add_reduce(r->t, r->t, r->t);
  curve25519_copy(r->z, r->t);
  curve25519_add(rb[2+signbit], rb[2+signbit], c); /* z for +, t for - */
  curve25519_sub(rb[2+(signbit^1)], rb[2+(signbit^1)], c); /* t for +, z for - */
}

static void
ge25519_double_partial(ge25519 *r, const ge25519 *p) {
  ge25519_p1p1 t;
  ge25519_double_p1p1(&t, p);
  ge25519_p1p1_to_partial(r, &t);
}

static void
ge25519_double(ge25519 *r, const ge25519 *p) {
  ge25519_p1p1 t;
  ge25519_double_p1p1(&t, p);
  ge25519_p1p1_to_full(r, &t);
}

static void
ge25519_add(ge25519 *r, const ge25519 *p,  const ge25519 *q) {
  ge25519_p1p1 t;
  ge25519_add_p1p1(&t, p, q);
  ge25519_p1p1_to_full(r, &t);
}

static void
ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q) {
  bignum25519 a,b,c,e,f,g,h;

  curve25519_sub(a, r->y, r->x);
  curve25519_add(b, r->y, r->x);
  curve25519_mul(a, a, q->ysubx);
  curve25519_mul(e, b, q->xaddy);
  curve25519_add(h, e, a);
  curve25519_sub(e, e, a);
  curve25519_mul(c, r->t, q->t2d);
  curve25519_add(f, r->z, r->z);
  curve25519_add_after_basic(g, f, c);
  curve25519_sub_after_basic(f, f, c);
  curve25519_mul(r->x, e, f);
  curve25519_mul(r->y, h, g);
  curve25519_mul(r->z, g, f);
  curve25519_mul(r->t, e, h);
}

static void
ge25519_pnielsadd(ge25519_pniels *r, const ge25519 *p, const ge25519_pniels *q) {
  bignum25519 a,b,c,x,y,z,t;

  curve25519_sub(a, p->y, p->x);
  curve25519_add(b, p->y, p->x);
  curve25519_mul(a, a, q->ysubx);
  curve25519_mul(x, b, q->xaddy);
  curve25519_add(y, x, a);
  curve25519_sub(x, x, a);
  curve25519_mul(c, p->t, q->t2d);
  curve25519_mul(t, p->z, q->z);
  curve25519_add(t, t, t);
  curve25519_add_after_basic(z, t, c);
  curve25519_sub_after_basic(t, t, c);
  curve25519_mul(r->xaddy, x, t);
  curve25519_mul(r->ysubx, y, z);
  curve25519_mul(r->z, z, t);
  curve25519_mul(r->t2d, x, y);
  curve25519_copy(y, r->ysubx);
  curve25519_sub(r->ysubx, r->ysubx, r->xaddy);
  curve25519_add(r->xaddy, r->xaddy, y);
  curve25519_mul(r->t2d, r->t2d, ge25519_ec2d);
}

/*
  negation
*/

static void
ge25519_neg(ge25519 *r, const ge25519 *p) {
  curve25519_neg(r->x, p->x);
  curve25519_copy(r->y, p->y);
  curve25519_copy(r->z, p->z);
  curve25519_neg(r->t, p->t);
}

/*
  infinity
*/

static int
ge25519_is_neutral(const ge25519 *p) {
  static const unsigned char zero[32] = {0};
  unsigned char point_buffer[3][32];

  curve25519_contract(point_buffer[0], p->x);
  curve25519_contract(point_buffer[1], p->y);
  curve25519_contract(point_buffer[2], p->z);

  return bcrypto_ed25519_equal(point_buffer[0], zero, 32)
       & bcrypto_ed25519_equal(point_buffer[1], point_buffer[2], 32);
}

static int
ge25519_is_neutral_vartime(const ge25519 *p) {
  static const unsigned char zero[32] = {0};
  unsigned char point_buffer[3][32];

  curve25519_contract(point_buffer[0], p->x);
  curve25519_contract(point_buffer[1], p->y);
  curve25519_contract(point_buffer[2], p->z);

  return (memcmp(point_buffer[0], zero, 32) == 0)
      && (memcmp(point_buffer[1], point_buffer[2], 32) == 0);
}

/*
  torsion
*/

static void
ge25519_mulh(ge25519 *r, const ge25519 *p) {
  ge25519_double(r, p);
  ge25519_double(r, r);
  ge25519_double(r, r);
}

static void
ge25519_divh(ge25519 *r, const ge25519 *p) {
  ge25519_scalarmult_vartime(r, p, modm_hinv);
}

static void
ge25519_untorsion(ge25519 *r, const ge25519 *p) {
  ge25519_mulh(r, p);
  ge25519_divh(r, r);
}

static int
ge25519_is_small(const ge25519 *p) {
  ge25519 ALIGN(16) r;
  ge25519_mulh(&r, p);
  return (ge25519_is_neutral(p) ^ 1)
        & ge25519_is_neutral(&r);
}

static int
ge25519_has_torsion(const ge25519 *p) {
  ge25519 ALIGN(16) r;
  ge25519_scalarmult_vartime(&r, p, modm_m);
  return ge25519_is_neutral(&r) ^ 1;
}

/*
  pack & unpack
*/

static inline int
ge25519_is_zero(const unsigned char p[32]) {
  static const unsigned char zero[32] = {0};
  return bcrypto_ed25519_equal(p, zero, 32);
}

static inline int
ge25519_is_one(const unsigned char p[32]) {
  static const unsigned char one[32] = {1};
  return bcrypto_ed25519_equal(p, one, 32);
}

static int
ge25519_is_canonical(const unsigned char p[32]) {
  /* https://github.com/jedisct1/libsodium/blob/3d37974/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c */
  unsigned char c;
  unsigned char d;
  unsigned int i;

  c = (p[31] & 0x7f) ^ 0x7f;

  for (i = 30; i > 0; i--)
    c |= p[i] ^ 0xff;

  c = (((unsigned int)c) - 1U) >> 8;
  d = (0xed - 1U - (unsigned int)p[0]) >> 8;

  return 1 - (c & d & 1);
}

static void
ge25519_pack(unsigned char r[32], const ge25519 *p) {
  bignum25519 tx, ty, zi;
  unsigned char parity[32];

  curve25519_recip(zi, p->z);
  curve25519_mul(tx, p->x, zi);
  curve25519_mul(ty, p->y, zi);
  curve25519_contract(r, ty);
  curve25519_contract(parity, tx);

  r[31] ^= ((parity[0] & 1) << 7);
}

static int
ge25519_unpack(ge25519 *r, const unsigned char p[32]) {
  unsigned char sign = p[31] >> 7;
  unsigned char check[32];
  int ret = 1;
  bignum25519 lhs, rhs;

  /* y >= p */
  ret &= ge25519_is_canonical(p);

  curve25519_expand(r->y, p);
  curve25519_set_word(r->z, 1);
  curve25519_square(lhs, r->y); /* x = y^2 */
  curve25519_mul(rhs, lhs, ge25519_ecd); /* rhs = dy^2 */
  curve25519_sub_reduce(lhs, lhs, r->z); /* x = y^1 - 1 */
  curve25519_add(rhs, rhs, r->z); /* rhs = dy^2 + 1 */

  /* Computation of sqrt(lhs/rhs) */
  ret &= curve25519_isqrt(r->x, lhs, rhs);

  curve25519_contract(check, r->x);

  /* x = 0, sign = 1 (malleable) */
  ret &= (ge25519_is_zero(check) & sign) ^ 1;

  curve25519_neg_conditional(r->x, r->x, (check[0] & 1) ^ sign);
  curve25519_mul(r->t, r->x, r->y);

  return ret;
}

static int
ge25519_unpack_vartime(ge25519 *r, const unsigned char p[32]) {
  unsigned char sign = p[31] >> 7;
  unsigned char check[32];
  bignum25519 t, root, num, den, d3;

  /* y >= p */
  if (!ge25519_is_canonical(p))
    return 0;

  curve25519_expand(r->y, p);
  curve25519_set_word(r->z, 1);
  curve25519_square(num, r->y); /* x = y^2 */
  curve25519_mul(den, num, ge25519_ecd); /* den = dy^2 */
  curve25519_sub_reduce(num, num, r->z); /* x = y^1 - 1 */
  curve25519_add(den, den, r->z); /* den = dy^2 + 1 */

  /* Computation of sqrt(num/den) */
  /* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
  curve25519_square(t, den);
  curve25519_mul(d3, t, den);
  curve25519_square(r->x, d3);
  curve25519_mul(r->x, r->x, den);
  curve25519_mul(r->x, r->x, num);
  curve25519_pow_two252m3(r->x, r->x);

  /* 2. computation of r->x = num * den^3 * (num*den^7)^((p-5)/8) */
  curve25519_mul(r->x, r->x, d3);
  curve25519_mul(r->x, r->x, num);

  /* 3. Check if either of the roots works: */
  curve25519_square(t, r->x);
  curve25519_mul(t, t, den);
  curve25519_sub_reduce(root, t, num);
  curve25519_contract(check, root);

  if (!ge25519_is_zero(check)) {
    curve25519_add_reduce(t, t, num);
    curve25519_contract(check, t);

    if (!ge25519_is_zero(check))
      return 0;

    curve25519_mul(r->x, r->x, ge25519_sqrtneg1);
  }

  curve25519_contract(check, r->x);

  /* x = 0, sign = 1 (malleable) */
  if (sign && ge25519_is_zero(check))
    return 0;

  if ((check[0] & 1) != sign)
    curve25519_neg(r->x, r->x);

  curve25519_mul(r->t, r->x, r->y);

  return 1;
}

/*
  helpers
*/

static inline void
ge25519_swap_conditional(ge25519 *a, ge25519 *b, int swap) {
  curve25519_swap_conditional(a->x, b->x, swap);
  curve25519_swap_conditional(a->y, b->y, swap);
  curve25519_swap_conditional(a->z, b->z, swap);
  curve25519_swap_conditional(a->t, b->t, swap);
}

static inline void
ge25519_copy(ge25519 *a, const ge25519 *b) {
  curve25519_copy(a->x, b->x);
  curve25519_copy(a->y, b->y);
  curve25519_copy(a->z, b->z);
  curve25519_copy(a->t, b->t);
}

static inline void
ge25519_set_neutral(ge25519 *a) {
  curve25519_set_word(a->x, 0);
  curve25519_set_word(a->y, 1);
  curve25519_set_word(a->z, 1);
  curve25519_set_word(a->t, 0);
}

/*
  conversion
*/

static int
ge25519_to_mont(bignum25519 u, bignum25519 v, const ge25519 *p) {
  bignum25519 ALIGN(16) uu, uz, vv, vz, zz;

  /* infinity does not exist in the mont affine space */
  int ret = ge25519_is_neutral(p) ^ 1;

  /* u = (1 + y) / (1 - y) */
  curve25519_add_reduce(uu, p->z, p->y);
  curve25519_sub_reduce(uz, p->z, p->y);

  /* v = sqrt(-486664) * u / x */
  curve25519_mul(vv, curve25519_sqrt_m486664, p->z);
  curve25519_mul(vv, vv, uu);
  curve25519_mul(vz, p->x, uz);

  /* scale */
  curve25519_mul(uu, uu, vz);
  curve25519_mul(vv, vv, uz);
  curve25519_mul(zz, uz, vz);

  /* affinize */
  /* note that (0, -1) will be mapped to (0, 0) */
  curve25519_recip(zz, zz);
  curve25519_mul(u, uu, zz);
  curve25519_mul(v, vv, zz);

  return ret;
}

static void
ge25519_from_mont(ge25519 *p, const bignum25519 u, const bignum25519 v) {
  bignum25519 ALIGN(16) xx, xz, yy, yz;
  bignum25519 one = {1};

  /* x = sqrt(-486664) * u / v */
  curve25519_mul(xx, curve25519_sqrt_m486664, u);
  curve25519_copy(xz, v);

  /* y = (u - 1) / (u + 1) */
  curve25519_sub_reduce(yy, u, one);
  curve25519_add_reduce(yz, u, one);

  /* ensure that (0, 0) will be mapped to (0, -1) */
  curve25519_swap_conditional(xz, one, curve25519_is_zero(u));

  /* scale */
  curve25519_mul(p->x, xx, yz);
  curve25519_mul(p->y, yy, xz);
  curve25519_mul(p->z, xz, yz);
  curve25519_mul(p->t, xx, yy);
}

/*
  elligator
*/

static void
ge25519_elligator2(ge25519 *p, const unsigned char bytes[32]) {
  bignum25519 ALIGN(16) u, v;
  curve25519_elligator2(u, v, bytes);
  ge25519_from_mont(p, u, v);
}

static int
ge25519_invert2(unsigned char bytes[32], const ge25519 *p, unsigned int hint) {
  bignum25519 ALIGN(16) u, v;
  int ret = 1;

  ret &= ge25519_to_mont(u, v, p);
  ret &= curve25519_invert2(bytes, u, v, hint);

  return ret;
}

static void
ge25519_from_hash(ge25519 *p, const unsigned char bytes[64], int pake) {
  ge25519 ALIGN(16) p1, p2;

  ge25519_elligator2(&p1, bytes);
  ge25519_elligator2(&p2, bytes + 32);
  ge25519_add(p, &p1, &p2);

  if (pake)
    ge25519_mulh(p, p);
}

static int
ge25519_to_hash(unsigned char bytes[64], const ge25519 *p) {
  ge25519 ALIGN(16) p1, p2;
  unsigned char *u1 = &bytes[0];
  unsigned char *u2 = &bytes[32];
  unsigned int hint;

  for (;;) {
    if (!bcrypto_ed25519_randombytes(u1, 32))
      return 0;

    ge25519_elligator2(&p1, u1);

    /* Avoid the 2-torsion point (0, -1). */
    if (curve25519_is_zero(p1.x))
      continue;

    ge25519_neg(&p1, &p1);
    ge25519_add(&p2, p, &p1);

    if (!bcrypto_ed25519_randombytes(&hint, sizeof(unsigned int)))
      return 0;

    if (ge25519_invert2(u2, &p2, hint))
      break;
  }

  return 1;
}

/*
  scalarmults
*/

#define S1_SWINDOWSIZE 5
#define S1_TABLE_SIZE (1<<(S1_SWINDOWSIZE-2))
#define S2_SWINDOWSIZE 7
#define S2_TABLE_SIZE (1<<(S2_SWINDOWSIZE-2))

/* computes [s1]p1 + [s2]basepoint */
static void
ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2) {
  signed char slide1[256], slide2[256];
  ge25519_pniels pre1[S1_TABLE_SIZE];
  ge25519 d1;
  ge25519_p1p1 t;
  int32_t i;

  contract256_slidingwindow_modm(slide1, s1, S1_SWINDOWSIZE);
  contract256_slidingwindow_modm(slide2, s2, S2_SWINDOWSIZE);

  ge25519_double(&d1, p1);
  ge25519_full_to_pniels(pre1, p1);
  for (i = 0; i < S1_TABLE_SIZE - 1; i++)
    ge25519_pnielsadd(&pre1[i+1], &d1, &pre1[i]);

  /* set neutral */
  ge25519_set_neutral(r);

  i = 255;
  while ((i >= 0) && !(slide1[i] | slide2[i]))
    i--;

  for (; i >= 0; i--) {
    ge25519_double_p1p1(&t, r);

    if (slide1[i]) {
      ge25519_p1p1_to_full(r, &t);
      ge25519_pnielsadd_p1p1(&t, r, &pre1[abs(slide1[i]) / 2], (unsigned char)slide1[i] >> 7);
    }

    if (slide2[i]) {
      ge25519_p1p1_to_full(r, &t);
      ge25519_nielsadd2_p1p1(&t, r, &ge25519_niels_sliding_multiples[abs(slide2[i]) / 2], (unsigned char)slide2[i] >> 7);
    }

    ge25519_p1p1_to_partial(r, &t);
  }

  ge25519_p1p1_to_full(r, &t);
}

// https://github.com/forthy42/ed25519-donna/blob/master/ed25519-donna-impl-base.h
static void
ge25519_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1) {
  signed char slide1[256];
  ge25519_pniels pre1[S1_TABLE_SIZE];
  ge25519 d1;
  ge25519_p1p1 t;
  int32_t i;

  contract256_slidingwindow_modm(slide1, s1, S1_SWINDOWSIZE);

  ge25519_double(&d1, p1);
  ge25519_full_to_pniels(pre1, p1);
  for (i = 0; i < S1_TABLE_SIZE - 1; i++)
    ge25519_pnielsadd(&pre1[i+1], &d1, &pre1[i]);

  /* set neutral */
  ge25519_set_neutral(r);

  i = 255;
  while ((i >= 0) && !slide1[i])
    i--;

  for (; i >= 0; i--) {
    ge25519_double_p1p1(&t, r);

    if (slide1[i]) {
      ge25519_p1p1_to_full(r, &t);
      ge25519_pnielsadd_p1p1(&t, r, &pre1[abs(slide1[i]) / 2], (unsigned char)slide1[i] >> 7);
    }

    ge25519_p1p1_to_partial(r, &t);
  }

  ge25519_p1p1_to_full(r, &t);
}

static void
ge25519_scalarmult(ge25519 *r, const ge25519 *p, const bignum256modm s) {
  unsigned char exp[32];
  ge25519 a, b;
  int swap = 0;
  int i;

  ge25519_copy(&a, p);
  ge25519_set_neutral(&b);

  contract256_modm(exp, s);

  for (i = 256 - 1; i >= 0; i--) {
    int bit = (exp[i >> 3] >> (i & 7)) & 1;

    ge25519_swap_conditional(&a, &b, swap ^ bit);

    ge25519_add(&a, &a, &b);
    ge25519_double(&b, &b);

    swap = bit;
  }

  ge25519_swap_conditional(&a, &b, swap);
  ge25519_copy(r, &b);
}

#if !defined(HAVE_GE25519_SCALARMULT_BASE_CHOOSE_NIELS)

static uint32_t
ge25519_windowb_equal(uint32_t b, uint32_t c) {
  return ((b ^ c) - 1) >> 31;
}

static void
ge25519_scalarmult_base_choose_niels(ge25519_niels *t, const uint8_t table[256][96], uint32_t pos, signed char b) {
  bignum25519 neg;
  uint32_t sign = (uint32_t)((unsigned char)b >> 7);
  uint32_t mask = ~(sign - 1);
  uint32_t u = (b + mask) ^ mask;
  uint32_t i;

  /* ysubx, xaddy, t2d in packed form. initialize to ysubx = 1, xaddy = 1, t2d = 0 */
  uint8_t packed[96] = {0};
  packed[0] = 1;
  packed[32] = 1;

  for (i = 0; i < 8; i++)
    curve25519_move_conditional_bytes(packed, table[(pos * 8) + i], ge25519_windowb_equal(u, i + 1));

  /* expand in to t */
  curve25519_expand(t->ysubx, packed +  0);
  curve25519_expand(t->xaddy, packed + 32);
  curve25519_expand(t->t2d  , packed + 64);

  /* adjust for sign */
  curve25519_swap_conditional(t->ysubx, t->xaddy, sign);
  curve25519_neg(neg, t->t2d);
  curve25519_swap_conditional(t->t2d, neg, sign);
}

#endif /* HAVE_GE25519_SCALARMULT_BASE_CHOOSE_NIELS */


/* computes [s]basepoint */
static void
ge25519_scalarmult_base_niels(ge25519 *r, const uint8_t basepoint_table[256][96], const bignum256modm s) {
  signed char b[64];
  uint32_t i;
  ge25519_niels t;

  contract256_window4_modm(b, s);

  ge25519_scalarmult_base_choose_niels(&t, basepoint_table, 0, b[1]);
  curve25519_sub_reduce(r->x, t.xaddy, t.ysubx);
  curve25519_add_reduce(r->y, t.xaddy, t.ysubx);
  memset(r->z, 0, sizeof(bignum25519));
  curve25519_copy(r->t, t.t2d);
  r->z[0] = 2;
  for (i = 3; i < 64; i += 2) {
    ge25519_scalarmult_base_choose_niels(&t, basepoint_table, i / 2, b[i]);
    ge25519_nielsadd2(r, &t);
  }
  ge25519_double_partial(r, r);
  ge25519_double_partial(r, r);
  ge25519_double_partial(r, r);
  ge25519_double(r, r);
  ge25519_scalarmult_base_choose_niels(&t, basepoint_table, 0, b[0]);
  curve25519_mul(t.t2d, t.t2d, ge25519_ecd);
  ge25519_nielsadd2(r, &t);
  for(i = 2; i < 64; i += 2) {
    ge25519_scalarmult_base_choose_niels(&t, basepoint_table, i / 2, b[i]);
    ge25519_nielsadd2(r, &t);
  }
}
