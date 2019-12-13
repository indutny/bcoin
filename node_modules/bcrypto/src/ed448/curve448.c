/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */
#include "openssl/crypto.h"
#include "../random/random.h"
#include "word.h"
#include "field.h"

#include "point_448.h"
#include "ed448.h"
#include "curve448_lcl.h"

#define BCRYPTO_COFACTOR 4

#define BCRYPTO_C448_WINDOW_BITS 5
#define BCRYPTO_C448_WNAF_FIXED_TABLE_BITS 5
#define BCRYPTO_C448_WNAF_VAR_TABLE_BITS 3

#define BCRYPTO_EDWARDS_D     (-39081)

static const bcrypto_curve448_scalar_t point_scalarmul_adjustment = {
  {
    {
      BCRYPTO_SC_BCRYPTO_LIMB(0xc873d6d54a7bb0cf), BCRYPTO_SC_BCRYPTO_LIMB(0xe933d8d723a70aad),
      BCRYPTO_SC_BCRYPTO_LIMB(0xbb124b65129c96fd), BCRYPTO_SC_BCRYPTO_LIMB(0x00000008335dc163)
    }
  }
};

static const bcrypto_curve448_scalar_t precomputed_scalarmul_adjustment = {
  {
    {
      BCRYPTO_SC_BCRYPTO_LIMB(0xc873d6d54a7bb0cf), BCRYPTO_SC_BCRYPTO_LIMB(0xe933d8d723a70aad),
      BCRYPTO_SC_BCRYPTO_LIMB(0xbb124b65129c96fd), BCRYPTO_SC_BCRYPTO_LIMB(0x00000008335dc163)
    }
  }
};

#define BCRYPTO_TWISTED_D (BCRYPTO_EDWARDS_D - 1)

#if BCRYPTO_TWISTED_D < 0
#define BCRYPTO_EFF_D (-(BCRYPTO_TWISTED_D))
#define BCRYPTO_NEG_D 1
#else
#define BCRYPTO_EFF_D BCRYPTO_TWISTED_D
#define BCRYPTO_NEG_D 0
#endif

#define BCRYPTO_WBITS BCRYPTO_C448_WORD_BITS   /* NB this may be different from BCRYPTO_ARCH_WORD_BITS */

void
curve448_proj_twist(curve448_proj_point *p,
                    const bcrypto_gf u,
                    const bcrypto_gf v)
{
  bcrypto_gf xx, xz, yy, yz;

  /* (x, y) = (u / v, (u + 1) / (u - 1)) */
  bcrypto_gf_copy(xx, u);
  bcrypto_gf_copy(xz, v);
  bcrypto_gf_add(yy, u, ONE);
  bcrypto_gf_sub(yz, u, ONE);

  /* (0, 0) -> (0, -1) */
  bcrypto_gf_cond_sel(xz, xz, ONE, bcrypto_gf_eq(v, ZERO));

  bcrypto_gf_mul(p->x, xx, yz);
  bcrypto_gf_mul(p->y, yy, xz);
  bcrypto_gf_mul(p->z, xz, yz);
}

static bcrypto_mask_t
curve448_proj_untwist(bcrypto_gf u, bcrypto_gf v,
                      const curve448_proj_point *p)
{
  bcrypto_mask_t torsion = bcrypto_gf_eq(p->x, ZERO);
  bcrypto_mask_t inf = torsion & bcrypto_gf_eq(p->y, p->z);
  bcrypto_gf uu, uz, vv, vz, zi, t;

  /* (u, v) = ((y + 1) / (y - 1), u / x) */
  bcrypto_gf_add(uu, p->y, p->z);
  bcrypto_gf_sub(uz, p->y, p->z);
  bcrypto_gf_mul(vv, p->z, uu);
  bcrypto_gf_mul(vz, p->x, uz);

  /* (0, -1) -> (0, 0) */
  bcrypto_gf_cond_sel(vz, vz, ONE, torsion);

  bcrypto_gf_mul(t, uz, vz);
  bcrypto_gf_invert(zi, t, 0);

  bcrypto_gf_mul(t, uu, vz);
  bcrypto_gf_mul(u, t, zi);

  bcrypto_gf_mul(t, vv, uz);
  bcrypto_gf_mul(v, t, zi);

  /* (0, 1) -> O */
  bcrypto_gf_cond_sel(u, u, ZERO, inf);
  bcrypto_gf_cond_sel(v, v, ZERO, inf);

  return ~inf;
}

static void
curve448_proj_destroy(curve448_proj_point *p)
{
  OPENSSL_cleanse(p->x, sizeof(bcrypto_gf));
  OPENSSL_cleanse(p->y, sizeof(bcrypto_gf));
  OPENSSL_cleanse(p->z, sizeof(bcrypto_gf));
}

static void
curve448_proj_neg(curve448_proj_point *p2,
                  const curve448_proj_point *p1)
{
  bcrypto_gf_sub(p2->x, ZERO, p1->x);
  bcrypto_gf_copy(p2->y, p1->y);
  bcrypto_gf_copy(p2->z, p1->z);
}

static void
curve448_proj_add(curve448_proj_point *p3,
                  const curve448_proj_point *p1,
                  const curve448_proj_point *p2)
{
  static const bcrypto_gf A = {{{156324}}}; /* (-A + 2) / -B */
  static const bcrypto_gf D = {{{156328}}}; /* (-A - 2) / -B */
  bcrypto_gf a, b, c, d, e, f, g, xyxy, t1, t2;

  /* A = Z1 * Z2 */
  bcrypto_gf_mul(a, p1->z, p2->z);

  /* B = A^2 */
  bcrypto_gf_sqr(b, a);

  /* C = X1 * X2 */
  bcrypto_gf_mul(c, p1->x, p2->x);

  /* D = Y1 * Y2 */
  bcrypto_gf_mul(d, p1->y, p2->y);

  /* E = d * C * D */
  bcrypto_gf_mul(t1, D, c);
  bcrypto_gf_mul(e, t1, d);

  /* F = B - E */
  bcrypto_gf_sub(f, b, e);

  /* G = B + E */
  bcrypto_gf_add(g, b, e);

  /* XYXY = (X1 + Y1) * (X2 + Y2) */
  bcrypto_gf_add(t1, p1->x, p1->y);
  bcrypto_gf_add(t2, p2->x, p2->y);
  bcrypto_gf_mul(xyxy, t1, t2);

  /* X3 = A * F * (XYXY - C - D) */
  bcrypto_gf_sub(xyxy, xyxy, c);
  bcrypto_gf_sub(xyxy, xyxy, d);
  bcrypto_gf_mul(t1, xyxy, f);
  bcrypto_gf_mul(p3->x, t1, a);

  /* Y3 = A * G * (D - a * C) */
  bcrypto_gf_mul(t1, A, c);
  bcrypto_gf_sub(t1, d, t1);
  bcrypto_gf_mul(t2, g, t1);
  bcrypto_gf_mul(p3->y, t2, a);

  /* Z3 = F * G */
  bcrypto_gf_mul(p3->z, f, g);
}

static void
curve448_proj_dbl(curve448_proj_point *p2, const curve448_proj_point *p1)
{
  curve448_proj_add(p2, p1, p1);
}

/** identity = (0,1) */
const bcrypto_curve448_point_t bcrypto_curve448_point_identity =
  { {{{{0}}}, {{{1}}}, {{{1}}}, {{{0}}}} };

void bcrypto_curve448_point_sub(
  bcrypto_curve448_point_t p,
  const bcrypto_curve448_point_t q,
  const bcrypto_curve448_point_t r
) {
  bcrypto_gf a, b, c, d;
  bcrypto_gf_sub_nr(b, q->y, q->x); /* 3+e */
  bcrypto_gf_sub_nr(d, r->y, r->x); /* 3+e */
  bcrypto_gf_add_nr(c, r->y, r->x); /* 2+e */
  bcrypto_gf_mul(a, c, b);
  bcrypto_gf_add_nr(b, q->y, q->x); /* 2+e */
  bcrypto_gf_mul(p->y, d, b);
  bcrypto_gf_mul(b, r->t, q->t);
  bcrypto_gf_mulw(p->x, b, 2 * BCRYPTO_EFF_D);
  bcrypto_gf_add_nr(b, a, p->y);    /* 2+e */
  bcrypto_gf_sub_nr(c, p->y, a);    /* 3+e */
  bcrypto_gf_mul(a, q->z, r->z);
  bcrypto_gf_add_nr(a, a, a);       /* 2+e */

  if (BCRYPTO_GF_HEADROOM <= 3)
    bcrypto_gf_weak_reduce(a); /* or 1+e */

#if BCRYPTO_NEG_D
  bcrypto_gf_sub_nr(p->y, a, p->x); /* 4+e or 3+e */
  bcrypto_gf_add_nr(a, a, p->x);    /* 3+e or 2+e */
#else
  bcrypto_gf_add_nr(p->y, a, p->x); /* 3+e or 2+e */
  bcrypto_gf_sub_nr(a, a, p->x);    /* 4+e or 3+e */
#endif

  bcrypto_gf_mul(p->z, a, p->y);
  bcrypto_gf_mul(p->x, p->y, c);
  bcrypto_gf_mul(p->y, a, b);
  bcrypto_gf_mul(p->t, b, c);
}

void bcrypto_curve448_point_add(
  bcrypto_curve448_point_t p,
  const bcrypto_curve448_point_t q,
  const bcrypto_curve448_point_t r
) {
  bcrypto_gf a, b, c, d;
  bcrypto_gf_sub_nr(b, q->y, q->x); /* 3+e */
  bcrypto_gf_sub_nr(c, r->y, r->x); /* 3+e */
  bcrypto_gf_add_nr(d, r->y, r->x); /* 2+e */
  bcrypto_gf_mul(a, c, b);
  bcrypto_gf_add_nr(b, q->y, q->x); /* 2+e */
  bcrypto_gf_mul(p->y, d, b);
  bcrypto_gf_mul(b, r->t, q->t);
  bcrypto_gf_mulw(p->x, b, 2 * BCRYPTO_EFF_D);
  bcrypto_gf_add_nr(b, a, p->y);    /* 2+e */
  bcrypto_gf_sub_nr(c, p->y, a);    /* 3+e */
  bcrypto_gf_mul(a, q->z, r->z);
  bcrypto_gf_add_nr(a, a, a);       /* 2+e */

  if (BCRYPTO_GF_HEADROOM <= 3)
    bcrypto_gf_weak_reduce(a); /* or 1+e */

#if BCRYPTO_NEG_D
  bcrypto_gf_add_nr(p->y, a, p->x); /* 3+e or 2+e */
  bcrypto_gf_sub_nr(a, a, p->x);    /* 4+e or 3+e */
#else
  bcrypto_gf_sub_nr(p->y, a, p->x); /* 4+e or 3+e */
  bcrypto_gf_add_nr(a, a, p->x);    /* 3+e or 2+e */
#endif

  bcrypto_gf_mul(p->z, a, p->y);
  bcrypto_gf_mul(p->x, p->y, c);
  bcrypto_gf_mul(p->y, a, b);
  bcrypto_gf_mul(p->t, b, c);
}

void bcrypto_curve448_point_negate(
  bcrypto_curve448_point_t nega,
  const bcrypto_curve448_point_t a
) {
  bcrypto_gf_sub(nega->x, ZERO, a->x);
  bcrypto_gf_copy(nega->y, a->y);
  bcrypto_gf_copy(nega->z, a->z);
  bcrypto_gf_sub(nega->t, ZERO, a->t);
}

static void point_double_internal(bcrypto_curve448_point_t p, const bcrypto_curve448_point_t q,
                  int before_double)
{
  bcrypto_gf a, b, c, d;

  bcrypto_gf_sqr(c, q->x);
  bcrypto_gf_sqr(a, q->y);
  bcrypto_gf_add_nr(d, c, a);     /* 2+e */
  bcrypto_gf_add_nr(p->t, q->y, q->x); /* 2+e */
  bcrypto_gf_sqr(b, p->t);
  bcrypto_gf_subx_nr(b, b, d, 3);   /* 4+e */
  bcrypto_gf_sub_nr(p->t, a, c);    /* 3+e */
  bcrypto_gf_sqr(p->x, q->z);
  bcrypto_gf_add_nr(p->z, p->x, p->x); /* 2+e */
  bcrypto_gf_subx_nr(a, p->z, p->t, 4); /* 6+e */
  if (BCRYPTO_GF_HEADROOM == 5)
    bcrypto_gf_weak_reduce(a);    /* or 1+e */
  bcrypto_gf_mul(p->x, a, b);
  bcrypto_gf_mul(p->z, p->t, a);
  bcrypto_gf_mul(p->y, p->t, d);
  if (!before_double)
    bcrypto_gf_mul(p->t, b, d);
}

void bcrypto_curve448_point_double(bcrypto_curve448_point_t p, const bcrypto_curve448_point_t q)
{
  point_double_internal(p, q, 0);
}

/* Operations on [p]niels */
static inline void cond_neg_niels(bcrypto_niels_t n, bcrypto_mask_t neg)
{
  bcrypto_gf_cond_swap(n->a, n->b, neg);
  bcrypto_gf_cond_neg(n->c, neg);
}

static void pt_to_pniels(bcrypto_pniels_t b, const bcrypto_curve448_point_t a)
{
  bcrypto_gf_sub(b->n->a, a->y, a->x);
  bcrypto_gf_add(b->n->b, a->x, a->y);
  bcrypto_gf_mulw(b->n->c, a->t, 2 * BCRYPTO_TWISTED_D);
  bcrypto_gf_add(b->z, a->z, a->z);
}

static void pniels_to_pt(bcrypto_curve448_point_t e, const bcrypto_pniels_t d)
{
  bcrypto_gf eu;

  bcrypto_gf_add(eu, d->n->b, d->n->a);
  bcrypto_gf_sub(e->y, d->n->b, d->n->a);
  bcrypto_gf_mul(e->t, e->y, eu);
  bcrypto_gf_mul(e->x, d->z, e->y);
  bcrypto_gf_mul(e->y, d->z, eu);
  bcrypto_gf_sqr(e->z, d->z);
}

static void niels_to_pt(bcrypto_curve448_point_t e, const bcrypto_niels_t n)
{
  bcrypto_gf_add(e->y, n->b, n->a);
  bcrypto_gf_sub(e->x, n->b, n->a);
  bcrypto_gf_mul(e->t, e->y, e->x);
  bcrypto_gf_copy(e->z, ONE);
}

static void add_niels_to_pt(bcrypto_curve448_point_t d, const bcrypto_niels_t e,
              int before_double)
{
  bcrypto_gf a, b, c;

  bcrypto_gf_sub_nr(b, d->y, d->x);   /* 3+e */
  bcrypto_gf_mul(a, e->a, b);
  bcrypto_gf_add_nr(b, d->x, d->y);   /* 2+e */
  bcrypto_gf_mul(d->y, e->b, b);
  bcrypto_gf_mul(d->x, e->c, d->t);
  bcrypto_gf_add_nr(c, a, d->y);    /* 2+e */
  bcrypto_gf_sub_nr(b, d->y, a);    /* 3+e */
  bcrypto_gf_sub_nr(d->y, d->z, d->x); /* 3+e */
  bcrypto_gf_add_nr(a, d->x, d->z);   /* 2+e */
  bcrypto_gf_mul(d->z, a, d->y);
  bcrypto_gf_mul(d->x, d->y, b);
  bcrypto_gf_mul(d->y, a, c);
  if (!before_double)
    bcrypto_gf_mul(d->t, b, c);
}

static void sub_niels_from_pt(bcrypto_curve448_point_t d, const bcrypto_niels_t e,
                int before_double)
{
  bcrypto_gf a, b, c;

  bcrypto_gf_sub_nr(b, d->y, d->x);   /* 3+e */
  bcrypto_gf_mul(a, e->b, b);
  bcrypto_gf_add_nr(b, d->x, d->y);   /* 2+e */
  bcrypto_gf_mul(d->y, e->a, b);
  bcrypto_gf_mul(d->x, e->c, d->t);
  bcrypto_gf_add_nr(c, a, d->y);    /* 2+e */
  bcrypto_gf_sub_nr(b, d->y, a);    /* 3+e */
  bcrypto_gf_add_nr(d->y, d->z, d->x); /* 2+e */
  bcrypto_gf_sub_nr(a, d->z, d->x);   /* 3+e */
  bcrypto_gf_mul(d->z, a, d->y);
  bcrypto_gf_mul(d->x, d->y, b);
  bcrypto_gf_mul(d->y, a, c);
  if (!before_double)
    bcrypto_gf_mul(d->t, b, c);
}

static void add_pniels_to_pt(bcrypto_curve448_point_t p, const bcrypto_pniels_t pn,
               int before_double)
{
  bcrypto_gf L0;

  bcrypto_gf_mul(L0, p->z, pn->z);
  bcrypto_gf_copy(p->z, L0);
  add_niels_to_pt(p, pn->n, before_double);
}

static void sub_pniels_from_pt(bcrypto_curve448_point_t p, const bcrypto_pniels_t pn,
                 int before_double)
{
  bcrypto_gf L0;

  bcrypto_gf_mul(L0, p->z, pn->z);
  bcrypto_gf_copy(p->z, L0);
  sub_niels_from_pt(p, pn->n, before_double);
}

bcrypto_c448_bool_t bcrypto_curve448_point_eq(const bcrypto_curve448_point_t p,
                const bcrypto_curve448_point_t q)
{
  bcrypto_mask_t succ;
  bcrypto_gf a, b;

  /* equality mod 2-torsion compares x/y */
  bcrypto_gf_mul(a, p->y, q->x);
  bcrypto_gf_mul(b, q->y, p->x);
  succ = bcrypto_gf_eq(a, b);

  return mask_to_bool(succ);
}

bcrypto_c448_bool_t bcrypto_curve448_point_valid(const bcrypto_curve448_point_t p)
{
  bcrypto_mask_t out;
  bcrypto_gf a, b, c;

  bcrypto_gf_mul(a, p->x, p->y);
  bcrypto_gf_mul(b, p->z, p->t);
  out = bcrypto_gf_eq(a, b);
  bcrypto_gf_sqr(a, p->x);
  bcrypto_gf_sqr(b, p->y);
  bcrypto_gf_sub(a, b, a);
  bcrypto_gf_sqr(b, p->t);
  bcrypto_gf_mulw(c, b, BCRYPTO_TWISTED_D);
  bcrypto_gf_sqr(b, p->z);
  bcrypto_gf_add(b, b, c);
  out &= bcrypto_gf_eq(a, b);
  out &= ~bcrypto_gf_eq(p->z, ZERO);
  return mask_to_bool(out);
}

bcrypto_c448_bool_t bcrypto_curve448_point_infinity(const bcrypto_curve448_point_t p)
{
  bcrypto_mask_t out;
  out = bcrypto_gf_eq(p->x, ZERO);
  out &= bcrypto_gf_eq(p->y, p->z);
  return mask_to_bool(out);
}

static inline void constant_time_lookup_niels(bcrypto_niels_s * BCRYPTO_RESTRICT ni,
                           const bcrypto_niels_t * table,
                           int nelts, int idx)
{
  constant_time_lookup(ni, table, sizeof(bcrypto_niels_s), nelts, idx);
}

void bcrypto_curve448_precomputed_scalarmul(bcrypto_curve448_point_t out,
                  const bcrypto_curve448_precomputed_s * table,
                  const bcrypto_curve448_scalar_t scalar)
{
  unsigned int i, j, k;
  const unsigned int n = BCRYPTO_COMBS_N, t = BCRYPTO_COMBS_T, s = BCRYPTO_COMBS_S;
  bcrypto_niels_t ni;
  bcrypto_curve448_scalar_t scalar1x;

  bcrypto_curve448_scalar_add(scalar1x, scalar, precomputed_scalarmul_adjustment);
  bcrypto_curve448_scalar_halve(scalar1x, scalar1x);

  for (i = s; i > 0; i--) {
    if (i != s)
      point_double_internal(out, out, 0);

    for (j = 0; j < n; j++) {
      int tab = 0;
      bcrypto_mask_t invert;

      for (k = 0; k < t; k++) {
        unsigned int bit = (i - 1) + s * (k + j * t);

        if (bit < BCRYPTO_C448_SCALAR_BITS)
          tab |=
            (scalar1x->limb[bit / BCRYPTO_WBITS] >> (bit % BCRYPTO_WBITS) & 1) << k;
      }

      invert = (tab >> (t - 1)) - 1;
      tab ^= invert;
      tab &= (1 << (t - 1)) - 1;

      constant_time_lookup_niels(ni, &table->table[j << (t - 1)],
                     1 << (t - 1), tab);

      cond_neg_niels(ni, invert);
      if ((i != s) || j != 0)
        add_niels_to_pt(out, ni, j == n - 1 && i != 1);
      else
        niels_to_pt(out, ni);
    }
  }

  OPENSSL_cleanse(ni, sizeof(ni));
  OPENSSL_cleanse(scalar1x, sizeof(scalar1x));
}

static void
prepare_fixed_window(
  bcrypto_pniels_t *multiples,
  const bcrypto_curve448_point_t b,
  int ntable
) {
  bcrypto_curve448_point_t tmp;
  bcrypto_pniels_t pn;
  int i;

  point_double_internal(tmp, b, 0);
  pt_to_pniels(pn, tmp);
  pt_to_pniels(multiples[0], b);
  bcrypto_curve448_point_copy(tmp, b);

  for (i = 1; i < ntable; i++) {
    add_pniels_to_pt(tmp, pn, 0);
    pt_to_pniels(multiples[i], tmp);
  }

  OPENSSL_cleanse(pn, sizeof(pn));
  OPENSSL_cleanse(tmp, sizeof(tmp));
}

void bcrypto_curve448_point_scalarmul(
  bcrypto_curve448_point_t a,
  const bcrypto_curve448_point_t b,
  const bcrypto_curve448_scalar_t scalar
) {
  const int WINDOW = BCRYPTO_C448_WINDOW_BITS,
            WINDOW_MASK = (1 << WINDOW) - 1,
            WINDOW_T_MASK = WINDOW_MASK >> 1,
            NTABLE = 1 << (WINDOW - 1);

  bcrypto_curve448_scalar_t scalar1x;
  bcrypto_curve448_scalar_add(scalar1x, scalar, point_scalarmul_adjustment);
  bcrypto_curve448_scalar_halve(scalar1x, scalar1x);

  /* Set up a precomputed table with odd multiples of b. */
  bcrypto_pniels_t pn, multiples[1 << ((int)(BCRYPTO_C448_WINDOW_BITS) - 1)];
  bcrypto_curve448_point_t tmp;
  prepare_fixed_window(multiples, b, NTABLE);

  /* Initialize. */
  int i, j, first = 1;
  i = BCRYPTO_C448_SCALAR_BITS - ((BCRYPTO_C448_SCALAR_BITS - 1) % WINDOW) - 1;

  for (; i >= 0; i -= WINDOW) {
    /* Fetch another block of bits */
    bcrypto_word_t bits = scalar1x->limb[i / BCRYPTO_WBITS] >> (i % BCRYPTO_WBITS);

    if (i % BCRYPTO_WBITS >= BCRYPTO_WBITS - WINDOW
        && i / BCRYPTO_WBITS < BCRYPTO_C448_SCALAR_LIMBS - 1) {
      bits ^= scalar1x->limb[i / BCRYPTO_WBITS + 1]
           << (BCRYPTO_WBITS - (i % BCRYPTO_WBITS));
    }

    bits &= WINDOW_MASK;
    bcrypto_mask_t inv = (bits>>(WINDOW-1))-1;
    bits ^= inv;

    /* Add in from table.  Compute t only on last iteration. */
    constant_time_lookup(pn, multiples, sizeof(pn), NTABLE, bits & WINDOW_T_MASK);
    cond_neg_niels(pn->n, inv);
    if (first) {
      pniels_to_pt(tmp, pn);
      first = 0;
    } else {
     /* Using Hisil et al's lookahead method instead of extensible here
      * for no particular reason.  Double WINDOW times, but only compute t on
      * the last one.
      */
      for (j = 0; j < WINDOW - 1; j++)
        point_double_internal(tmp, tmp, -1);
      point_double_internal(tmp, tmp, 0);
      add_pniels_to_pt(tmp, pn, i ? -1 : 0);
    }
  }

  /* Write out the answer */
  bcrypto_curve448_point_copy(a, tmp);

  OPENSSL_cleanse(scalar1x, sizeof(scalar1x));
  OPENSSL_cleanse(pn, sizeof(pn));
  OPENSSL_cleanse(multiples, sizeof(multiples));
  OPENSSL_cleanse(tmp, sizeof(tmp));
}

void bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(
                  uint8_t enc[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
                  const bcrypto_curve448_point_t p)
{
  bcrypto_gf x, y, z, t;
  bcrypto_curve448_point_t q;

  /* The point is now on the twisted curve.  Move it to untwisted. */
  bcrypto_curve448_point_copy(q, p);

  {
    /* 4-isogeny: 2xy/(y^+x^2), (y^2-x^2)/(2z^2-y^2+x^2) */
    bcrypto_gf u;

    bcrypto_gf_sqr(x, q->x);
    bcrypto_gf_sqr(t, q->y);
    bcrypto_gf_add(u, x, t);
    bcrypto_gf_add(z, q->y, q->x);
    bcrypto_gf_sqr(y, z);
    bcrypto_gf_sub(y, y, u);
    bcrypto_gf_sub(z, t, x);
    bcrypto_gf_sqr(x, q->z);
    bcrypto_gf_add(t, x, x);
    bcrypto_gf_sub(t, t, z);
    bcrypto_gf_mul(x, t, y);
    bcrypto_gf_mul(y, z, u);
    bcrypto_gf_mul(z, u, t);
    OPENSSL_cleanse(u, sizeof(u));
  }

  /* Affinize */
  bcrypto_gf_invert(z, z, 1);
  bcrypto_gf_mul(t, x, z);
  bcrypto_gf_mul(x, y, z);

  /* Encode */
  enc[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] = 0;
  bcrypto_gf_serialize(enc, x, 1);
  enc[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] |= 0x80 & bcrypto_gf_lobit(t);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));
  OPENSSL_cleanse(z, sizeof(z));
  OPENSSL_cleanse(t, sizeof(t));
  bcrypto_curve448_point_destroy(q);
}

bcrypto_c448_error_t bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(
                bcrypto_curve448_point_t p,
                const uint8_t enc[BCRYPTO_EDDSA_448_PUBLIC_BYTES])
{
  uint8_t enc2[BCRYPTO_EDDSA_448_PUBLIC_BYTES];
  bcrypto_mask_t low;
  bcrypto_mask_t succ;
  bcrypto_mask_t inf;

  memcpy(enc2, enc, sizeof(enc2));

  low = ~word_is_zero(enc2[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] & 0x80);
  enc2[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] &= ~0x80;

  succ = bcrypto_gf_deserialize(p->y, enc2, 1, 0);
  succ &= word_is_zero(enc2[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1]);

  bcrypto_gf_sqr(p->x, p->y);
  bcrypto_gf_sub(p->z, ONE, p->x);  /* num = 1-y^2 */
  inf = bcrypto_gf_eq(p->z, ZERO);
  bcrypto_gf_mulw(p->t, p->x, BCRYPTO_EDWARDS_D); /* dy^2 */
  bcrypto_gf_sub(p->t, ONE, p->t);  /* denom = 1-dy^2 or 1-d + dy^2 */

  bcrypto_gf_mul(p->x, p->z, p->t);
  succ &= bcrypto_gf_isr(p->t, p->x) | inf; /* 1/sqrt(num * denom) */

  bcrypto_gf_mul(p->x, p->t, p->z);   /* sqrt(num / denom) */
  bcrypto_gf_cond_neg(p->x, bcrypto_gf_lobit(p->x) ^ low);
  bcrypto_gf_cond_sel(p->x, p->x, ZERO, inf); /* allow (0, 1) and (0, -1) */
  bcrypto_gf_copy(p->z, ONE);

  /* x = 0, sign = 1 (malleable) */
  succ &= ~(bcrypto_gf_eq(p->x, ZERO) & low);

  {
    bcrypto_gf a, b, c, d;

    /* 4-isogeny 2xy/(y^2-ax^2), (y^2+ax^2)/(2-y^2-ax^2) */
    bcrypto_gf_sqr(c, p->x);
    bcrypto_gf_sqr(a, p->y);
    bcrypto_gf_add(d, c, a);
    bcrypto_gf_add(p->t, p->y, p->x);
    bcrypto_gf_sqr(b, p->t);
    bcrypto_gf_sub(b, b, d);
    bcrypto_gf_sub(p->t, a, c);
    bcrypto_gf_sqr(p->x, p->z);
    bcrypto_gf_add(p->z, p->x, p->x);
    bcrypto_gf_sub(a, p->z, d);
    bcrypto_gf_mul(p->x, a, b);
    bcrypto_gf_mul(p->z, p->t, a);
    bcrypto_gf_mul(p->y, p->t, d);
    bcrypto_gf_mul(p->t, b, d);
    OPENSSL_cleanse(a, sizeof(a));
    OPENSSL_cleanse(b, sizeof(b));
    OPENSSL_cleanse(c, sizeof(c));
    OPENSSL_cleanse(d, sizeof(d));
  }

  OPENSSL_cleanse(enc2, sizeof(enc2));
  assert(bcrypto_curve448_point_valid(p) || ~succ);

  return bcrypto_c448_succeed_if(mask_to_bool(succ));
}

bcrypto_c448_error_t bcrypto_x448_int(uint8_t out[BCRYPTO_X_PUBLIC_BYTES],
            const uint8_t base[BCRYPTO_X_PUBLIC_BYTES],
            const uint8_t scalar[BCRYPTO_X_PRIVATE_BYTES])
{
  bcrypto_gf x1, x2, z2, x3, z3, t1, t2;
  int t;
  bcrypto_mask_t swap = 0;
  bcrypto_mask_t nz;

  (void)bcrypto_gf_deserialize(x1, base, 1, 0);
  bcrypto_gf_copy(x2, ONE);
  bcrypto_gf_copy(z2, ZERO);
  bcrypto_gf_copy(x3, x1);
  bcrypto_gf_copy(z3, ONE);

  for (t = BCRYPTO_X_PRIVATE_BITS - 1; t >= 0; t--) {
    uint8_t sb = scalar[t / 8];
    bcrypto_mask_t k_t;

    /* Scalar conditioning */
    if (t / 8 == 0)
      sb &= -(uint8_t)BCRYPTO_COFACTOR;
    else if (t == BCRYPTO_X_PRIVATE_BITS - 1)
      sb = -1;

    k_t = (sb >> (t % 8)) & 1;
    k_t = 0 - k_t;       /* set to all 0s or all 1s */

    swap ^= k_t;
    bcrypto_gf_cond_swap(x2, x3, swap);
    bcrypto_gf_cond_swap(z2, z3, swap);
    swap = k_t;

    /*
     * The "_nr" below skips coefficient reduction. In the following
     * comments, "2+e" is saying that the coefficients are at most 2+epsilon
     * times the reduction limit.
     */
    bcrypto_gf_add_nr(t1, x2, z2);  /* A = x2 + z2 */ /* 2+e */
    bcrypto_gf_sub_nr(t2, x2, z2);  /* B = x2 - z2 */ /* 3+e */
    bcrypto_gf_sub_nr(z2, x3, z3);  /* D = x3 - z3 */ /* 3+e */
    bcrypto_gf_mul(x2, t1, z2);   /* DA */
    bcrypto_gf_add_nr(z2, z3, x3);  /* C = x3 + z3 */ /* 2+e */
    bcrypto_gf_mul(x3, t2, z2);   /* CB */
    bcrypto_gf_sub_nr(z3, x2, x3);  /* DA-CB */ /* 3+e */
    bcrypto_gf_sqr(z2, z3);     /* (DA-CB)^2 */
    bcrypto_gf_mul(z3, x1, z2);   /* z3 = x1(DA-CB)^2 */
    bcrypto_gf_add_nr(z2, x2, x3);  /* (DA+CB) */ /* 2+e */
    bcrypto_gf_sqr(x3, z2);     /* x3 = (DA+CB)^2 */

    bcrypto_gf_sqr(z2, t1);     /* AA = A^2 */
    bcrypto_gf_sqr(t1, t2);     /* BB = B^2 */
    bcrypto_gf_mul(x2, z2, t1);   /* x2 = AA*BB */
    bcrypto_gf_sub_nr(t2, z2, t1);  /* E = AA-BB */ /* 3+e */

    bcrypto_gf_mulw(t1, t2, -BCRYPTO_EDWARDS_D); /* E*-d = a24*E */
    bcrypto_gf_add_nr(t1, t1, z2);  /* AA + a24*E */ /* 2+e */
    bcrypto_gf_mul(z2, t2, t1);   /* z2 = E(AA+a24*E) */
  }

  /* Finish */
  bcrypto_gf_cond_swap(x2, x3, swap);
  bcrypto_gf_cond_swap(z2, z3, swap);
  bcrypto_gf_invert(z2, z2, 0);
  bcrypto_gf_mul(x1, x2, z2);
  bcrypto_gf_serialize(out, x1, 1);
  nz = ~bcrypto_gf_eq(x1, ZERO);

  OPENSSL_cleanse(x1, sizeof(x1));
  OPENSSL_cleanse(x2, sizeof(x2));
  OPENSSL_cleanse(z2, sizeof(z2));
  OPENSSL_cleanse(x3, sizeof(x3));
  OPENSSL_cleanse(z3, sizeof(z3));
  OPENSSL_cleanse(t1, sizeof(t1));
  OPENSSL_cleanse(t2, sizeof(t2));

  return bcrypto_c448_succeed_if(mask_to_bool(nz));
}

void bcrypto_curve448_point_mul_by_ratio_and_encode_like_x448(uint8_t
                            out[BCRYPTO_X_PUBLIC_BYTES],
                            const bcrypto_curve448_point_t p)
{
  bcrypto_curve448_point_t q;

  bcrypto_curve448_point_copy(q, p);
  bcrypto_gf_invert(q->t, q->x, 0);   /* 1/x */
  bcrypto_gf_mul(q->z, q->t, q->y);   /* y/x */
  bcrypto_gf_sqr(q->y, q->z);     /* (y/x)^2 */
  bcrypto_gf_serialize(out, q->y, 1);
  bcrypto_curve448_point_destroy(q);
}

void bcrypto_x448_derive_public_key(uint8_t out[BCRYPTO_X_PUBLIC_BYTES],
              const uint8_t scalar[BCRYPTO_X_PRIVATE_BYTES])
{
  /* Scalar conditioning */
  uint8_t scalar2[BCRYPTO_X_PRIVATE_BYTES];
  bcrypto_curve448_scalar_t the_scalar;
  bcrypto_curve448_point_t p;
  unsigned int i;

  memcpy(scalar2, scalar, sizeof(scalar2));
  scalar2[0] &= -(uint8_t)BCRYPTO_COFACTOR;

  scalar2[BCRYPTO_X_PRIVATE_BYTES - 1] &= ~((0u - 1u) << ((BCRYPTO_X_PRIVATE_BITS + 7) % 8));
  scalar2[BCRYPTO_X_PRIVATE_BYTES - 1] |= 1 << ((BCRYPTO_X_PRIVATE_BITS + 7) % 8);

  bcrypto_curve448_scalar_decode_long(the_scalar, scalar2, sizeof(scalar2));

  /* Compensate for the encoding ratio */
  for (i = 1; i < BCRYPTO_X448_ENCODE_RATIO; i <<= 1)
    bcrypto_curve448_scalar_halve(the_scalar, the_scalar);

  bcrypto_curve448_precomputed_scalarmul(p, bcrypto_curve448_precomputed_base, the_scalar);
  bcrypto_curve448_point_mul_by_ratio_and_encode_like_x448(out, p);
  bcrypto_curve448_point_destroy(p);
}

bcrypto_c448_bool_t bcrypto_curve448_public_key_is_infinity(
  const uint8_t ed[BCRYPTO_EDDSA_448_PUBLIC_BYTES]
) {
  static const unsigned char one[BCRYPTO_EDDSA_448_PUBLIC_BYTES] = {1};
  size_t size = BCRYPTO_EDDSA_448_PUBLIC_BYTES;
  bcrypto_mask_t ret = bcrypto_gf_bytes_eq(ed, one, size);

  return mask_to_bool(ret);
}

bcrypto_c448_bool_t bcrypto_curve448_public_key_is_small(
  const uint8_t ed[BCRYPTO_EDDSA_448_PUBLIC_BYTES]
) {
  bcrypto_curve448_point_t p;
  static const unsigned char one[BCRYPTO_EDDSA_448_PUBLIC_BYTES] = {1};
  size_t size = BCRYPTO_EDDSA_448_PUBLIC_BYTES;

  /* exclude infinity */
  if (bcrypto_gf_bytes_eq(ed, one, size))
    return BCRYPTO_C448_FALSE;

  bcrypto_c448_error_t error =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(p, ed);

  if (error != BCRYPTO_C448_SUCCESS)
    return BCRYPTO_C448_FALSE;

  /* 4-isogeny should convert small order points to infinity */
  bcrypto_c448_bool_t ret = bcrypto_curve448_point_infinity(p);

  bcrypto_curve448_point_destroy(p);

  return ret;
}

bcrypto_c448_bool_t bcrypto_curve448_public_key_has_torsion(
  const uint8_t ed[BCRYPTO_EDDSA_448_PUBLIC_BYTES]
) {
  bcrypto_curve448_point_t p;
  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];
  size_t size = BCRYPTO_EDDSA_448_PUBLIC_BYTES;
  bcrypto_mask_t ret;

  bcrypto_c448_error_t error =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(p, ed);

  if (error != BCRYPTO_C448_SUCCESS)
    return BCRYPTO_C448_FALSE;

  /* 4-isogeny should remove torsion components */
  bcrypto_curve448_point_scalarmul(p, p, bcrypto_sc_inv_4);
  bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(out, p);
  bcrypto_curve448_point_destroy(p);

  ret = ~bcrypto_gf_bytes_eq(ed, out, size);

  return mask_to_bool(ret);
}

bcrypto_c448_error_t bcrypto_x448_verify_public_key(const uint8_t x[BCRYPTO_X_PUBLIC_BYTES])
{
  bcrypto_mask_t ret;
  bcrypto_gf u;

  (void)bcrypto_gf_deserialize(u, x, 1, 0);

  ret = bcrypto_gf_valid_x(u);

  return bcrypto_c448_succeed_if(mask_to_bool(ret));
}

bcrypto_c448_bool_t bcrypto_x448_public_key_is_small(
  const uint8_t x[BCRYPTO_X_PUBLIC_BYTES]
) {
  bcrypto_mask_t ret = -1;
  bcrypto_gf x1;
  bcrypto_gf z1 = {{{1}}};
  bcrypto_gf a, aa, b, bb, c;
  int i;

  (void)bcrypto_gf_deserialize(x1, x, 1, 0);

  ret &= bcrypto_gf_valid_x(x1);

  for (i = 0; i < 2; i++) {
    /* A = X1 + Z1 */
    bcrypto_gf_add_nr(a, x1, z1);

    /* AA = A^2 */
    bcrypto_gf_sqr(aa, a);

    /* B = X1 - Z1 */
    bcrypto_gf_sub_nr(b, x1, z1);

    /* BB = B^2 */
    bcrypto_gf_sqr(bb, b);

    /* C = AA - BB */
    bcrypto_gf_sub_nr(c, aa, bb);

    /* X3 = AA * BB */
    bcrypto_gf_mul(x1, aa, bb);

    /* Z3 = C * (BB + a24 * C) */
    bcrypto_gf_mulw(a, c, -BCRYPTO_EDWARDS_D);
    bcrypto_gf_add_nr(a, a, bb);
    bcrypto_gf_mul(z1, c, a);
  }

  ret &= bcrypto_gf_eq(z1, ZERO);

  return mask_to_bool(ret);
}

bcrypto_c448_bool_t bcrypto_x448_public_key_has_torsion(
  const uint8_t x[BCRYPTO_X_PUBLIC_BYTES]
) {
  static const unsigned char order[BCRYPTO_X_PRIVATE_BYTES] = {
    0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78,
    0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2,
    0x6c, 0x21, 0x90, 0x36, 0xd6, 0xae, 0x49,
    0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
  };

  bcrypto_gf x1, x2, z2, x3, z3, t1, t2;
  bcrypto_mask_t ret = -1;
  bcrypto_mask_t swap = 0;
  bcrypto_mask_t zero;
  int t;

  (void)bcrypto_gf_deserialize(x1, x, 1, 0);

  ret &= bcrypto_gf_valid_x(x1);

  zero = bcrypto_gf_eq(x1, ZERO);

  bcrypto_gf_copy(x2, ONE);
  bcrypto_gf_copy(z2, ZERO);
  bcrypto_gf_copy(x3, x1);
  bcrypto_gf_copy(z3, ONE);

  for (t = BCRYPTO_X_PRIVATE_BITS - 1; t >= 0; t--) {
    uint8_t sb = order[t / 8];
    bcrypto_mask_t k_t;

    k_t = (sb >> (t % 8)) & 1;
    k_t = 0 - k_t;

    swap ^= k_t;
    bcrypto_gf_cond_swap(x2, x3, swap);
    bcrypto_gf_cond_swap(z2, z3, swap);
    swap = k_t;

    bcrypto_gf_add_nr(t1, x2, z2);
    bcrypto_gf_sub_nr(t2, x2, z2);
    bcrypto_gf_sub_nr(z2, x3, z3);
    bcrypto_gf_mul(x2, t1, z2);
    bcrypto_gf_add_nr(z2, z3, x3);
    bcrypto_gf_mul(x3, t2, z2);
    bcrypto_gf_sub_nr(z3, x2, x3);
    bcrypto_gf_sqr(z2, z3);
    bcrypto_gf_mul(z3, x1, z2);
    bcrypto_gf_add_nr(z2, x2, x3);
    bcrypto_gf_sqr(x3, z2);
    bcrypto_gf_sqr(z2, t1);
    bcrypto_gf_sqr(t1, t2);
    bcrypto_gf_mul(x2, z2, t1);
    bcrypto_gf_sub_nr(t2, z2, t1);
    bcrypto_gf_mulw(t1, t2, -BCRYPTO_EDWARDS_D);
    bcrypto_gf_add_nr(t1, t1, z2);
    bcrypto_gf_mul(z2, t2, t1);
  }

  bcrypto_gf_cond_swap(x2, x3, swap);
  bcrypto_gf_cond_swap(z2, z3, swap);

  ret &= ~bcrypto_gf_eq(z2, ZERO) | zero;

  return mask_to_bool(ret);
}

static bcrypto_mask_t
curve448_decode_mont(bcrypto_gf u, bcrypto_gf v,
                     const uint8_t raw[BCRYPTO_X_PUBLIC_BYTES])
{
  (void)bcrypto_gf_deserialize(u, raw, 1, 0);
  return bcrypto_gf_solve_y(v, u);
}

static void
curve448_encode_mont(uint8_t out[BCRYPTO_X_PUBLIC_BYTES], const bcrypto_gf u)
{
  bcrypto_gf_serialize(out, u, 1);
}

static bcrypto_mask_t
curve448_decode_ed448_as_mont(bcrypto_gf u0, bcrypto_gf v0,
                              const uint8_t raw[BCRYPTO_EDDSA_448_PUBLIC_BYTES])
{
  static const bcrypto_gf two = {{{2}}};
  uint8_t enc[BCRYPTO_EDDSA_448_PUBLIC_BYTES];
  bcrypto_gf x, y, y2, n, d;
  bcrypto_gf uu, uz;
  bcrypto_gf vv, vz;
  bcrypto_gf u, v, z;
  bcrypto_mask_t ret = -1;
  bcrypto_mask_t low;

  memcpy(enc, raw, sizeof(enc));

  low = ~word_is_zero(enc[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] & 0x80);
  enc[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] &= ~0x80;

  ret &= bcrypto_gf_deserialize(y, enc, 1, 0);
  ret &= word_is_zero(enc[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1]);

  /* x^2 = (y^2 - 1) / (d * y^2 - 1) */
  bcrypto_gf_sqr(y2, y);
  bcrypto_gf_sub(n, y2, ONE);
  bcrypto_gf_mulw(d, y2, BCRYPTO_EDWARDS_D);
  bcrypto_gf_sub(d, d, ONE);

  ret &= bcrypto_gf_isqrt(x, n, d);
  ret &= ~(bcrypto_gf_eq(x, ZERO) & low);

  bcrypto_gf_cond_neg(x, bcrypto_gf_lobit(x) ^ low);

  /*
   * u = y^2 / x^2
   * v = (2 - x^2 - y^2) * y / x^3
   */

  /* infinity does not exist in the mont affine space */
  ret &= ~(bcrypto_gf_eq(x, ZERO) & bcrypto_gf_eq(y, ONE));

  bcrypto_gf_sqr(uu, y);
  bcrypto_gf_sqr(uz, x);
  bcrypto_gf_sub(vv, two, uz);
  bcrypto_gf_sub(vv, vv, uu);
  bcrypto_gf_mul(vz, vv, y);
  bcrypto_gf_copy(vv, vz);
  bcrypto_gf_mul(vz, uz, x);

  bcrypto_gf_mul(u, uu, vz);
  bcrypto_gf_mul(v, vv, uz);
  bcrypto_gf_mul(z, uz, vz);

  /* note that (0, -1) will be mapped to (0, 0) */
  bcrypto_gf_invert(z, z, 0);
  bcrypto_gf_mul(u0, u, z);
  bcrypto_gf_mul(v0, v, z);

  OPENSSL_cleanse(enc, sizeof(enc));
  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));
  OPENSSL_cleanse(y2, sizeof(y2));
  OPENSSL_cleanse(n, sizeof(n));
  OPENSSL_cleanse(d, sizeof(d));
  OPENSSL_cleanse(uu, sizeof(uu));
  OPENSSL_cleanse(uz, sizeof(uz));
  OPENSSL_cleanse(vv, sizeof(vv));
  OPENSSL_cleanse(vz, sizeof(vz));
  OPENSSL_cleanse(u, sizeof(u));
  OPENSSL_cleanse(v, sizeof(v));
  OPENSSL_cleanse(z, sizeof(z));

  return ret;
}

static void
curve448_encode_mont_as_ed448(
  uint8_t ed[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
  const bcrypto_gf u,
  const bcrypto_gf v
) {
  bcrypto_curve448_point_t p;
  bcrypto_mask_t inf;
  bcrypto_gf u2, u3, u4, u5, v2;
  bcrypto_gf a, b, c, d;
  bcrypto_gf e, f, g, h;
  bcrypto_gf xx, xz, yy, yz;

  /*
   * x = 4 * v * (u^2 - 1) / (u^4 - 2 * u^2 + 4 * v^2 + 1)
   * y = -(u^5 - 2 * u^3 - 4 * u * v^2 + u) /
   *      (u^5 - 2 * u^2 * v^2 - 2 * u^3 - 2 * v^2 + u)
   */

  bcrypto_gf_sqr(u2, u);
  bcrypto_gf_mul(u3, u2, u);
  bcrypto_gf_mul(u4, u3, u);
  bcrypto_gf_mul(u5, u4, u);
  bcrypto_gf_sqr(v2, v);

  bcrypto_gf_mulw(a, v, 4);
  bcrypto_gf_sub(b, u2, ONE);
  bcrypto_gf_mulw(c, u2, 2);
  bcrypto_gf_mulw(d, v2, 4);
  bcrypto_gf_mulw(e, u3, 2);
  bcrypto_gf_mul(f, u, v2);
  bcrypto_gf_mulw(f, f, 4);
  bcrypto_gf_mul(g, u2, v2);
  bcrypto_gf_mulw(g, g, 2);
  bcrypto_gf_mulw(h, v2, 2);

  bcrypto_gf_mul(xx, a, b);

  bcrypto_gf_sub(xz, u4, c);
  bcrypto_gf_add(xz, xz, d);
  bcrypto_gf_add(xz, xz, ONE);

  bcrypto_gf_sub(yy, u5, e);
  bcrypto_gf_sub(yy, yy, f);
  bcrypto_gf_add(yy, yy, u);
  bcrypto_gf_sub(yy, ZERO, yy);

  bcrypto_gf_sub(yz, u5, g);
  bcrypto_gf_sub(yz, yz, e);
  bcrypto_gf_sub(yz, yz, h);
  bcrypto_gf_add(yz, yz, u);

  bcrypto_gf_mul(p->x, xx, yz);
  bcrypto_gf_mul(p->y, yy, xz);
  bcrypto_gf_mul(p->z, xz, yz);

  /* ensure that (0, 0) will be mapped to (0, -1) */
  /* this is then normalized to infinity */
  inf = bcrypto_gf_eq(p->z, ZERO);
  bcrypto_gf_cond_sel(p->x, p->x, ZERO, inf);
  bcrypto_gf_cond_sel(p->y, p->y, ONE, inf);
  bcrypto_gf_cond_neg(p->y, inf);
  bcrypto_gf_cond_sel(p->z, p->z, ONE, inf);

  /* 4-isogeny 2xy/(y^2-ax^2), (y^2+ax^2)/(2-y^2-ax^2) */
  bcrypto_gf_sqr(c, p->x);
  bcrypto_gf_sqr(a, p->y);
  bcrypto_gf_add(d, c, a);
  bcrypto_gf_add(p->t, p->y, p->x);
  bcrypto_gf_sqr(b, p->t);
  bcrypto_gf_sub(b, b, d);
  bcrypto_gf_sub(p->t, a, c);
  bcrypto_gf_sqr(p->x, p->z);
  bcrypto_gf_add(p->z, p->x, p->x);
  bcrypto_gf_sub(a, p->z, d);
  bcrypto_gf_mul(p->x, a, b);
  bcrypto_gf_mul(p->z, p->t, a);
  bcrypto_gf_mul(p->y, p->t, d);
  bcrypto_gf_mul(p->t, b, d);

  /* P / h^2 */
  bcrypto_curve448_point_scalarmul(p, p, bcrypto_sc_inv_16);
  bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(ed, p);
  bcrypto_curve448_point_destroy(p);

  OPENSSL_cleanse(u2, sizeof(u2));
  OPENSSL_cleanse(u3, sizeof(u3));
  OPENSSL_cleanse(u4, sizeof(u4));
  OPENSSL_cleanse(u5, sizeof(u5));
  OPENSSL_cleanse(v2, sizeof(v2));
  OPENSSL_cleanse(a, sizeof(a));
  OPENSSL_cleanse(b, sizeof(b));
  OPENSSL_cleanse(c, sizeof(c));
  OPENSSL_cleanse(d, sizeof(d));
  OPENSSL_cleanse(e, sizeof(e));
  OPENSSL_cleanse(f, sizeof(f));
  OPENSSL_cleanse(g, sizeof(g));
  OPENSSL_cleanse(h, sizeof(h));
  OPENSSL_cleanse(xx, sizeof(xx));
  OPENSSL_cleanse(xz, sizeof(xz));
  OPENSSL_cleanse(yy, sizeof(yy));
  OPENSSL_cleanse(yz, sizeof(yz));
}

static void
curve448_elligator2(bcrypto_gf x, bcrypto_gf y, const unsigned char bytes[56])
{
  static const bcrypto_gf a = {{{156326}}};

  bcrypto_mask_t alpha;
  bcrypto_gf u, x1, x2, y1, y2, t;
  bcrypto_gf one = {{{1}}};
  bcrypto_gf z = {{{1}}};

  bcrypto_gf_sub(z, ZERO, z);

  (void)bcrypto_gf_deserialize(u, bytes, 1, 0);

  /* x1 = -a / (1 + z * u^2) */
  bcrypto_gf_sqr(x1, u);
  bcrypto_gf_mul(t, x1, z);
  bcrypto_gf_add(x1, t, ONE);
  bcrypto_gf_cond_swap(x1, one, bcrypto_gf_eq(x1, ZERO));
  bcrypto_gf_invert(t, x1, 1);
  bcrypto_gf_mul(x1, a, t);
  bcrypto_gf_sub(x1, ZERO, x1);

  /* x2 = -x1 - a */
  bcrypto_gf_sub(x2, ZERO, x1);
  bcrypto_gf_sub(x2, x2, a);

  /* compute y coordinate */
  alpha = bcrypto_gf_solve_y(y1, x1);
  bcrypto_gf_solve_y(y2, x2);

  /* x = cmov(x1, x2, f(g(x1)) != 1) */
  bcrypto_gf_cond_swap(x1, x2, ~alpha);
  bcrypto_gf_cond_swap(y1, y2, ~alpha);

  /* adjust sign */
  bcrypto_gf_cond_neg(y1, bcrypto_gf_lobit(y1) ^ bcrypto_gf_lobit(u));

  bcrypto_gf_copy(x, x1);
  bcrypto_gf_copy(y, y1);

  OPENSSL_cleanse(u, sizeof(u));
  OPENSSL_cleanse(x1, sizeof(x1));
  OPENSSL_cleanse(x2, sizeof(x2));
  OPENSSL_cleanse(y1, sizeof(y1));
  OPENSSL_cleanse(y2, sizeof(y2));
  OPENSSL_cleanse(t, sizeof(t));
  OPENSSL_cleanse(one, sizeof(one));
}

static bcrypto_mask_t
curve448_invert2(
  unsigned char out[56],
  const bcrypto_gf x,
  const bcrypto_gf y,
  bcrypto_mask_t hint
) {
  static const bcrypto_gf a = {{{156326}}};

  bcrypto_mask_t ret = -1;
  bcrypto_gf n, d, u, t;
  bcrypto_gf z = {{{1}}};

  bcrypto_gf_sub(z, ZERO, z);

  /* u = sqrt(-n / (d * z)) */
  bcrypto_gf_add(n, x, a);
  bcrypto_gf_copy(d, x);
  bcrypto_gf_cond_swap(n, d, hint);
  bcrypto_gf_sub(n, ZERO, n);
  bcrypto_gf_mul(t, d, z);
  ret &= bcrypto_gf_isqrt(u, n, t);

  /* adjust sign */
  bcrypto_gf_cond_neg(u, bcrypto_gf_lobit(u) ^ bcrypto_gf_lobit(y));

  /* output */
  bcrypto_gf_serialize(out, u, 1);

  OPENSSL_cleanse(n, sizeof(n));
  OPENSSL_cleanse(d, sizeof(d));
  OPENSSL_cleanse(u, sizeof(u));
  OPENSSL_cleanse(t, sizeof(t));

  return ret;
}

static bcrypto_mask_t
curve448_point_from_hash(bcrypto_gf x, bcrypto_gf y,
                         const unsigned char bytes[112],
                         int pake)
{
  bcrypto_gf u1, v1, u2, v2;
  curve448_proj_point p1, p2;

  curve448_elligator2(u1, v1, bytes);
  curve448_elligator2(u2, v2, bytes + 56);

  /*
   * Montgomery curves don't have complete
   * addition formulas. We could compute
   * the 4-isogeny forwards and backwards
   * to Ed448 in order to do addition, but
   * this is expensive and clunky. To get
   * around this, we do the addition on
   * a twisted edwards curve.
   *
   * Assuming Curve448 is M(-A,-B), we
   * are simply moving to E(a,d).
   */
  curve448_proj_twist(&p1, u1, v1);
  curve448_proj_twist(&p2, u2, v2);
  curve448_proj_add(&p1, &p1, &p2);

  if (pake) {
    curve448_proj_dbl(&p1, &p1);
    curve448_proj_dbl(&p1, &p1);
  }

  /* Fails if P = O. */
  return curve448_proj_untwist(x, y, &p1);
}

static bcrypto_mask_t
curve448_point_to_hash(unsigned char out[112],
                       const bcrypto_gf x,
                       const bcrypto_gf y)
{
  bcrypto_mask_t ret = 0;
  bcrypto_gf x1, y1, x2, y2;
  curve448_proj_point p, p1, p2;
  unsigned char *u1 = &out[0];
  unsigned char *u2 = &out[56];
  unsigned int bit;
  bcrypto_mask_t hint;

  curve448_proj_twist(&p, x, y);

  for (;;) {
    if (!bcrypto_random(u1, 56))
      goto fail;

    if (!bcrypto_random(&bit, sizeof(unsigned int)))
      goto fail;

    curve448_elligator2(x1, y1, u1);

    /* Avoid the 2-torsion point (0, 0). */
    if (bcrypto_gf_eq(y1, ZERO))
      continue;

    curve448_proj_twist(&p1, x1, y1);
    curve448_proj_neg(&p1, &p1);
    curve448_proj_add(&p2, &p, &p1);

    if (!curve448_proj_untwist(x2, y2, &p2))
      continue;

    hint = -(bcrypto_mask_t)(bit & 1);

    if (curve448_invert2(u2, x2, y2, hint))
      break;
  }

  ret = (bcrypto_mask_t)-1;
fail:
  OPENSSL_cleanse(x1, sizeof(x1));
  OPENSSL_cleanse(y1, sizeof(y1));
  OPENSSL_cleanse(x2, sizeof(x2));
  OPENSSL_cleanse(y2, sizeof(y2));
  curve448_proj_destroy(&p);
  curve448_proj_destroy(&p1);
  curve448_proj_destroy(&p2);
  return ret;
}

bcrypto_c448_error_t bcrypto_curve448_convert_public_key_to_x448(
  uint8_t out[BCRYPTO_X_PUBLIC_BYTES],
  const uint8_t raw[BCRYPTO_EDDSA_448_PUBLIC_BYTES]
) {
  bcrypto_gf x, y;
  bcrypto_mask_t ret = -1;

  ret &= curve448_decode_ed448_as_mont(x, y, raw);

  curve448_encode_mont(out, x);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));

  return bcrypto_c448_succeed_if(mask_to_bool(ret));
}

bcrypto_c448_error_t
bcrypto_x448_convert_public_key_to_eddsa(
  uint8_t ed[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
  const uint8_t raw[BCRYPTO_X_PUBLIC_BYTES],
  int sign
) {
  bcrypto_mask_t ret = -1;
  bcrypto_gf x, y;

  ret &= curve448_decode_mont(x, y, raw);

  curve448_encode_mont_as_ed448(ed, x, y);

  (void)bcrypto_gf_deserialize(y, ed, 1, 0);

  sign &= ~bcrypto_gf_eq(y, ONE);

  ed[BCRYPTO_EDDSA_448_PUBLIC_BYTES - 1] &= ~0x80;
  ed[BCRYPTO_EDDSA_448_PUBLIC_BYTES - 1] |= sign << 7;

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));

  return bcrypto_c448_succeed_if(mask_to_bool(ret));
}

void
bcrypto_curve448_public_key_from_uniform(
  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
  const unsigned char bytes[56]
) {
  bcrypto_gf x, y;

  curve448_elligator2(x, y, bytes);
  curve448_encode_mont_as_ed448(out, x, y);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));
}

void
bcrypto_x448_public_key_from_uniform(
  uint8_t out[BCRYPTO_X_PUBLIC_BYTES],
  const unsigned char bytes[56]
) {
  bcrypto_gf x, y;

  curve448_elligator2(x, y, bytes);
  curve448_encode_mont(out, x);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));
}

bcrypto_c448_error_t
bcrypto_curve448_public_key_to_uniform(
  unsigned char out[56],
  const uint8_t pub[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
  unsigned int hint
) {
  bcrypto_mask_t ret = -1;
  bcrypto_gf x, y;

  ret &= curve448_decode_ed448_as_mont(x, y, pub);
  ret &= curve448_invert2(out, x, y, -(bcrypto_mask_t)(hint & 1));

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));

  return bcrypto_c448_succeed_if(mask_to_bool(ret));
}

bcrypto_c448_error_t
bcrypto_x448_public_key_to_uniform(
  unsigned char out[56],
  const uint8_t pub[BCRYPTO_X_PUBLIC_BYTES],
  unsigned int hint
) {
  bcrypto_mask_t ret = -1;
  bcrypto_gf x, y;

  ret &= curve448_decode_mont(x, y, pub);
  ret &= curve448_invert2(out, x, y, -(bcrypto_mask_t)(hint & 1));

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));

  return bcrypto_c448_succeed_if(mask_to_bool(ret));
}

void
bcrypto_curve448_public_key_from_hash(
  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
  const unsigned char bytes[112],
  int pake
) {
  bcrypto_gf x, y;

  (void)curve448_point_from_hash(x, y, bytes, pake);

  curve448_encode_mont_as_ed448(out, x, y);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));
}

bcrypto_c448_error_t
bcrypto_x448_public_key_from_hash(
  uint8_t out[BCRYPTO_X_PUBLIC_BYTES],
  const unsigned char bytes[112],
  int pake
) {
  bcrypto_mask_t ret = -1;
  bcrypto_gf x, y;

  ret &= curve448_point_from_hash(x, y, bytes, pake);

  curve448_encode_mont(out, x);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));

  return bcrypto_c448_succeed_if(mask_to_bool(ret));
}

bcrypto_c448_error_t
bcrypto_curve448_public_key_to_hash(
  unsigned char out[112],
  const uint8_t pub[BCRYPTO_EDDSA_448_PUBLIC_BYTES]
) {
  bcrypto_mask_t ret = -1;
  bcrypto_gf x, y;

  ret &= curve448_decode_ed448_as_mont(x, y, pub);
  ret &= curve448_point_to_hash(out, x, y);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));

  return bcrypto_c448_succeed_if(mask_to_bool(ret));
}

bcrypto_c448_error_t
bcrypto_x448_public_key_to_hash(
  unsigned char out[112],
  const uint8_t pub[BCRYPTO_X_PUBLIC_BYTES]
) {
  bcrypto_mask_t ret = -1;
  bcrypto_gf x, y;

  ret &= curve448_decode_mont(x, y, pub);
  ret &= curve448_point_to_hash(out, x, y);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));

  return bcrypto_c448_succeed_if(mask_to_bool(ret));
}

/* Control for variable-time scalar multiply algorithms. */
struct bcrypto_smvt_control {
  int power, addend;
};

#if defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 3))
# define BCRYPTO_NUMTRAILINGZEROS	__builtin_ctz
#else
# define BCRYPTO_NUMTRAILINGZEROS	numtrailingzeros
static uint32_t numtrailingzeros(uint32_t i)
{
  uint32_t tmp;
  uint32_t num = 31;

  if (i == 0)
    return 32;

  tmp = i << 16;
  if (tmp != 0) {
    i = tmp;
    num -= 16;
  }
  tmp = i << 8;
  if (tmp != 0) {
    i = tmp;
    num -= 8;
  }
  tmp = i << 4;
  if (tmp != 0) {
    i = tmp;
    num -= 4;
  }
  tmp = i << 2;
  if (tmp != 0) {
    i = tmp;
    num -= 2;
  }
  tmp = i << 1;
  if (tmp != 0)
    num--;

  return num;
}
#endif

static int recode_wnaf(struct bcrypto_smvt_control *control,
             /* [nbits/(table_bits + 1) + 3] */
             const bcrypto_curve448_scalar_t scalar,
             unsigned int table_bits)
{
  unsigned int table_size = BCRYPTO_C448_SCALAR_BITS / (table_bits + 1) + 3;
  int position = table_size - 1; /* at the end */
  uint64_t current = scalar->limb[0] & 0xFFFF;
  uint32_t mask = (1 << (table_bits + 1)) - 1;
  unsigned int w;
  const unsigned int B_OVER_16 = sizeof(scalar->limb[0]) / 2;
  unsigned int n, i;

  /* place the end marker */
  control[position].power = -1;
  control[position].addend = 0;
  position--;

  /*
   * PERF: Could negate scalar if it's large.  But then would need more cases
   * in the actual code that uses it, all for an expected reduction of like
   * 1/5 op. Probably not worth it.
   */

  for (w = 1; w < (BCRYPTO_C448_SCALAR_BITS - 1) / 16 + 3; w++) {
    if (w < (BCRYPTO_C448_SCALAR_BITS - 1) / 16 + 1) {
      /* Refill the 16 high bits of current */
      current += (uint32_t)((scalar->limb[w / B_OVER_16]
             >> (16 * (w % B_OVER_16))) << 16);
    }

    while (current & 0xFFFF) {
      uint32_t pos = BCRYPTO_NUMTRAILINGZEROS((uint32_t)current);
      uint32_t odd = (uint32_t)current >> pos;
      int32_t delta = odd & mask;

      assert(position >= 0);
      if (odd & (1 << (table_bits + 1)))
        delta -= (1 << (table_bits + 1));
      current -= delta * (1 << pos);
      control[position].power = pos + 16 * (w - 1);
      control[position].addend = delta;
      position--;
    }
    current >>= 16;
  }
  assert(current == 0);

  position++;
  n = table_size - position;
  for (i = 0; i < n; i++)
    control[i] = control[i + position];

  return n - 1;
}

static void prepare_wnaf_table(bcrypto_pniels_t * output,
                 const bcrypto_curve448_point_t working,
                 unsigned int tbits)
{
  bcrypto_curve448_point_t tmp;
  int i;
  bcrypto_pniels_t twop;

  pt_to_pniels(output[0], working);

  if (tbits == 0)
    return;

  bcrypto_curve448_point_double(tmp, working);
  pt_to_pniels(twop, tmp);

  add_pniels_to_pt(tmp, output[0], 0);
  pt_to_pniels(output[1], tmp);

  for (i = 2; i < 1 << tbits; i++) {
    add_pniels_to_pt(tmp, twop, 0);
    pt_to_pniels(output[i], tmp);
  }

  bcrypto_curve448_point_destroy(tmp);
  OPENSSL_cleanse(twop, sizeof(twop));
}

void bcrypto_curve448_base_double_scalarmul_non_secret(bcrypto_curve448_point_t combo,
                         const bcrypto_curve448_scalar_t scalar1,
                         const bcrypto_curve448_point_t base2,
                         const bcrypto_curve448_scalar_t scalar2)
{
  const int table_bits_var = BCRYPTO_C448_WNAF_VAR_TABLE_BITS;
  const int table_bits_pre = BCRYPTO_C448_WNAF_FIXED_TABLE_BITS;
  struct bcrypto_smvt_control control_var[BCRYPTO_C448_SCALAR_BITS /
                  (BCRYPTO_C448_WNAF_VAR_TABLE_BITS + 1) + 3];
  struct bcrypto_smvt_control control_pre[BCRYPTO_C448_SCALAR_BITS /
                  (BCRYPTO_C448_WNAF_FIXED_TABLE_BITS + 1) + 3];
  int ncb_pre = recode_wnaf(control_pre, scalar1, table_bits_pre);
  int ncb_var = recode_wnaf(control_var, scalar2, table_bits_var);
  bcrypto_pniels_t precmp_var[1 << BCRYPTO_C448_WNAF_VAR_TABLE_BITS];
  int contp = 0, contv = 0, i;

  prepare_wnaf_table(precmp_var, base2, table_bits_var);
  i = control_var[0].power;

  if (i < 0) {
    bcrypto_curve448_point_copy(combo, bcrypto_curve448_point_identity);
    return;
  }
  if (i > control_pre[0].power) {
    pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
    contv++;
  } else if (i == control_pre[0].power && i >= 0) {
    pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
    add_niels_to_pt(combo, bcrypto_curve448_wnaf_base[control_pre[0].addend >> 1],
            i);
    contv++;
    contp++;
  } else {
    i = control_pre[0].power;
    niels_to_pt(combo, bcrypto_curve448_wnaf_base[control_pre[0].addend >> 1]);
    contp++;
  }

  for (i--; i >= 0; i--) {
    int cv = (i == control_var[contv].power);
    int cp = (i == control_pre[contp].power);

    point_double_internal(combo, combo, i && !(cv || cp));

    if (cv) {
      assert(control_var[contv].addend);

      if (control_var[contv].addend > 0)
        add_pniels_to_pt(combo,
                 precmp_var[control_var[contv].addend >> 1],
                 i && !cp);
      else
        sub_pniels_from_pt(combo,
                   precmp_var[(-control_var[contv].addend)
                        >> 1], i && !cp);
      contv++;
    }

    if (cp) {
      assert(control_pre[contp].addend);

      if (control_pre[contp].addend > 0)
        add_niels_to_pt(combo,
                bcrypto_curve448_wnaf_base[control_pre[contp].addend
                           >> 1], i);
      else
        sub_niels_from_pt(combo,
                  bcrypto_curve448_wnaf_base[(-control_pre
                            [contp].addend) >> 1], i);
      contp++;
    }
  }

  /* This function is non-secret, but whatever this is cheap. */
  OPENSSL_cleanse(control_var, sizeof(control_var));
  OPENSSL_cleanse(control_pre, sizeof(control_pre));
  OPENSSL_cleanse(precmp_var, sizeof(precmp_var));

  assert(contv == ncb_var);
  (void)ncb_var;
  assert(contp == ncb_pre);
  (void)ncb_pre;
}

void bcrypto_curve448_point_destroy(bcrypto_curve448_point_t point)
{
  OPENSSL_cleanse(point, sizeof(bcrypto_curve448_point_t));
}

int bcrypto_x448(uint8_t out_shared_key[56], const uint8_t private_key[56],
     const uint8_t peer_public_value[56])
{
  return bcrypto_x448_int(out_shared_key, peer_public_value, private_key)
       == BCRYPTO_C448_SUCCESS;
}

void bcrypto_x448_public_from_private(uint8_t out_public_value[56],
                const uint8_t private_key[56])
{
  bcrypto_x448_derive_public_key(out_public_value, private_key);
}
