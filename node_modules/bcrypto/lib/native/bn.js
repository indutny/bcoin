/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/bn.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/bn.js
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on openssl/openssl:
 *   Copyright (c) 1998-2018, The OpenSSL Project (Apache License v2.0).
 *   Copyright (c) 1995-1998, Eric A. Young, Tim J. Hudson. All rights reserved.
 *   https://github.com/openssl/openssl
 *
 * Parts of this software are based on libgmp:
 *   Copyright (c) 1991-1997, 1999-2014, Free Software Foundation, Inc.
 *   https://gmplib.org/
 *
 * Parts of this software are based on v8/v8:
 *   Copyright (c) 2017, The V8 Project Authors (BSD-Style License).
 *   https://github.com/v8/v8
 *
 * Resources:
 *   https://github.com/indutny/bn.js/blob/master/lib/bn.js
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/openssl/openssl/tree/master/crypto/bn
 *   https://github.com/gnutls/nettle/blob/master/mini-gmp.c
 *   https://github.com/v8/v8/blob/master/src/objects/bigint.cc
 */

/* eslint valid-typeof: "off" */

'use strict';

const {custom} = require('../internal/custom');
const Native = require('loady')('bcrypto', __dirname).BN;

if (!Native)
  throw new Error('GMP backend not supported.');

/*
 * Constants
 */

const primes = {
  p192: null,
  p224: null,
  p521: null,
  k256: null,
  p25519: null,
  p448: null
};

/**
 * BN
 */

class BN extends Native {
  constructor(num, base, endian) {
    super();

    this.red = null;
    this.from(num, base, endian);
  }

  /*
   * Compat
   */

  get negative() {
    return this.isNeg() ? 1 : 0;
  }

  set negative(val) {
    if ((val & 1) !== this.negative)
      this.ineg();
  }

  get length() {
    return Math.floor((this.bitLength() + 25) / 26);
  }

  /*
   * Addition
   */

  add(num) {
    return this.clone().iadd(num);
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  /*
   * Subtraction
   */

  sub(num) {
    return this.clone().isub(num);
  }

  subn(num) {
    return this.clone().isubn(num);
  }

  /*
   * Multiplication
   */

  mul(num) {
    return this.clone().imul(num);
  }

  muln(num) {
    return this.clone().imuln(num);
  }

  /*
   * Multiplication + Shift
   */

  mulShift(num, bits) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    const r = this.mul(num);
    const b = r.utestn(bits - 1);

    r.iushrn(bits);

    if (this.negative ^ num.negative)
      return r.isubn(b);

    return r.iaddn(b);
  }

  /*
   * Truncation Division + Modulo
   */

  quorem(num) {
    const q = new BN();
    const r = new BN();
    super.quorem(q, r, num);
    return [q, r];
  }

  /*
   * Truncation Division
   */

  quo(num) {
    return this.clone().iquo(num);
  }

  quon(num) {
    return this.clone().iquon(num);
  }

  /*
   * Truncation Modulo
   */

  rem(num) {
    return this.clone().irem(num);
  }

  remn(num) {
    return this.clone().iremn(num);
  }

  /*
   * Euclidean Division + Modulo
   */

  divmod(num) {
    const q = new BN();
    const r = new BN();
    super.divmod(q, r, num);
    return [q, r];
  }

  /*
   * Euclidean Division
   */

  div(num) {
    return this.clone().idiv(num);
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  /*
   * Euclidean Modulo
   */

  mod(num) {
    return this.clone().imod(num);
  }

  modn(num) {
    return this.clone().imodn(num);
  }

  /*
   * Round Division
   */

  divRound(num) {
    return this.clone().idivRound(num);
  }

  /*
   * Exponentiation
   */

  pow(num) {
    return this.clone().ipow(num);
  }

  pown(num) {
    return this.clone().ipown(num);
  }

  sqr() {
    return this.clone().isqr();
  }

  /*
   * Roots
   */

  rootrem(pow) {
    const x = new BN();
    const r = new BN();
    super.rootrem(x, r, pow);
    return [x, r];
  }

  root(pow) {
    return this.clone().iroot(pow);
  }

  sqrtrem() {
    const x = new BN();
    const r = new BN();
    super.sqrtrem(x, r);
    return [x, r];
  }

  sqrt() {
    return this.clone().isqrt();
  }

  /*
   * AND
   */

  and(num) {
    return this.clone().iand(num);
  }

  andn(num) {
    return this.clone().iandn(num);
  }

  /*
   * Unsigned AND
   */

  uand(num) {
    return this.clone().iuand(num);
  }

  uandn(num) {
    return this.clone().iuandn(num);
  }

  /*
   * OR
   */

  or(num) {
    return this.clone().ior(num);
  }

  orn(num) {
    return this.clone().iorn(num);
  }

  /*
   * Unsigned OR
   */

  uor(num) {
    return this.clone().iuor(num);
  }

  uorn(num) {
    return this.clone().iuorn(num);
  }

  /*
   * XOR
   */

  xor(num) {
    return this.clone().ixor(num);
  }

  xorn(num) {
    return this.clone().ixorn(num);
  }

  /*
   * Unsigned XOR
   */

  uxor(num) {
    return this.clone().ixor(num);
  }

  uxorn(num) {
    return this.clone().iuxorn(num);
  }

  /*
   * NOT
   */

  not() {
    return this.clone().inot();
  }

  notn(width) {
    return this.clone().inotn(width);
  }

  /*
   * Left Shift
   */

  ishl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.ishln(num.toNumber());
  }

  shl(num) {
    return this.clone().ishl(num);
  }

  shln(bits) {
    return this.clone().ishln(bits);
  }

  /*
   * Unsigned Left Shift
   */

  iushl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.iushln(num.toNumber());
  }

  ushl(num) {
    return this.clone().iushl(num);
  }

  ushln(bits) {
    return this.clone().iushln(bits);
  }

  /*
   * Right Shift
   */

  ishr(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.ishrn(num.toNumber());
  }

  shr(num) {
    return this.clone().ishr(num);
  }

  shrn(bits) {
    return this.clone().ishrn(bits);
  }

  /*
   * Unsigned Right Shift
   */

  iushr(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.iushrn(num.toNumber());
  }

  ushr(num) {
    return this.clone().iushr(num);
  }

  ushrn(bits) {
    return this.clone().iushrn(bits);
  }

  /*
   * Bit Manipulation
   */

  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  umaskn(bits) {
    return this.clone().iumaskn(bits);
  }

  andln(num) {
    return super.andln(num & 0x3ffffff);
  }

  /*
   * Negation
   */

  neg() {
    return this.clone().ineg();
  }

  abs() {
    return this.clone().iabs();
  }

  /*
   * Comparison
   */

  gt(num) {
    return this.cmp(num) > 0;
  }

  gtn(num) {
    return this.cmpn(num) > 0;
  }

  gte(num) {
    return this.cmp(num) >= 0;
  }

  gten(num) {
    return this.cmpn(num) >= 0;
  }

  lt(num) {
    return this.cmp(num) < 0;
  }

  ltn(num) {
    return this.cmpn(num) < 0;
  }

  lte(num) {
    return this.cmp(num) <= 0;
  }

  lten(num) {
    return this.cmpn(num) <= 0;
  }

  /*
   * Unsigned Comparison
   */

  /*
   * Number Theoretic Functions
   */

  gcd(num) {
    return this.clone().igcd(num);
  }

  lcm(num) {
    return this.clone().ilcm(num);
  }

  egcd(p) {
    const s = new BN();
    const t = new BN();
    const g = new BN();
    super.egcd(s, t, g, p);
    return [s, t, g];
  }

  invert(num) {
    return this.clone().iinvert(num);
  }

  fermat(num) {
    return this.clone().ifermat(num);
  }

  ipowm(y, m, mont, size) {
    if (size != null)
      size >>>= 0;

    return super.ipowm(y, m, mont, size);
  }

  powm(y, m, mont, size) {
    return this.clone().ipowm(y, m, mont, size);
  }

  powmn(y, m, mont) {
    return this.clone().ipowmn(y, m, mont);
  }

  sqrtm(p) {
    return this.clone().isqrtm(p);
  }

  sqrtpq(p, q) {
    return this.clone().isqrtpq(p, q);
  }

  /*
   * Primality Testing
   */

  isPrime(rng, reps, limit) {
    enforce((reps >>> 0) === reps, 'reps', 'uint32');

    if (!this.isPrimeMR(rng, reps + 1, true))
      return false;

    if (!this.isPrimeLucas(limit))
      return false;

    return true;
  }

  isPrimeMR(rng, reps, force2) {
    if (force2 == null)
      force2 = false;

    return super.isPrimeMR(rng, reps, force2);
  }

  isPrimeLucas(limit) {
    if (limit == null)
      limit = 0;

    return super.isPrimeLucas(limit);
  }

  /*
   * Twos Complement
   */

  /*
   * Reduction Context
   */

  toRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red)
      throw new Error('Already in reduction context.');

    return ctx.convertTo(this);
  }

  fromRed() {
    red(this.red, 'fromRed');
    return this.red.convertFrom(this);
  }

  forceRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red) {
      if (!ctx.m.eq(this.red.m) || ctx.mont !== this.red.mont)
        throw new Error('Already in reduction context.');
    } else {
      range(!this.isNeg(), 'red');
      range(this.ucmp(ctx.m) < 0, 'red');
    }

    return this.clone()._forceRed(ctx);
  }

  redIAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIAdd');
    return this.red.iadd(this, num);
  }

  redAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redAdd');
    return this.red.add(this, num);
  }

  redIAddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIAddn');
    return this.red.iaddn(this, num);
  }

  redAddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redAddn');
    return this.red.addn(this, num);
  }

  redISub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redISub');
    return this.red.isub(this, num);
  }

  redSub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redSub');
    return this.red.sub(this, num);
  }

  redISubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redISubn');
    return this.red.isubn(this, num);
  }

  redSubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redSubn');
    return this.red.subn(this, num);
  }

  redIMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIMul');
    return this.red.imul(this, num);
  }

  redMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redMul');
    return this.red.mul(this, num);
  }

  redIMuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIMuln');
    return this.red.imuln(this, num);
  }

  redMuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redMuln');
    return this.red.muln(this, num);
  }

  redIDiv(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIDiv');
    return this.red.idiv(this, num);
  }

  redDiv(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redDiv');
    return this.red.div(this, num);
  }

  redIDivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIDivn');
    return this.red.idivn(this, num);
  }

  redDivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redDivn');
    return this.red.divn(this, num);
  }

  redIPow(num, size) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIPow');
    nonred(!num.red, 'redIPow');
    return this.red.ipow(this, num, size);
  }

  redPow(num, size) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redPow');
    nonred(!num.red, 'redPow');
    return this.red.pow(this, num, size);
  }

  redIPown(num) {
    red(this.red, 'redIPown');
    return this.red.ipown(this, num);
  }

  redPown(num) {
    red(this.red, 'redPown');
    return this.red.pown(this, num);
  }

  redISqr() {
    red(this.red, 'redISqr');
    return this.red.isqr(this);
  }

  redSqr() {
    red(this.red, 'redSqr');
    return this.red.sqr(this);
  }

  redISqrt() {
    red(this.red, 'redISqrt');
    return this.red.isqrt(this);
  }

  redSqrt() {
    red(this.red, 'redSqrt');
    return this.red.sqrt(this);
  }

  redIDivSqrt(v) {
    red(this.red, 'redIDivSqrt');
    return this.red.idivsqrt(this, v);
  }

  redDivSqrt(v) {
    red(this.red, 'redDivSqrt');
    return this.red.divsqrt(this, v);
  }

  redIsSquare() {
    red(this.red, 'redIsSquare');
    return this.red.isSquare(this);
  }

  redIShl(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIShl');
    nonred(!num.red, 'redIShl');
    return this.red.ishl(this, num);
  }

  redShl(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redShl');
    nonred(!num.red, 'redShl');
    return this.red.shl(this, num);
  }

  redIShln(num) {
    enforce((num >>> 0) === num, 'num', 'uint32');
    red(this.red, 'redIShln');
    return this.red.ishln(this, num);
  }

  redShln(num) {
    enforce((num >>> 0) === num, 'num', 'uint32');
    red(this.red, 'redShln');
    return this.red.shln(this, num);
  }

  redINeg() {
    red(this.red, 'redINeg');
    return this.red.ineg(this);
  }

  redNeg() {
    red(this.red, 'redNeg');
    return this.red.neg(this);
  }

  redEq(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redEq');
    return this.red.eq(this, num);
  }

  redEqn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redEqn');
    return this.red.eqn(this, num);
  }

  redIsHigh() {
    red(this.red, 'redIsHigh');
    return this.red.isHigh(this);
  }

  redIsLow() {
    red(this.red, 'redIsLow');
    return this.red.isLow(this);
  }

  redIsOdd() {
    red(this.red, 'redIsOdd');
    return this.red.isOdd(this);
  }

  redIsEven() {
    red(this.red, 'redIsEven');
    return this.red.isEven(this);
  }

  redLegendre() {
    red(this.red, 'redLegendre');
    return this.red.legendre(this);
  }

  redJacobi() {
    red(this.red, 'redJacobi');
    return this.red.jacobi(this);
  }

  redKronecker() {
    red(this.red, 'redKronecker');
    return this.red.kronecker(this);
  }

  redIInvert() {
    red(this.red, 'redIInvert');
    return this.red.iinvert(this);
  }

  redInvert() {
    red(this.red, 'redInvert');
    return this.red.invert(this);
  }

  redIFermat() {
    red(this.red, 'redIFermat');
    return this.red.ifermat(this);
  }

  redFermat() {
    red(this.red, 'redFermat');
    return this.red.fermat(this);
  }

  /*
   * Internal
   */

  _forceRed(ctx) {
    this.red = ctx;
    return this;
  }

  /*
   * Helpers
   */

  clone() {
    return new BN().inject(this);
  }

  inject(num) {
    super.inject(num);
    this.red = num.red;
    return this;
  }

  set(num, endian) {
    return this.fromNumber(num, endian);
  }

  swap(num) {
    super.swap(num);
    [this.red, num.red] = [num.red, this.red];
    return this;
  }

  reverse() {
    const neg = this.negative;

    this.fromBuffer(this.toBuffer('le'), 'be');
    this.negative = neg;

    return this;
  }

  word(pos) {
    enforce((pos >>> 0) === pos, 'pos', 'uint32');

    if (pos === 0)
      return this.andln(-1);

    return this.ushrn(pos * 26).andln(-1);
  }

  [custom]() {
    let prefix = 'BN';

    if (this.red)
      prefix = 'BN-R';

    return `<${prefix}: ${this.toString(10)}>`;
  }

  /*
   * Constant Time (sort of)
   */

  csign() {
    return this.sign();
  }

  czero() {
    const sign = this.sign();
    const nz = ((sign >> 31) | (-sign >> 31)) & 1;

    return 1 - nz;
  }

  cneg() {
    return this.isNeg() | 0;
  }

  cpos() {
    return this.isPos() | 0;
  }

  ceq(num) {
    return this.xor(num).czero();
  }

  ceqn(num) {
    const neg = (num >> 31) | 1;
    const word = (((num | 0) * neg) & 0x3ffffff) * neg;

    return this.xorn(word).czero();
  }

  cswap(num, flag) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const cond = ((flag >> 31) | (-flag >> 31)) & 1;
    const a = this.muln(cond ^ 1).iadd(num.muln(cond));
    const b = num.muln(cond ^ 1).iadd(this.muln(cond));

    this.inject(a);
    num.inject(b);

    return this;
  }

  cinject(num, flag) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const cond = ((flag >> 31) | (-flag >> 31)) & 1;
    const b = num.muln(cond);

    this.imuln(cond ^ 1).iadd(b);

    return this;
  }

  cset(num, flag) {
    const cond = ((flag >> 31) | (-flag >> 31)) & 1;
    const neg = (num >> 31) | 1;
    const word = (((num | 0) * neg) & 0x3ffffff) * neg;

    this.imuln(cond ^ 1).iaddn(word * cond);

    return this;
  }

  /*
   * Conversion
   */

  valueOf() {
    return this.toDouble();
  }

  toBigInt() {
    const str = super.toString(16);

    let n = BigInt(`0x${str}`);

    if (this.isNeg())
      n = -n;

    return n;
  }

  toString(base, padding) {
    let str = super.toString(getBase(base));

    if (padding == null)
      padding = 0;

    if (padding === 0)
      padding = 1;

    enforce((padding >>> 0) === padding, 'padding', 'uint32');

    while (str.length % padding)
      str = '0' + str;

    if (this.isNeg())
      str = '-' + str;

    return str;
  }

  toJSON() {
    return this.toString(16, 2);
  }

  toArray(endian, length) {
    // 1.75x faster than the common case.
    const buf = this.toBuffer(endian, length);

    if (Array.from)
      return Array.from(buf);

    return Array.prototype.slice.call(buf);
  }

  toBuffer(endian, length) {
    if (endian == null)
      endian = 'be';

    if (length == null)
      length = 0;

    return super.toBuffer(endian, length);
  }

  toArrayLike(ArrayType, endian, length) {
    if (ArrayType === Buffer)
      return this.toBuffer(endian, length);

    if (ArrayType === Array)
      return this.toArray(endian, length);

    if (ArrayType === Int8Array
        || ArrayType === Uint8Array
        || ArrayType === Uint8ClampedArray) {
      const buf = this.toBuffer(endian, length);
      return new ArrayType(buf.buffer, buf.byteOffset, buf.byteLength);
    }

    enforce(typeof ArrayType === 'function', 'ArrayType', 'function');

    const buf = this.toBuffer(endian, length);
    const arr = allocate(ArrayType, buf.length);

    for (let i = 0; i < buf.length; i++)
      arr[i] = buf[i];

    return arr;
  }

  encode(endian, length) {
    return this.toBuffer(endian, length);
  }

  /*
   * Instantiation
   */

  of(num, endian) {
    return this.fromNumber(num, endian);
  }

  fromNumber(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    super.fromNumber(num);

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromDouble(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'number', 'num', 'double');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (!isFinite(num))
      num = 0;

    super.fromDouble(num);

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromBigInt(num, endian) {
    enforce(typeof num === 'bigint', 'num', 'bigint');
    return this.fromString(num.toString(16), 16, endian);
  }

  fromString(str, base, endian) {
    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    if (endian == null)
      endian = 'be';

    super.fromString(str, getBase(base));

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromJSON(json) {
    if (BN.isBN(json)) {
      if (json.red)
        return json.fromRed();

      return json.clone();
    }

    if (Array.isArray(json)) {
      for (const chunk of json)
        enforce(typeof chunk === 'string', 'chunk', 'string');

      json = json.join('');
    }

    return this.fromString(json, 16);
  }

  fromBN(num) {
    return this.inject(num);
  }

  fromArray(data, endian) {
    enforce(Array.isArray(data), 'data', 'array');
    return this.fromBuffer(Buffer.from(data), endian);
  }

  fromBuffer(data, endian) {
    if (endian == null)
      endian = 'be';

    return super.fromBuffer(data, endian);
  }

  fromArrayLike(data, endian) {
    if (Buffer.isBuffer(data))
      return this.fromBuffer(data, endian);

    if (Array.isArray(data))
      return this.fromArray(data, endian);

    if ((data instanceof Int8Array)
        || (data instanceof Uint8Array)
        || (data instanceof Uint8ClampedArray)) {
      const raw = Buffer.from(data.buffer,
                              data.byteOffset,
                              data.byteLength);

      return this.fromBuffer(raw, endian);
    }

    return this.fromBuffer(Buffer.from(data), endian);
  }

  decode(data, endian) {
    return this.fromBuffer(data, endian);
  }

  from(num, base, endian) {
    if (num == null)
      return this;

    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    if (typeof num === 'number')
      return this.fromNumber(num, endian);

    if (typeof num === 'bigint')
      return this.fromBigInt(num, endian);

    if (typeof num === 'string')
      return this.fromString(num, base, endian);

    if (typeof num === 'object') {
      if (BN.isBN(num))
        return this.fromBN(num, endian);

      if (Buffer.isBuffer(num))
        return this.fromBuffer(num, endian);

      if ((num.length >>> 0) === num.length)
        return this.fromArrayLike(num, endian);
    }

    if (typeof num === 'boolean')
      return this.fromBool(num);

    throw new TypeError('Non-numeric object passed to BN.');
  }

  /*
   * Static Methods
   */

  static min(...args) {
    let min = null;

    for (const num of args) {
      enforce(BN.isBN(num), 'num', 'bignum');

      if (!min || num.cmp(min) < 0)
        min = num;
    }

    return min || new BN(0);
  }

  static max(...args) {
    let max = null;

    for (const num of args) {
      enforce(BN.isBN(num), 'num', 'bignum');

      if (!max || num.cmp(max) > 0)
        max = num;
    }

    return max || new BN(0);
  }

  static cmp(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.cmp(b);
  }

  static ucmp(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.ucmp(b);
  }

  static red(num) {
    return new Red(num, false);
  }

  static mont(num) {
    return new Red(num, true);
  }

  static _prime(name) {
    if (primes[name])
      return primes[name];

    let prime;

    if (name === 'p192')
      prime = new P192();
    else if (name === 'p224')
      prime = new P224();
    else if (name === 'p521')
      prime = new P521();
    else if (name === 'k256')
      prime = new K256();
    else if (name === 'p25519')
      prime = new P25519();
    else if (name === 'p448')
      prime = new P448();
    else
      throw new Error(`Unknown prime: "${name}".`);

    primes[name] = prime;

    return prime;
  }

  static prime(name) {
    return BN._prime(name).p.clone();
  }

  static pow(num, exp) {
    if (num === 2)
      return BN.shift(1, exp);

    return new BN().fromNumber(num).ipown(exp);
  }

  static shift(num, bits) {
    return new BN().fromNumber(num).ishln(bits);
  }

  static mask(bits) {
    return BN.shift(1, bits).isubn(1);
  }

  static randomBits(rng, bits) {
    return super.randomBits(rng, new BN(), bits);
  }

  static random(rng, min, max) {
    const a = new BN();
    const b = BN.cast(min, 16);
    const c = BN.cast(max, 16);
    return super.random(rng, a, b, c);
  }

  static of(num, endian) {
    return new BN().of(num, endian);
  }

  static fromNumber(num, endian) {
    return new BN().fromNumber(num, endian);
  }

  static fromDouble(num, endian) {
    return new BN().fromDouble(num, endian);
  }

  static fromBigInt(num, endian) {
    return new BN().fromBigInt(num, endian);
  }

  static fromBool(value) {
    return new BN().fromBool(value);
  }

  static fromString(str, base, endian) {
    return new BN().fromString(str, base, endian);
  }

  static fromJSON(json) {
    return new BN().fromJSON(json);
  }

  static fromBN(num) {
    return new BN().fromBN(num);
  }

  static fromArray(data, endian) {
    return new BN().fromArray(data, endian);
  }

  static fromBuffer(data, endian) {
    return new BN().fromBuffer(data, endian);
  }

  static fromArrayLike(data, endian) {
    return new BN().fromArrayLike(data, endian);
  }

  static decode(data, endian) {
    return new BN().decode(data, endian);
  }

  static from(num, base, endian) {
    return new BN().from(num, base, endian);
  }

  static cast(num, base, endian) {
    if (BN.isBN(num))
      return num;

    return new BN(num, base, endian);
  }

  static isBN(obj) {
    return obj instanceof BN;
  }
}

/*
 * Static
 */

BN.BN = BN;
BN.wordSize = 26;
BN.native = 2;

/**
 * Prime
 */

class Prime {
  constructor(name, p) {
    this.name = name;
    this.p = new BN(p, 16);
  }
}

/**
 * P192
 */

class P192 extends Prime {
  constructor() {
    // 2^192 - 2^64 - 1 (= 3 mod 4)
    super('p192', 'ffffffff ffffffff ffffffff fffffffe'
                + 'ffffffff ffffffff');
  }
}

/**
 * P224
 */

class P224 extends Prime {
  constructor() {
    // 2^224 - 2^96 + 1 (no congruence)
    super('p224', 'ffffffff ffffffff ffffffff ffffffff'
                + '00000000 00000000 00000001');
  }
}

/**
 * P521
 */

class P521 extends Prime {
  constructor() {
    // 2^521 - 1 (= 3 mod 4)
    super('p521', '000001ff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff');
  }
}

/**
 * K256
 */

class K256 extends Prime {
  constructor() {
    // 2^256 - 2^32 - 977 (= 3 mod 4)
    super('k256', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe fffffc2f');
  }
}

/**
 * P25519
 */

class P25519 extends Prime {
  constructor() {
    // 2^255 - 19 (= 5 mod 8)
    super('p25519', '7fffffff ffffffff ffffffff ffffffff'
                  + 'ffffffff ffffffff ffffffff ffffffed');
  }
}

/**
 * P448
 */

class P448 extends Prime {
  constructor() {
    // 2^448 - 2^224 - 1 (= 3 mod 4)
    super('p448', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff');
  }
}

/**
 * Reduction Engine
 */

class Red {
  constructor(m, coprime) {
    let prime = null;

    if (typeof m === 'string') {
      prime = BN._prime(m);
      m = prime.p;
    }

    enforce(BN.isBN(m), 'm', 'bignum');
    nonred(!m.red, 'reduction');
    range(m.sign() > 0, 'reduction');

    this.m = m;
    this.prime = prime;
    this.coprime = coprime;
    this.smi = m.bitLength() <= 26 ? m.andln(-1) : 0;
    this.sm1 = null;
  }

  _verify1(a) {
    range(a.negative === 0, 'red');
    red(a.red != null, 'red');
  }

  _verify2(a, b) {
    range((a.negative | b.negative) === 0, 'red');
    red(a.red != null && a.red === b.red, 'red');
  }

  get mont() {
    return false;
  }

  precompute() {
    // Precompute `sqrt(-1)` for primes congruent to 5 mod 8.
    if (this.sm1 === null && this.m.andln(7) === 5) {
      const x = new BN(2).toRed(this);
      const e = this.m.subn(1).iushrn(2);

      // sqrt(-1) = 2^((p - 1) / 4) mod p
      this.sm1 = this.pow(x, e);
    }

    return this;
  }

  convertTo(num) {
    const res = num.mod(this.m);
    res.red = this;
    return res;
  }

  convertFrom(num) {
    const res = num.clone();
    res.red = null;
    return res;
  }

  iadd(a, b) {
    this._verify2(a, b);

    a.iadd(b);

    if (a.cmp(this.m) >= 0)
      a.isub(this.m);

    return a;
  }

  add(a, b) {
    return this.iadd(a.clone(), b);
  }

  iaddn(a, num) {
    this._verify1(a);

    if (num < 0)
      return this.isubn(a, -num);

    if (this.smi)
      num %= this.smi;

    a.iaddn(num);

    if (a.cmp(this.m) >= 0)
      a.isub(this.m);

    return a;
  }

  addn(a, num) {
    return this.iaddn(a.clone(), num);
  }

  isub(a, b) {
    this._verify2(a, b);

    a.isub(b);

    if (a.isNeg())
      a.iadd(this.m);

    return a;
  }

  sub(a, b) {
    return this.isub(a.clone(), b);
  }

  isubn(a, num) {
    this._verify1(a);

    if (num < 0)
      return this.iaddn(a, -num);

    if (this.smi)
      num %= this.smi;

    a.isubn(num);

    if (a.isNeg())
      a.iadd(this.m);

    return a;
  }

  subn(a, num) {
    return this.isubn(a.clone(), num);
  }

  imul(a, b) {
    this._verify2(a, b);
    return a.imul(b).imod(this.m);
  }

  mul(a, b) {
    this._verify2(a, b);
    return this.imul(a.clone(), b);
  }

  imuln(a, num) {
    this._verify1(a);
    return a.imuln(num).imod(this.m);
  }

  muln(a, num) {
    return this.imuln(a.clone(), num);
  }

  idiv(a, b) {
    this._verify2(a, b);
    return a.imul(b.invert(this.m)).imod(this.m);
  }

  div(a, b) {
    return this.idiv(a.clone(), b);
  }

  idivn(a, num) {
    return this.idiv(a, this.convertTo(new BN(num)));
  }

  divn(a, num) {
    return this.idivn(a.clone(), num);
  }

  ipow(a, num, size) {
    this._verify1(a);
    return a.ipowm(num, this.m, false, size);
  }

  pow(a, num, size) {
    return this.ipow(a.clone(), num, size);
  }

  ipown(a, num) {
    this._verify1(a);
    return a.ipowmn(num, this.m, false);
  }

  pown(a, num) {
    return this.ipown(a.clone(), num);
  }

  isqr(a) {
    this._verify1(a);
    return a.isqr().imod(this.m);
  }

  sqr(a) {
    return this.isqr(a.clone());
  }

  isqrt(a) {
    this._verify1(a);

    if (this.sm1 != null)
      return this.isqrt5mod8sm1(a);

    return a.isqrtm(this.m);
  }

  isqrt5mod8sm1(x) {
    const e = this.m.addn(3).iushrn(3);

    let b = this.pow(x, e);

    if (!this.sqr(b).eq(x)) {
      b = this.mul(b, this.sm1);

      if (!this.sqr(b).eq(x))
        throw new Error('X is not a square mod P.');
    }

    return x.inject(b);
  }

  sqrt(a) {
    return this.isqrt(a.clone());
  }

  idivsqrt(u, v) {
    return this.divsqrt(u, v)._move(u);
  }

  divsqrt(u, v) {
    this._verify2(u, v);

    // v = 0
    if (v.isZero())
      throw new RangeError('Not invertible.');

    // p = 3 mod 4
    if (this.m.andln(3) === 3)
      return this.divsqrt3mod4(u, v);

    // p = 5 mod 8
    if (this.sm1 != null && this.m.andln(7) === 5)
      return this.divsqrt5mod8(u, v);

    return this.sqrt(this.div(u, v));
  }

  divsqrt3mod4(u, v) {
    // x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p
    const e = this.m.subn(3).iushrn(2);
    const u2 = this.sqr(u);
    const u3 = this.mul(u2, u);
    const u5 = this.mul(u3, u2);
    const v3 = this.mul(this.sqr(v), v);
    const p = this.pow(this.mul(u5, v3), e);
    const x = this.mul(this.mul(u3, v), p);
    const c = this.mul(v, this.sqr(x));

    if (c.cmp(u) === 0)
      return x;

    throw new Error('X is not a square mod P.');
  }

  divsqrt5mod8(u, v) {
    // x = u * v^3 * (u * v^7)^((p - 5) / 8) mod p
    const e = this.m.subn(5).iushrn(3);
    const v3 = this.mul(this.sqr(v), v);
    const v7 = this.mul(this.sqr(v3), v);
    const p = this.pow(this.mul(u, v7), e);
    const x = this.mul(this.mul(u, v3), p);
    const c = this.mul(v, this.sqr(x));

    if (c.cmp(u) === 0)
      return x;

    if (this.ineg(c).cmp(u) === 0)
      return this.mul(x, this.sm1);

    throw new Error('X is not a square mod P.');
  }

  isSquare(a) {
    this._verify1(a);

    let symbol;

    if (this.prime || this.coprime)
      symbol = a.legendre(this.m);
    else if (this.m.isOdd())
      symbol = a.jacobi(this.m);
    else
      symbol = a.kronecker(this.m);

    return Boolean(~symbol >>> 31);
  }

  ishl(a, num) {
    this._verify1(a);
    return a.iushl(num).imod(this.m);
  }

  shl(a, num) {
    return this.ishl(a.clone(), num);
  }

  ishln(a, num) {
    this._verify1(a);
    return a.iushln(num).imod(this.m);
  }

  shln(a, num) {
    return this.ishln(a.clone(), num);
  }

  ineg(a) {
    this._verify1(a);

    if (!a.isZero()) {
      a.isub(this.m);
      a.ineg();
    }

    return a;
  }

  neg(a) {
    return this.ineg(a.clone());
  }

  eq(a, b) {
    this._verify2(a, b);
    return a.ucmp(b) === 0;
  }

  eqn(a, num) {
    this._verify1(a);

    if (this.smi) {
      num %= this.smi;

      if (num < 0)
        num += this.smi;

      return a.ucmpn(num) === 0;
    }

    if (num < 0) {
      this.m.iaddn(num);

      const cmp = a.ucmp(this.m);

      this.m.isubn(num);

      return cmp === 0;
    }

    return a.ucmpn(num) === 0;
  }

  isHigh(a) {
    return !this.isLow(a);
  }

  isLow(a) {
    this._verify1(a);
    return a.ucmp(this.m.ushrn(1)) <= 0;
  }

  isOdd(a) {
    this._verify1(a);
    return a.isOdd();
  }

  isEven(a) {
    this._verify1(a);
    return a.isEven();
  }

  legendre(a) {
    this._verify1(a);
    return a.legendre(this.m);
  }

  jacobi(a) {
    this._verify1(a);
    return a.jacobi(this.m);
  }

  kronecker(a) {
    this._verify1(a);
    return a.kronecker(this.m);
  }

  iinvert(a) {
    this._verify1(a);
    return a.iinvert(this.m);
  }

  invert(a) {
    return this.iinvert(a.clone());
  }

  ifermat(a) {
    this._verify1(a);
    return a.ifermat(this.m);
  }

  fermat(a) {
    return this.ifermat(a.clone());
  }

  [custom]() {
    if (this.prime)
      return `<Red: ${this.prime.name}>`;

    return `<Red: ${this.m.toString(10)}>`;
  }
}

/*
 * Helpers
 */

function makeError(Error, msg, start) {
  const err = new Error(msg);

  if (Error.captureStackTrace)
    Error.captureStackTrace(err, start);

  return err;
}

function enforce(value, name, type) {
  if (!value) {
    const msg = `"${name}" must be a(n) ${type}.`;
    throw makeError(TypeError, msg, enforce);
  }
}

function range(value, name) {
  if (!value) {
    const msg = `"${name}" only works with positive numbers.`;
    throw makeError(RangeError, msg, range);
  }
}

function red(value, name) {
  if (!value) {
    const msg = `"${name}" only works with red numbers.`;
    throw makeError(TypeError, msg, red);
  }
}

function nonred(value, name) {
  if (!value) {
    const msg = `"${name}" only works with normal numbers.`;
    throw makeError(TypeError, msg, nonred);
  }
}

function isInteger(num) {
  return Number.isSafeInteger(num);
}

function isSMI(num) {
  return isInteger(num)
      && num >= -0x3ffffff
      && num <= 0x3ffffff;
}

function allocate(ArrayType, size) {
  if (ArrayType.allocUnsafe)
    return ArrayType.allocUnsafe(size);

  return new ArrayType(size);
}

function getBase(base) {
  if (base == null)
    return 10;

  if (typeof base === 'number')
    return base;

  switch (base) {
    case 'bin':
      return 2;
    case 'oct':
      return 8;
    case 'dec':
      return 10;
    case 'hex':
      return 16;
  }

  return 0;
}

/*
 * Expose
 */

BN.Red = Red;

module.exports = BN;
