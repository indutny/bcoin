/*!
 * signature.js - signatures for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/bitcoin-core/secp256k1
 *
 * Resources:
 *   https://github.com/indutny/elliptic/blob/master/lib/elliptic/ec/signature.js
 *   https://github.com/bitcoin-core/secp256k1/blob/master/src/ecdsa_impl.h
 *   https://github.com/bitcoin-core/secp256k1/blob/master/contrib/lax_der_parsing.c
 */

'use strict';

const assert = require('bsert');
const {trimLeft, padLeft} = require('../encoding/util');

/**
 * Signature
 */

class Signature {
  constructor(size = 0, r, s) {
    this.r = padLeft(r, size);
    this.s = padLeft(s, size);
    this.param = 0;
  }

  setR(r, size) {
    this.r = padLeft(r, size);
    return this;
  }

  setS(s, size) {
    this.s = padLeft(s, size);
    return this;
  }

  encode(size) {
    assert((size >>> 0) === size);
    assert(size < 0x7d);
    assert(this.r.length === size);
    assert(this.s.length === size);

    const raw = Buffer.allocUnsafe(size * 2);

    this.r.copy(raw, 0);
    this.s.copy(raw, size);

    return raw;
  }

  decode(data, size) {
    assert(Buffer.isBuffer(data));
    assert((size >>> 0) === size);
    assert(data.length === size * 2);

    this.r = data.slice(0, size);
    this.s = data.slice(size, size * 2);

    return this;
  }

  toDER(size) {
    assert((size >>> 0) === size);
    assert(size < 0x7d);
    assert(this.r.length === size);
    assert(this.s.length === size);

    const r = encodeInt(this.r);
    const s = encodeInt(this.s);

    const seq = 2 + r.length + 2 + s.length;
    const wide = seq >= 0x80 ? 1 : 0;
    const len = 2 + wide + seq;
    const buf = Buffer.allocUnsafe(len);

    let p = 0;

    buf[p++] = 0x30;

    if (wide)
      buf[p++] = 0x81;

    buf[p++] = seq;
    buf[p++] = 0x02;
    buf[p++] = r.length;

    p += r.copy(buf, p);

    buf[p++] = 0x02;
    buf[p++] = s.length;

    p += s.copy(buf, p);

    assert(p === len);

    return buf;
  }

  fromDER(data, size) {
    assert(Buffer.isBuffer(data));
    assert((size >>> 0) === size);

    let len = 0;
    let pos = 0;
    let rlen = 0;
    let slen = 0;
    let r = null;
    let s = null;

    // Sequence tag byte.
    assert(pos + 1 <= data.length);
    assert(data[pos] === 0x30);
    pos += 1;

    // Sequence length bytes.
    assert(pos + 1 <= data.length);
    len = data[pos];
    pos += 1;

    if (len & 0x80) {
      len -= 0x80;
      assert(pos + len <= data.length);
      pos += len;
    }

    // Integer tag byte for R.
    assert(pos + 1 <= data.length);
    assert(data[pos] === 0x02);
    pos += 1;

    // Integer length for R.
    assert(pos + 1 <= data.length);
    len = data[pos];
    pos += 1;

    if (len & 0x80) {
      len -= 0x80;

      assert(pos + len <= data.length);

      while (len > 0 && data[pos] === 0x00) {
        len -= 1;
        pos += 1;
      }

      assert(len <= 6);

      while (len > 0) {
        rlen *= 0x100;
        rlen += data[pos];
        len -= 1;
        pos += 1;
      }
    } else {
      rlen = len;
    }

    // Ignore leading zeroes in R.
    assert(pos + rlen <= data.length);

    while (rlen > 0 && data[pos] === 0x00) {
      rlen -= 1;
      pos += 1;
    }

    if (rlen > size)
      r = Buffer.alloc(size, 0x00);
    else
      r = data.slice(pos, pos + rlen);

    pos += rlen;

    // Integer tag byte for S.
    assert(pos + 1 <= data.length);
    assert(data[pos] === 0x02);
    pos += 1;

    // Integer length for S.
    assert(pos + 1 <= data.length);
    len = data[pos];
    pos += 1;

    if (len & 0x80) {
      len -= 0x80;

      assert(pos + len <= data.length);

      while (len > 0 && data[pos] === 0x00) {
        len -= 1;
        pos += 1;
      }

      assert(len <= 6);

      while (len > 0) {
        slen *= 0x100;
        slen += data[pos];
        len -= 1;
        pos += 1;
      }
    } else {
      slen = len;
    }

    // Ignore leading zeroes in S.
    assert(pos + slen <= data.length);

    while (slen > 0 && data[pos] === 0x00) {
      slen -= 1;
      pos += 1;
    }

    if (slen > size)
      s = Buffer.alloc(size, 0x00);
    else
      s = data.slice(pos, pos + slen);

    pos += slen;

    this.r = padLeft(r, size);
    this.s = padLeft(s, size);

    return this;
  }

  static decode(data, size) {
    return new this().decode(data, size);
  }

  static fromDER(data, size) {
    return new this().fromDER(data, size);
  }

  static toRS(raw, size) {
    const sig = Signature.fromDER(raw, size);
    return sig.encode(size);
  }

  static toDER(raw, size) {
    const sig = Signature.decode(raw, size);
    return sig.toDER(size);
  }
}

/*
 * Helpers
 */

function encodeInt(buf) {
  const val = trimLeft(buf);

  if (val[0] & 0x80) {
    const out = Buffer.allocUnsafe(1 + val.length);
    out[0] = 0x00;
    val.copy(out, 1);
    return out;
  }

  return val;
}

/*
 * Expose
 */

module.exports = Signature;
