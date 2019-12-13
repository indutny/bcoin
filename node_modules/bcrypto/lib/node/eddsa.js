/*!
 * eddsa.js - ed25519 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const JS = require('../js/eddsa');

// This API is unstable prior to node 12.
if (!crypto.sign || !crypto.verify)
  throw new Error('EDDSA backend not supported.');

/*
 * ASN.1 Key Prefixes
 */

const prefixes = {
  pkcs8: {
    ED25519: Buffer.from('302e020100300506032b657004220420', 'hex'),
    ED448: Buffer.from('3047020100300506032b6571043b0439', 'hex')
  },
  spki: {
    ED25519: Buffer.from('302a300506032b6570032100', 'hex'),
    ED448: Buffer.from('3043300506032b6571033a00', 'hex')
  }
};

/*
 * Invalid Points
 */

const invalid = {
  ED25519: [
    Buffer.from('01000000000000000000000000000000'
              + '00000000000000000000000000000080', 'hex'),
    Buffer.from('ecffffffffffffffffffffffffffffff'
              + 'ffffffffffffffffffffffffffffffff', 'hex')
  ],
  ED448: [
    Buffer.from('0100000000000000000000000000'
              + '0000000000000000000000000000'
              + '0000000000000000000000000000'
              + '000000000000000000000000000080', 'hex'),
    Buffer.from('feffffffffffffffffffffffffff'
              + 'ffffffffffffffffffffffffffff'
              + 'feffffffffffffffffffffffffff'
              + 'ffffffffffffffffffffffffffff80', 'hex')
  ]
};

/*
 * Fallback Points (Ed448)
 */

const fallback = [
  Buffer.from('0100000000000000000000000000'
            + '0000000000000000000000000000'
            + '0000000000000000000000000000'
            + '000000000000000000000000000000', 'hex'),
  Buffer.from('feffffffffffffffffffffffffff'
            + 'ffffffffffffffffffffffffffff'
            + 'feffffffffffffffffffffffffff'
            + 'ffffffffffffffffffffffffffff00', 'hex')
];

/*
 * EDDSA
 */

class EDDSA extends JS {
  constructor(id, xid, hash, pre) {
    super(id, xid, hash, pre);
    this.native = 1;
    this.field = this.curve.encodeField(this.curve.p);
    this.order = this.curve.encodeField(this.curve.n);
  }

  publicKeyCreate(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.curve.fieldSize);

    // Added in 11.6.0.
    // `key` allowed to be private in 11.7.0.
    // Note that this function is known to
    // crash prior to node 12.0.0.
    const pub = crypto.createPublicKey({
      key: exportPrivate(this.id, secret),
      format: 'der',
      type: 'pkcs8'
    });

    const raw = pub.export({
      format: 'der',
      type: 'spki'
    });

    return importPublic(this.id, raw);
  }

  sign(msg, secret, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.curve.fieldSize);

    if (this.curve.context && ph === false)
      ph = null;

    if (ph != null || (ctx && ctx.length > 0))
      return super.sign(msg, secret, ph, ctx);

    // Added in 12.0.0.
    return crypto.sign(null, msg, {
      key: exportPrivate(this.id, secret),
      format: 'der',
      type: 'pkcs8'
    });
  }

  _openssl(msg, sig, key) {
    const R = sig.slice(0, this.curve.fieldSize);

    // Check for `x == 0 && sign == 1`.
    if (isInvalid(this.id, key) || isInvalid(this.id, R))
      return false;

    if (this.id === 'ED25519') {
      // OpenSSL checks for canonical scalars
      // and implicitly checks for canonical
      // R values, but it does not check that
      // the key is canonical.
      if (!isCanonical(key, this.field, true))
        return false;
    }

    if (this.id === 'ED448') {
      // Check S < N.
      const S = sig.slice(this.curve.fieldSize);

      if (!isCanonical(S, this.order, false))
        return false;

      // Check for (0, 1) and (0, -1).
      if (isFallback(key) || isFallback(R))
        return super._verifySingle(msg, sig, key, null, null);
    }

    // Added in 12.0.0.
    return crypto.verify(null, msg, {
      key: exportPublic(this.id, key),
      format: 'der',
      type: 'spki'
    }, sig);
  }

  _verify(msg, sig, key, ph, ctx) {
    if (this.curve.context && ph === false)
      ph = null;

    if (ph != null || (ctx && ctx.length > 0))
      return super._verify(msg, sig, key, ph, ctx);

    // Note that the Ed448 backend uses cofactor
    // verification. We consider this the default.
    return this._openssl(msg, sig, key);
  }

  _verifySingle(msg, sig, key, ph, ctx) {
    if (this.curve.context && ph === false)
      ph = null;

    if (ph != null || (ctx && ctx.length > 0))
      return super._verifySingle(msg, sig, key, ph, ctx);

    // Ed25519 backend uses cofactor-less verification.
    if (this.id === 'ED25519')
      return super._verifySingle(msg, sig, key, ph, ctx);

    return this._openssl(msg, sig, key);
  }

  _verifyBatch(batch, ph, ctx) {
    if (this.curve.context && ph === false)
      ph = null;

    if (ph != null || (ctx && ctx.length > 0))
      return super._verifyBatch(batch, ph, ctx);

    // Ed25519 backend uses cofactor-less verification.
    if (this.id === 'ED25519')
      return super._verifyBatch(batch, ph, ctx);

    for (const [msg, sig, key] of batch) {
      if (!this._openssl(msg, sig, key))
        return false;
    }

    return true;
  }
}

/*
 * Helpers
 */

function exportPrivate(id, secret) {
  const prefix = prefixes.pkcs8[id];

  if (prefix)
    return Buffer.concat([prefix, secret]);

  return new pkcs8.PrivateKeyInfo(
    0,
    asn1.objects.curves[id],
    new asn1.Null(),
    new asn1.OctString(secret).encode()
  ).encode();
}

function exportPublic(id, key) {
  const prefix = prefixes.spki[id];

  if (prefix)
    return Buffer.concat([prefix, key]);

  return new x509.SubjectPublicKeyInfo(
    asn1.objects.curves[id],
    new asn1.Null(),
    key
  ).encode();
}

function importPublic(id, raw) {
  const prefix = prefixes.spki[id];

  let spki = null;
  let key;

  if (prefix) {
    key = raw.slice(prefix.length);
  } else {
    spki = x509.SubjectPublicKeyInfo.decode(raw);
    key = spki.publicKey.rightAlign();
  }

  return key;
}

function isInvalid(id, key) {
  const items = invalid[id];

  if (!items)
    return false;

  for (const item of items) {
    if (key.equals(item))
      return true;
  }

  return false;
}

function isFallback(key) {
  for (const item of fallback) {
    if (key.equals(item))
      return true;
  }

  return false;
}

function isCanonical(x, y, ignore) {
  return compare(x, y, ignore) < 0;
}

function compare(x, y, ignore) {
  assert(x.length === y.length);

  for (let i = x.length - 1; i >= 0; i--) {
    let a = x[i];
    let b = y[i];

    if (ignore && i === x.length - 1) {
      a &= ~0x80;
      b &= ~0x80;
    }

    if (a < b)
      return -1;

    if (a > b)
      return 1;
  }

  return 0;
}

/*
 * Expose
 */

module.exports = EDDSA;
