/*!
 * ecdh.js - ECDH for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://cr.yp.to/ecdh.html
 *   https://cr.yp.to/ecdh/curve25519-20060209.pdf
 *   https://tools.ietf.org/html/rfc7748
 */

'use strict';

const assert = require('bsert');
const elliptic = require('./elliptic');
const eckey = require('../internal/eckey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const rng = require('../random');

/**
 * ECDH
 */

class ECDH {
  constructor(id, eid, pre) {
    assert(typeof id === 'string');
    assert(!eid || typeof eid === 'string');

    this.id = id;
    this.type = 'ecdh';
    this.eid = eid || null;
    this._pre = pre || null;
    this._curve = null;
    this._edwards = null;
    this.native = 0;
  }

  get curve() {
    if (!this._curve)
      this._curve = elliptic.curve(this.id);
    return this._curve;
  }

  get edwards() {
    if (this.eid && !this._edwards) {
      this._edwards = elliptic.curve(this.eid, this._pre);
      this._edwards.precompute(rng);
      this._pre = null;
    }
    return this._edwards;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  privateKeyGenerate() {
    const key = rng.randomBytes(this.curve.scalarSize);
    return this.curve.clamp(key);
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));
    return key.length === this.curve.scalarSize;
  }

  privateKeyExport(key) {
    if (!this.privateKeyVerify(key))
      throw new Error('Invalid private key.');

    return new asn1.OctString(key).encode();
  }

  privateKeyImport(raw) {
    const key = asn1.OctString.decode(raw);

    if (!this.privateKeyVerify(key.value))
      throw new Error('Invalid private key.');

    return key.value;
  }

  privateKeyExportPKCS8(key) {
    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.privateKeyExport(key)
    ).encode();
  }

  privateKeyImportPKCS8(raw) {
    const pki = pkcs8.PrivateKeyInfo.decode(raw);
    const version = pki.version.toNumber();
    const {algorithm, parameters} = pki.algorithm;

    assert(version === 0 || version === 1);
    assert(algorithm.toString() === asn1.objects.curves[this.id]);
    assert(parameters.node.type === asn1.types.NULL);

    return this.privateKeyImport(pki.privateKey.value);
  }

  privateKeyExportJWK(key) {
    return eckey.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  publicKeyCreate(key) {
    const a = this.curve.decodeScalar(key);
    const k = this.curve.reduce(a);

    if (this.edwards && this.edwards.g.pre) {
      const A = this.edwards.g.mulBlind(k);
      const P = this.curve.pointFromEdwards(A);

      return P.encode();
    }

    const G = this.curve.g.toX();
    const A = G.mulBlind(k, rng);

    return A.encode();
  }

  publicKeyConvert(key, sign) {
    assert(typeof sign === 'boolean');

    if (!this.edwards)
      throw new Error('No equivalent edwards curve.');

    const A = this.curve.decodePoint(key);
    const P = this.edwards.pointFromMont(A);

    if (P.sign() !== sign)
      return P.neg().encode();

    return P.encode();
  }

  publicKeyFromUniform(bytes) {
    const u = this.curve.decodeUniform(bytes);
    const A = this.curve.pointFromUniform(u);

    return A.encode();
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    const A = this.curve.decodePoint(key);
    const u = this.curve.pointToUniform(A, hint);

    return this.curve.encodeUniform(u, rng);
  }

  publicKeyFromHash(bytes, pake = false) {
    const A = this.curve.pointFromHash(bytes, pake);

    return A.encode();
  }

  publicKeyToHash(key) {
    const A = this.curve.decodePoint(key);
    return this.curve.pointToHash(A, rng);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodeX(key);
    } catch (e) {
      return false;
    }

    return A.validate();
  }

  publicKeyIsSmall(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodeX(key);
    } catch (e) {
      return false;
    }

    if (!A.validate())
      return false;

    return A.isSmall();
  }

  publicKeyHasTorsion(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodeX(key);
    } catch (e) {
      return false;
    }

    if (!A.validate())
      return false;

    return A.hasTorsion();
  }

  publicKeyExport(key) {
    if (!this.publicKeyVerify(key))
      throw new Error('Invalid public key.');

    return Buffer.from(key);
  }

  publicKeyImport(raw) {
    if (!this.publicKeyVerify(raw))
      throw new Error('Invalid public key.');

    return Buffer.from(raw);
  }

  publicKeyExportSPKI(key) {
    return new x509.SubjectPublicKeyInfo(
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.publicKeyExport(key)
    ).encode();
  }

  publicKeyImportSPKI(raw) {
    const spki = x509.SubjectPublicKeyInfo.decode(raw);
    const {algorithm, parameters} = spki.algorithm;

    assert(algorithm.toString() === asn1.objects.curves[this.id]);
    assert(parameters.node.type === asn1.types.NULL);

    return this.publicKeyImport(spki.publicKey.rightAlign());
  }

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json) {
    return eckey.publicKeyImportJWK(this, json, false);
  }

  derive(pub, priv) {
    const A = this.curve.decodeX(pub);
    const a = this.curve.decodeScalar(priv);
    const k = this.curve.reduce(a);
    const P = A.mulConst(k, rng);

    return P.encode();
  }
}

/*
 * Expose
 */

module.exports = ECDH;
