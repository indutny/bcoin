/*!
 * dhkey.js - DH keys for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Diffie_hellman
 *   https://www.teletrust.de/fileadmin/files/oid/oid_pkcs-3v1-4.pdf
 */

'use strict';

const assert = require('bsert');
const base64 = require('../encoding/base64');
const {countLeft, trimLeft} = require('../encoding/util');
const {custom} = require('./custom');

/*
 * Constants
 */

const DEFAULT_BITS = 2048;
const DEFAULT_GEN = 2;
const MIN_BITS = 512;
const MAX_BITS = 10000;
const MIN_GEN = 2;
const MAX_GEN = 2 ** 31 - 1;

/**
 * DH Params
 */

class DHParams {
  constructor(p, g) {
    this.p = trimLeft(p);
    this.g = trimLeft(g);
  }

  setP(p) {
    this.p = trimLeft(p);
    return this;
  }

  setG(g) {
    this.g = trimLeft(g);
    return this;
  }

  bits() {
    return countLeft(this.p);
  }

  size() {
    return (this.bits() + 7) >>> 3;
  }

  toParams() {
    return this;
  }

  toJSON() {
    return {
      kty: 'DH',
      p: base64.encodeURL(this.p),
      g: base64.encodeURL(this.g),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'DH');

    this.p = base64.decodeURL(json.p);
    this.g = base64.decodeURL(json.g);

    return this;
  }

  [custom]() {
    return this.format();
  }

  format() {
    return {
      bits: this.bits(),
      size: this.size(),
      pbits: countLeft(this.p),
      gbits: countLeft(this.g),
      p: this.p.toString('hex'),
      g: this.g.toString('hex')
    };
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * DH Key
 */

class DHKey extends DHParams {
  constructor(p, g, y) {
    super(p, g);
    this.y = trimLeft(y);
  }

  setParams(params) {
    return this.fromParams(params);
  }

  setY(y) {
    this.y = trimLeft(y);
    return this;
  }

  toParams() {
    return new DHParams(this.p, this.g);
  }

  fromParams(params) {
    assert(params instanceof DHParams);
    this.p = params.p;
    this.g = params.g;
    return this;
  }

  toPublic() {
    return this;
  }

  toJSON() {
    return {
      kty: 'DH',
      p: base64.encodeURL(this.p),
      g: base64.encodeURL(this.g),
      y: base64.encodeURL(this.y),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'DH');

    this.p = base64.decodeURL(json.p);
    this.g = base64.decodeURL(json.g);
    this.y = base64.decodeURL(json.y);

    return this;
  }

  static fromParams(params) {
    return new this().fromParams(params);
  }
}

/**
 * DH Public Key
 */

class DHPublicKey extends DHKey {
  constructor(p, g, y) {
    super(p, g, y);
  }

  format() {
    return {
      bits: this.bits(),
      size: this.size(),
      pbits: countLeft(this.p),
      gbits: countLeft(this.g),
      ybits: countLeft(this.y),
      p: this.p.toString('hex'),
      g: this.g.toString('hex'),
      y: this.y.toString('hex')
    };
  }
}

/**
 * DH Public Key
 */

class DHPrivateKey extends DHKey {
  constructor(p, g, y, x) {
    super(p, g, y);
    this.x = trimLeft(x);
  }

  setX(x) {
    this.x = trimLeft(x);
    return this;
  }

  toPublic() {
    const key = new DHPublicKey();
    key.p = this.p;
    key.g = this.g;
    key.y = this.y;
    return key;
  }

  toJSON() {
    return {
      kty: 'DH',
      p: base64.encodeURL(this.p),
      g: base64.encodeURL(this.g),
      y: base64.encodeURL(this.y),
      x: base64.encodeURL(this.x),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'DH');

    this.p = base64.decodeURL(json.p);
    this.g = base64.decodeURL(json.g);

    if (json.y != null)
      this.y = base64.decodeURL(json.y);

    this.x = base64.decodeURL(json.x);

    return this;
  }

  format() {
    return {
      bits: this.bits(),
      size: this.size(),
      pbits: countLeft(this.p),
      gbits: countLeft(this.g),
      ybits: countLeft(this.y),
      xbits: countLeft(this.x),
      p: this.p.toString('hex'),
      g: this.g.toString('hex'),
      y: this.y.toString('hex'),
      x: this.x.toString('hex')
    };
  }
}

/*
 * Expose
 */

exports.DEFAULT_BITS = DEFAULT_BITS;
exports.DEFAULT_GEN = DEFAULT_GEN;
exports.MIN_BITS = MIN_BITS;
exports.MAX_BITS = MAX_BITS;
exports.MIN_GEN = MIN_GEN;
exports.MAX_GEN = MAX_GEN;

exports.DHKey = DHKey;
exports.DHParams = DHParams;
exports.DHPublicKey = DHPublicKey;
exports.DHPrivateKey = DHPrivateKey;
