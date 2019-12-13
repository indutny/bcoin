/*!
 * ecdsa.js - ecdsa wrapper for openssl
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const Native = require('./binding').ECDSA;

if (!Native)
  throw new Error('ECDSA native support not available.');

const eckey = require('../internal/eckey');
const random = require('./random');

/**
 * ECDSA
 */

class ECDSA extends Native {
  constructor(name) {
    super(name);

    this.id = name;
    this.type = 'ecdsa';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;
  }

  privateKeyExportJWK(key) {
    return eckey.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  publicKeyExport(key) {
    return this.publicKeyConvert(key, false).slice(1);
  }

  publicKeyImport(raw, compress) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size * 2);

    const key = Buffer.allocUnsafe(1 + raw.length);
    key[0] = 0x04;
    raw.copy(key, 1);

    return this.publicKeyConvert(key, compress);
  }

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json, compress) {
    return eckey.publicKeyImportJWK(this, json, compress);
  }

  publicKeyToUniform(key, hint = random.randomInt()) {
    return super.publicKeyToUniform(key, hint);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
