/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const bio = require('bufio');
const dsakey = require('../internal/dsakey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const dsa = require('../js/dsa');

const {
  DEFAULT_BITS,
  MIN_BITS,
  MAX_BITS,
  DSAKey,
  DSAParams,
  DSAPublicKey,
  DSAPrivateKey
} = dsakey;

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

function paramsGenerate(bits) {
  if (!crypto.generateKeyPairSync)
    return dsa.paramsGenerate(bits);

  const options = createOptions(bits);
  const {publicKey} = crypto.generateKeyPairSync('dsa', options);

  return parseParams(publicKey);
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

async function paramsGenerateAsync(bits) {
  if (!crypto.generateKeyPair)
    return dsa.paramsGenerateAsync(bits);

  const options = createOptions(bits);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      let params;
      try {
        params = parseParams(publicKey);
      } catch (e) {
        reject(e);
        return;
      }

      resolve(params);
    };

    try {
      crypto.generateKeyPair('dsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

function privateKeyGenerate(bits) {
  if (!crypto.generateKeyPairSync)
    return dsa.privateKeyGenerate(bits);

  const options = createOptions(bits);
  const {publicKey, privateKey} = crypto.generateKeyPairSync('dsa', options);

  return parsePrivateKey(publicKey, privateKey);
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

async function privateKeyGenerateAsync(bits) {
  if (!crypto.generateKeyPair)
    return dsa.privateKeyGenerateAsync(bits);

  const options = createOptions(bits);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      let key;
      try {
        key = parsePrivateKey(publicKey, privateKey);
      } catch (e) {
        reject(e);
        return;
      }

      resolve(key);
    };

    try {
      crypto.generateKeyPair('dsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/*
 * Helpers
 */

function createOptions(bits) {
  if (bits == null)
    bits = DEFAULT_BITS;

  assert((bits >>> 0) === bits);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  // OpenSSL behavior.
  const L = bits;
  const N = bits < 2048 ? 160 : 256;

  return {
    modulusLength: L,
    divisorLength: N,
    publicKeyEncoding: {
      type: 'spki',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'der'
    }
  };
}

function parseParams(publicKey) {
  const pub = parsePublicKey(publicKey);
  return pub.toParams();
}

function parsePublicKey(publicKey) {
  const spki = x509.SubjectPublicKeyInfo.decode(publicKey);
  const br = bio.read(spki.algorithm.parameters.node.value);
  const p = asn1.Unsigned.read(br);
  const q = asn1.Unsigned.read(br);
  const g = asn1.Unsigned.read(br);
  const y = asn1.Unsigned.decode(spki.publicKey.rightAlign());
  const key = new DSAPublicKey();

  key.p = p.value;
  key.q = q.value;
  key.g = g.value;
  key.y = y.value;

  return key;
}

function parsePrivateKey(publicKey, privateKey) {
  const pub = parsePublicKey(publicKey);
  const pki = pkcs8.PrivateKeyInfo.decode(privateKey);
  const x = asn1.Unsigned.decode(pki.privateKey.value);

  const key = new DSAPrivateKey();

  key.p = pub.p;
  key.q = pub.q;
  key.g = pub.g;
  key.y = pub.y;
  key.x = x.value;

  return key;
}

/*
 * Expose
 */

exports.native = 1;
exports.DSAParams = DSAParams;
exports.DSAKey = DSAKey;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAPrivateKey = DSAPrivateKey;
exports.paramsGenerate = paramsGenerate;
exports.paramsGenerateAsync = paramsGenerateAsync;
exports.paramsVerify = dsa.paramsVerify;
exports.paramsExport = dsa.paramsExport;
exports.paramsImport = dsa.paramsImport;
exports.paramsExportJWK = dsa.paramsExportJWK;
exports.paramsImportJWK = dsa.paramsImportJWK;
exports.privateKeyCreate = dsa.privateKeyCreate;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyCompute = dsa.privateKeyCompute;
exports.privateKeyVerify = dsa.privateKeyVerify;
exports.privateKeyExport = dsa.privateKeyExport;
exports.privateKeyImport = dsa.privateKeyImport;
exports.privateKeyExportPKCS8 = dsa.privateKeyExportPKCS8;
exports.privateKeyImportPKCS8 = dsa.privateKeyImportPKCS8;
exports.privateKeyExportJWK = dsa.privateKeyExportJWK;
exports.privateKeyImportJWK = dsa.privateKeyImportJWK;
exports.publicKeyCreate = dsa.publicKeyCreate;
exports.publicKeyVerify = dsa.publicKeyVerify;
exports.publicKeyExport = dsa.publicKeyExport;
exports.publicKeyImport = dsa.publicKeyImport;
exports.publicKeyExportSPKI = dsa.publicKeyExportSPKI;
exports.publicKeyImportSPKI = dsa.publicKeyImportSPKI;
exports.publicKeyExportJWK = dsa.publicKeyExportJWK;
exports.publicKeyImportJWK = dsa.publicKeyImportJWK;
exports.signatureExport = dsa.signatureExport;
exports.signatureImport = dsa.signatureImport;
exports.sign = dsa.sign;
exports.signDER = dsa.signDER;
exports.verify = dsa.verify;
exports.verifyDER = dsa.verifyDER;
exports.derive = dsa.derive;
exports.exchange = dsa.exchange;
