/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').dsa;

if (!binding)
  throw new Error('DSA native support not available.');

const dsakey = require('../internal/dsakey');

const {
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
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  const items = binding.paramsGenerate(bits);
  const params = new DSAParams();

  [
    params.p,
    params.q,
    params.g
  ] = items;

  return params;
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

async function paramsGenerateAsync(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  return new Promise((resolve, reject) => {
    const cb = (err, items) => {
      if (err) {
        reject(err);
        return;
      }

      const params = new DSAParams();

      [
        params.p,
        params.q,
        params.g
      ] = items;

      resolve(params);
    };

    try {
      binding.paramsGenerateAsync(bits, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Verify params.
 * @param {DSAParams} params
 * @returns {Boolean}
 */

function paramsVerify(params) {
  assert(params instanceof DSAParams);

  return binding.paramsVerify(
    params.p,
    params.q,
    params.g
  );
}

/**
 * Export params in OpenSSL ASN.1 format.
 * @param {DSAParams} params
 * @returns {Buffer}
 */

function paramsExport(params) {
  assert(params instanceof DSAParams);
  return binding.paramsExport(params.p, params.q, params.g);
}

/**
 * Import params in OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAParams}
 */

function paramsImport(raw) {
  const items = binding.paramsImport(raw);
  const params = new DSAParams();

  [
    params.p,
    params.q,
    params.g
  ] = items;

  return params;
}

/**
 * Export a public key to JWK JSON format.
 * @param {DSAParams} key
 * @returns {Object}
 */

function paramsExportJWK(key) {
  assert(key instanceof DSAParams);
  return key.toParams().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPublicKey}
 */

function paramsImportJWK(json) {
  return DSAParams.fromJSON(json);
}

/**
 * Generate private key from params.
 * @param {DSAParams} params
 * @returns {DSAPrivateKey}
 */

function privateKeyCreate(params) {
  assert(params instanceof DSAParams);

  const items = binding.privateKeyCreate(
    params.p,
    params.q,
    params.g
  );

  const key = new DSAPrivateKey();

  [
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ] = items;

  return key;
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

function privateKeyGenerate(bits) {
  const params = paramsGenerate(bits);
  return privateKeyCreate(params);
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

async function privateKeyGenerateAsync(bits) {
  const params = await paramsGenerateAsync(bits);
  return privateKeyCreate(params);
}

/**
 * Pre-compute a private key.
 * @param {DSAPrivateKey}
 * @returns {DSAPrivateKey}
 */

function privateKeyCompute(key) {
  assert(key instanceof DSAPrivateKey);

  const y = binding.privateKeyCompute(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );

  if (y)
    key.y = y;

  return key;
}

/**
 * Verify a private key.
 * @param {DSAPrivateKey} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(key instanceof DSAPrivateKey);

  return binding.privateKeyVerify(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
}

/**
 * Export a private key in OpenSSL ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  assert(key instanceof DSAPrivateKey);

  return binding.privateKeyExport(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
}

/**
 * Import a private key in OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPrivateKey}
 */

function privateKeyImport(raw) {
  const items = binding.privateKeyImport(raw);
  const key = new DSAPrivateKey();

  [
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ] = items;

  return key;
}

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  assert(key instanceof DSAPrivateKey);

  return binding.privateKeyExportPKCS8(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
}

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPrivateKey}
 */

function privateKeyImportPKCS8(raw) {
  const items = binding.privateKeyImportPKCS8(raw);
  const key = new DSAPrivateKey();

  [
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ] = items;

  return key;
}

/**
 * Export a private key to JWK JSON format.
 * @param {DSAPrivateKey} key
 * @returns {Object}
 */

function privateKeyExportJWK(key) {
  assert(key instanceof DSAPrivateKey);
  return key.toJSON();
}

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPrivateKey}
 */

function privateKeyImportJWK(json) {
  const key = DSAPrivateKey.fromJSON(json);

  privateKeyCompute(key);

  return key;
}

/**
 * Create a public key from a private key.
 * @param {DSAPrivateKey} key
 * @returns {DSAPublicKey}
 */

function publicKeyCreate(key) {
  assert(key instanceof DSAPrivateKey);

  const pub = new DSAPublicKey();

  pub.p = key.p;
  pub.q = key.q;
  pub.g = key.g;
  pub.y = key.y;

  return pub;
}

/**
 * Verify a public key.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  assert(key instanceof DSAKey);

  return binding.publicKeyVerify(
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  assert(key instanceof DSAKey);

  return binding.publicKeyExport(
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

function publicKeyImport(raw) {
  const items = binding.publicKeyImport(raw);
  const key = new DSAPublicKey();

  [
    key.p,
    key.q,
    key.g,
    key.y
  ] = items;

  return key;
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  assert(key instanceof DSAKey);

  return binding.publicKeyExportSPKI(
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

function publicKeyImportSPKI(raw) {
  const items = binding.publicKeyImportSPKI(raw);
  const key = new DSAPublicKey();

  [
    key.p,
    key.q,
    key.g,
    key.y
  ] = items;

  return key;
}

/**
 * Export a public key to JWK JSON format.
 * @param {DSAKey} key
 * @returns {Object}
 */

function publicKeyExportJWK(key) {
  assert(key instanceof DSAKey);
  return key.toPublic().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPublicKey}
 */

function publicKeyImportJWK(json) {
  return DSAPublicKey.fromJSON(json);
}

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} DER-formatted signature.
 */

function signatureExport(sig, size) {
  return binding.signatureExport(sig, size);
}

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} R/S-formatted signature.
 */

function signatureImport(sig, size) {
  return binding.signatureImport(sig, size);
}

/**
 * Sign a message (R/S).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function sign(msg, key) {
  assert(key instanceof DSAPrivateKey);

  return binding.sign(
    msg,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
}

/**
 * Sign a message (DER).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

function signDER(msg, key) {
  assert(key instanceof DSAPrivateKey);

  return binding.signDER(
    msg,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
}

/**
 * Verify a signature (R/S).
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  assert(key instanceof DSAKey);

  return binding.verify(
    msg,
    sig,
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/**
 * Verify a signature (DER).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  assert(key instanceof DSAKey);

  return binding.verifyDER(
    msg,
    sig,
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/**
 * Perform a diffie-hellman.
 * @param {DSAKey} pub
 * @param {DSAPrivateKey} priv
 * @returns {Buffer}
 */

function derive(pub, priv) {
  assert(pub instanceof DSAKey);
  assert(priv instanceof DSAPrivateKey);

  return binding.derive(
    pub.p,
    pub.q,
    pub.g,
    pub.y,
    priv.p,
    priv.q,
    priv.g,
    priv.y,
    priv.x
  );
}

/**
 * Perform a diffie-hellman.
 * @param {Buffer} pub
 * @param {DSAPrivateKey} priv
 * @returns {Buffer}
 */

function exchange(pub, priv) {
  assert(priv instanceof DSAPrivateKey);
  return derive(new DSAPublicKey(priv.p, priv.q, priv.g, pub), priv);
}

/*
 * Expose
 */

exports.native = 2;
exports.DSAParams = DSAParams;
exports.DSAKey = DSAKey;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAPrivateKey = DSAPrivateKey;
exports.paramsGenerate = paramsGenerate;
exports.paramsGenerateAsync = paramsGenerateAsync;
exports.paramsVerify = paramsVerify;
exports.paramsExport = paramsExport;
exports.paramsImport = paramsImport;
exports.paramsExportJWK = paramsExportJWK;
exports.paramsImportJWK = paramsImportJWK;
exports.privateKeyCreate = privateKeyCreate;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyCompute = privateKeyCompute;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyExport = privateKeyExport;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExportPKCS8 = privateKeyExportPKCS8;
exports.privateKeyImportPKCS8 = privateKeyImportPKCS8;
exports.privateKeyExportJWK = privateKeyExportJWK;
exports.privateKeyImportJWK = privateKeyImportJWK;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyExport = publicKeyExport;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExportSPKI = publicKeyExportSPKI;
exports.publicKeyImportSPKI = publicKeyImportSPKI;
exports.publicKeyExportJWK = publicKeyExportJWK;
exports.publicKeyImportJWK = publicKeyImportJWK;
exports.signatureExport = signatureExport;
exports.signatureImport = signatureImport;
exports.sign = sign;
exports.signDER = signDER;
exports.verify = verify;
exports.verifyDER = verifyDER;
exports.derive = derive;
exports.exchange = exchange;
