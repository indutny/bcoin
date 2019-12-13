/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const backend = require('./binding');
const binding = backend.rsa;

if (!binding)
  throw new Error('RSA native support not available.');

const rsakey = require('../internal/rsakey');

const {
  RSAKey,
  RSAPrivateKey,
  RSAPublicKey,
  DEFAULT_BITS,
  DEFAULT_EXP,
  MIN_BITS,
  MAX_BITS,
  MIN_EXP,
  MAX_EXP
} = rsakey;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

function privateKeyGenerate(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent & 1) === 0)
    throw new RangeError('"exponent" must be odd.');

  const key = new RSAPrivateKey();
  const items = binding.privateKeyGenerate(bits, exponent);

  [
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ] = items;

  return key;
}

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

async function privateKeyGenerateAsync(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent & 1) === 0)
    throw new RangeError('"exponent" must be odd.');

  return new Promise(function(resolve, reject) {
    const cb = function(err, items) {
      if (err) {
        reject(err);
        return;
      }

      const key = new RSAPrivateKey();

      [
        key.n,
        key.e,
        key.d,
        key.p,
        key.q,
        key.dp,
        key.dq,
        key.qi
      ] = items;

      resolve(key);
    };

    try {
      binding.privateKeyGenerateAsync(bits, exponent, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Pre-compute a private key.
 * @param {RSAPrivateKey}
 * @returns {RSAPrivateKey}
 */

function privateKeyCompute(key) {
  assert(key instanceof RSAPrivateKey);

  const items = binding.privateKeyCompute(
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );

  if (!items)
    return key;

  [
    key.n,
    key.e,
    key.d,
    key.dp,
    key.dq,
    key.qi
  ] = items;

  return key;
}

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(key instanceof RSAPrivateKey);

  return binding.privateKeyVerify(
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
}

/**
 * Export a private key to PKCS1 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  assert(key instanceof RSAPrivateKey);

  return binding.privateKeyExport(
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
}

/**
 * Import a private key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

function privateKeyImport(raw) {
  const items = binding.privateKeyImport(raw);
  const key = new RSAPrivateKey();

  [
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ] = items;

  return key;
}

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  assert(key instanceof RSAPrivateKey);

  return binding.privateKeyExportPKCS8(
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
}

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

function privateKeyImportPKCS8(raw) {
  const items = binding.privateKeyImportPKCS8(raw);
  const key = new RSAPrivateKey();

  [
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ] = items;

  return key;
}

/**
 * Export a private key to JWK JSON format.
 * @param {RSAPrivateKey} key
 * @returns {Object}
 */

function privateKeyExportJWK(key) {
  assert(key instanceof RSAPrivateKey);
  return key.toJSON();
}

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {RSAPrivateKey}
 */

function privateKeyImportJWK(json) {
  const key = RSAPrivateKey.fromJSON(json);

  privateKeyCompute(key);

  return key;
}

/**
 * Create a public key from a private key.
 * @param {RSAPrivateKey} key
 * @returns {RSAPublicKey}
 */

function publicKeyCreate(key) {
  assert(key instanceof RSAPrivateKey);

  const pub = new RSAPublicKey();

  pub.n = key.n;
  pub.e = key.e;

  return pub;
}

/**
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  assert(key instanceof RSAKey);
  return binding.publicKeyVerify(key.n, key.e);
}

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  assert(key instanceof RSAKey);
  return binding.publicKeyExport(key.n, key.e);
}

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

function publicKeyImport(raw) {
  const items = binding.publicKeyImport(raw);
  const key = new RSAPublicKey();

  [
    key.n,
    key.e
  ] = items;

  return key;
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  assert(key instanceof RSAKey);
  return binding.publicKeyExportSPKI(key.n, key.e);
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

function publicKeyImportSPKI(raw) {
  const items = binding.publicKeyImportSPKI(raw);
  const key = new RSAPublicKey();

  [
    key.n,
    key.e
  ] = items;

  return key;
}

/**
 * Export a public key to JWK JSON format.
 * @param {RSAKey} key
 * @returns {Object}
 */

function publicKeyExportJWK(key) {
  assert(key instanceof RSAKey);
  return key.toPublic().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {RSAPublicKey}
 */

function publicKeyImportJWK(json) {
  return RSAPublicKey.fromJSON(json);
}

/**
 * Sign a message (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

function sign(hash, msg, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(key instanceof RSAPrivateKey);

  backend.load();

  if (hash == null || !binding.hasHash(hash))
    return fallback().sign(hash, msg, key, decryptRaw);

  return binding.sign(
    hash,
    msg,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function verify(hash, msg, sig, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(key instanceof RSAKey);

  backend.load();

  if (hash == null || !binding.hasHash(hash))
    return fallback().verify(hash, msg, sig, key, encryptRaw);

  return binding.verify(
    hash,
    msg,
    sig,
    key.n,
    key.e
  );
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function verifyLax(hash, msg, sig, key) {
  assert(key instanceof RSAKey);
  return verify(hash, msg, key.pad(sig), key);
}

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encrypt(msg, key) {
  assert(key instanceof RSAKey);
  return binding.encrypt(msg, key.n, key.e);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decrypt(msg, key) {
  assert(key instanceof RSAPrivateKey);

  return binding.decrypt(
    msg,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptLax(msg, key) {
  assert(key instanceof RSAKey);
  return decrypt(key.pad(msg), key);
}

/**
 * Encrypt a message with public key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function encryptOAEP(hash, msg, key, label) {
  assert(hash && typeof hash.id === 'string');
  assert(key instanceof RSAKey);

  backend.load();

  if (!binding.hasHash(hash.id))
    return fallback().encryptOAEP(hash, msg, key, label, encryptRaw);

  return binding.encryptOAEP(hash.id, msg, key.n, key.e, label);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEP(hash, msg, key, label) {
  assert(hash && typeof hash.id === 'string');
  assert(key instanceof RSAPrivateKey);

  backend.load();

  if (!binding.hasHash(hash.id))
    return fallback().decryptOAEP(hash, msg, key, label, decryptRaw);

  return binding.decryptOAEP(
    hash.id,
    msg,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi,
    label
  );
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEPLax(hash, msg, key, label) {
  assert(key instanceof RSAKey);
  return decryptOAEP(hash, key.pad(msg), key, label);
}

/**
 * Sign a message (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Buffer} PSS-formatted signature.
 */

function signPSS(hash, msg, key, saltLen) {
  assert(hash && typeof hash.id === 'string');
  assert(key instanceof RSAPrivateKey);

  backend.load();

  if (!binding.hasHash(hash.id))
    return fallback().signPSS(hash, msg, key, saltLen, decryptRaw);

  return binding.signPSS(
    hash.id,
    msg,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi,
    saltLen
  );
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {RSAKey} key
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Boolean}
 */

function verifyPSS(hash, msg, sig, key, saltLen) {
  assert(hash && typeof hash.id === 'string');
  assert(key instanceof RSAKey);

  backend.load();

  if (!binding.hasHash(hash.id))
    return fallback().verifyPSS(hash, msg, sig, key, saltLen, encryptRaw);

  return binding.verifyPSS(
    hash.id,
    msg,
    sig,
    key.n,
    key.e,
    saltLen
  );
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {RSAKey} key
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Boolean}
 */

function verifyPSSLax(hash, msg, sig, key, saltLen) {
  assert(key instanceof RSAKey);
  return verifyPSS(hash, msg, key.pad(sig), key, saltLen);
}

/**
 * Raw encryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encryptRaw(msg, key) {
  assert(key instanceof RSAKey);
  return binding.encryptRaw(msg, key.n, key.e);
}

/**
 * Raw decryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptRaw(msg, key) {
  assert(key instanceof RSAPrivateKey);

  return binding.decryptRaw(
    msg,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function veil(msg, bits, key) {
  assert(key instanceof RSAKey);
  return binding.veil(msg, bits, key.n, key.e);
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function veilLax(msg, bits, key) {
  assert(key instanceof RSAKey);
  return veil(key.pad(msg), bits, key);
}

/**
 * "Unveil" a veiled RSA ciphertext.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function unveil(msg, bits, key) {
  assert(key instanceof RSAKey);
  return binding.unveil(msg, bits, key.n, key.e);
}

/**
 * "Unveil" a veiled RSA ciphertext.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function unveilLax(msg, bits, key) {
  assert(key instanceof RSAKey);
  return unveil(key.pad(msg), bits, key);
}

/*
 * Helpers
 */

let fb = null;

function fallback() {
  if (!fb)
    fb = require('../js/rsa');

  return fb;
}

/*
 * Expose
 */

exports.native = 2;
exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
exports.SALT_LENGTH_AUTO = 0;
exports.SALT_LENGTH_HASH = -1;
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
exports.sign = sign;
exports.verify = verify;
exports.verifyLax = verifyLax;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.decryptLax = decryptLax;
exports.encryptOAEP = encryptOAEP;
exports.decryptOAEP = decryptOAEP;
exports.decryptOAEPLax = decryptOAEPLax;
exports.signPSS = signPSS;
exports.verifyPSS = verifyPSS;
exports.verifyPSSLax = verifyPSSLax;
exports.encryptRaw = encryptRaw;
exports.decryptRaw = decryptRaw;
exports.veil = veil;
exports.veilLax = veilLax;
exports.unveil = unveil;
exports.unveilLax = unveilLax;
