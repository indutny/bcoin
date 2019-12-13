/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const rsakey = require('../internal/rsakey');
const pkcs1 = require('../encoding/pkcs1');
const rsa = require('../js/rsa');
const {constants} = crypto;

const {
  DEFAULT_BITS,
  DEFAULT_EXP,
  MIN_BITS,
  MAX_BITS,
  MIN_EXP,
  MAX_EXP,
  RSAKey,
  RSAPublicKey,
  RSAPrivateKey
} = rsakey;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

function privateKeyGenerate(bits, exponent) {
  if (!crypto.generateKeyPairSync || (exponent && exponent > 0xffffffff))
    return rsa.privateKeyGenerate(bits, exponent);

  const options = createOptions(bits, exponent);
  const {privateKey} = crypto.generateKeyPairSync('rsa', options);

  return rsa.privateKeyImport(privateKey);
}

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

async function privateKeyGenerateAsync(bits, exponent) {
  if (!crypto.generateKeyPair || (exponent && exponent > 0xffffffff))
    return rsa.privateKeyGenerateAsync(bits, exponent);

  const options = createOptions(bits, exponent);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      let key;
      try {
        key = rsa.privateKeyImport(privateKey);
      } catch (e) {
        reject(e);
        return;
      }

      resolve(key);
    };

    try {
      crypto.generateKeyPair('rsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Sign a message (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

function sign(hash, msg, key) {
  return rsa.sign(hash, msg, key, decryptRaw);
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
  return rsa.verify(hash, msg, sig, key, encryptRaw);
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
  return rsa.verifyLax(hash, msg, sig, key, encryptRaw);
}

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encrypt(msg, key) {
  return rsa.encrypt(msg, key, encryptRaw);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decrypt(msg, key) {
  return rsa.decrypt(msg, key, decryptRaw);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptLax(msg, key) {
  return rsa.decryptLax(msg, key, decryptRaw);
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
  return rsa.encryptOAEP(hash, msg, key, label, encryptRaw);
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
  return rsa.decryptOAEP(hash, msg, key, label, decryptRaw);
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
  return rsa.decryptOAEPLax(hash, msg, key, label, decryptRaw);
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
  return rsa.signPSS(hash, msg, key, saltLen, decryptRaw);
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
  return rsa.verifyPSS(hash, msg, sig, key, saltLen, encryptRaw);
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
  return rsa.verifyPSSLax(hash, msg, sig, key, saltLen, encryptRaw);
}

/**
 * Raw encryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encryptRaw(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAKey);

  const pub = new pkcs1.RSAPublicKey(key.n, key.e);

  return crypto.publicEncrypt({
    key: pub.toPEM(),
    padding: constants.RSA_NO_PADDING
  }, msg);
}

/**
 * Raw decryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptRaw(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);

  const priv = new pkcs1.RSAPrivateKey(
    0,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );

  return crypto.privateDecrypt({
    key: priv.toPEM(),
    padding: constants.RSA_NO_PADDING
  }, msg);
}

/*
 * Helpers
 */

function createOptions(bits, exponent) {
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

  return {
    modulusLength: bits,
    publicExponent: exponent,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'der'
    }
  };
}

/*
 * Expose
 */

exports.native = 1;
exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
exports.SALT_LENGTH_AUTO = rsa.SALT_LENGTH_AUTO;
exports.SALT_LENGTH_HASH = rsa.SALT_LENGTH_HASH;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyCompute = rsa.privateKeyCompute;
exports.privateKeyVerify = rsa.privateKeyVerify;
exports.privateKeyExport = rsa.privateKeyExport;
exports.privateKeyImport = rsa.privateKeyImport;
exports.privateKeyExportPKCS8 = rsa.privateKeyExportPKCS8;
exports.privateKeyImportPKCS8 = rsa.privateKeyImportPKCS8;
exports.privateKeyExportJWK = rsa.privateKeyExportJWK;
exports.privateKeyImportJWK = rsa.privateKeyImportJWK;
exports.publicKeyCreate = rsa.publicKeyCreate;
exports.publicKeyVerify = rsa.publicKeyVerify;
exports.publicKeyExport = rsa.publicKeyExport;
exports.publicKeyImport = rsa.publicKeyImport;
exports.publicKeyExportSPKI = rsa.publicKeyExportSPKI;
exports.publicKeyImportSPKI = rsa.publicKeyImportSPKI;
exports.publicKeyExportJWK = rsa.publicKeyExportJWK;
exports.publicKeyImportJWK = rsa.publicKeyImportJWK;
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
exports.veil = rsa.veil;
exports.veilLax = rsa.veilLax;
exports.unveil = rsa.unveil;
exports.unveilLax = rsa.unveilLax;
