/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const {Secp256k1} = require('./binding');
const random = require('./random');
const eckey = require('../internal/eckey');
const asn1 = require('../internal/asn1-mini');
const binding = new Secp256k1();

/*
 * Constants
 */

const CURVE_OID = Buffer.from('2b8104000a', 'hex');

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

function privateKeyGenerate() {
  const key = Buffer.allocUnsafe(32);

  do {
    random.randomFill(key, 0, 32);
  } while (!binding.privateKeyVerify(key));

  return key;
}

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

function privateKeyVerify(key) {
  return binding.privateKeyVerify(key);
}

/**
 * Export a private key to SEC1 ASN.1 format.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function privateKeyExport(key, compress) {
  const pub = publicKeyCreate(key, compress);

  return asn1.encodeSEC1({
    version: 1,
    key,
    oid: CURVE_OID,
    pub
  });
}

/**
 * Import a private key from SEC1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

function privateKeyImport(raw) {
  const pki = asn1.decodeSEC1(raw);

  assert(pki.version === 1);
  assert(!pki.oid || pki.oid.equals(CURVE_OID));

  if (pki.key.length > 32)
    throw new Error('Invalid private key.');

  const key = truncate(pki.key);

  if (!privateKeyVerify(key))
    throw new Error('Invalid private key.');

  return key;
}

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key, compress) {
  const pub = publicKeyCreate(key, compress);

  return asn1.encodePKCS8({
    version: 0,
    algorithm: {
      oid: asn1.ECDSA_OID,
      type: asn1.OID,
      params: CURVE_OID
    },
    key: asn1.encodeSEC1({
      version: 1,
      key,
      oid: null,
      pub
    })
  });
}

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

function privateKeyImportPKCS8(raw) {
  const pki = asn1.decodePKCS8(raw);

  assert(pki.version === 0);
  assert(pki.algorithm.oid.equals(asn1.ECDSA_OID));

  if (pki.algorithm.type === asn1.OID)
    assert(pki.algorithm.params.equals(CURVE_OID));
  else
    assert(pki.algorithm.type === asn1.NULL);

  return privateKeyImport(pki.key);
}

/**
 * Export a private key to JWK JSON format.
 * @param {Buffer} key
 * @returns {Object}
 */

function privateKeyExportJWK(key) {
  return eckey.privateKeyExportJWK(exports, key);
}

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {Buffer}
 */

function privateKeyImportJWK(json) {
  return eckey.privateKeyImportJWK(exports, json);
}

/**
 * Compute ((tweak + key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

function privateKeyTweakAdd(key, tweak) {
  return binding.privateKeyTweakAdd(key, tweak);
}

/**
 * Compute ((tweak * key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

function privateKeyTweakMul(key, tweak) {
  return binding.privateKeyTweakMul(key, tweak);
}

/**
 * Compute (key mod n).
 * @param {Buffer} key
 * @returns {Buffer} key
 */

function privateKeyReduce(key) {
  return binding.privateKeyReduce(key);
}

/**
 * Compute (-key mod n).
 * @param {Buffer} key
 * @returns {Buffer} key
 */

function privateKeyNegate(key) {
  return binding.privateKeyNegate(key);
}

/**
 * Compute (key^-1 mod n).
 * @param {Buffer} key
 * @returns {Buffer} key
 */

function privateKeyInvert(key) {
  return binding.privateKeyInvert(key);
}

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyCreate(key, compress) {
  return binding.publicKeyCreate(key, compress);
}

/**
 * Compress or decompress public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyConvert(key, compress) {
  return binding.publicKeyConvert(key, compress);
}

/**
 * Run uniform bytes through Shallue-van de Woestijne.
 * @param {Buffer} bytes
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyFromUniform(bytes, compress) {
  return binding.publicKeyFromUniform(bytes, compress);
}

/**
 * Run public key through Shallue-van de Woestijne inverse.
 * @param {Buffer} key
 * @param {Number?} hint
 * @returns {Buffer}
 */

function publicKeyToUniform(key, hint = random.randomInt()) {
  return binding.publicKeyToUniform(key, hint);
}

/**
 * Create public key from a 64 byte hash.
 * @param {Buffer} bytes
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyFromHash(bytes, compress) {
  return binding.publicKeyFromHash(bytes, compress);
}

/**
 * Create a 64 byte hash from a public key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyToHash(key) {
  return binding.publicKeyToHash(key);
}

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
}

/**
 * Export a public key to X/Y format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  return publicKeyConvert(key, false).slice(1);
}

/**
 * Import a public key from X/Y format.
 * @param {Buffer} raw
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyImport(raw, compress) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 64);

  const key = Buffer.allocUnsafe(1 + raw.length);
  key[0] = 0x04;
  raw.copy(key, 1);

  return publicKeyConvert(key, compress);
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN1 format.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key, compress) {
  return asn1.encodeSPKI({
    algorithm: {
      oid: asn1.ECDSA_OID,
      type: asn1.OID,
      params: CURVE_OID
    },
    key: publicKeyConvert(key, compress)
  });
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN1 format.
 * @param {Buffer} raw
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyImportSPKI(raw, compress) {
  const spki = asn1.decodeSPKI(raw);

  assert(spki.algorithm.oid.equals(asn1.ECDSA_OID));

  if (spki.algorithm.type === asn1.OID)
    assert(spki.algorithm.params.equals(CURVE_OID));
  else
    assert(spki.algorithm.type === asn1.NULL);

  return publicKeyConvert(spki.key, compress);
}

/**
 * Export a public key to JWK JSON format.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExportJWK(key) {
  return eckey.publicKeyExportJWK(exports, key);
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyImportJWK(json, compress) {
  return eckey.publicKeyImportJWK(exports, json, compress);
}

/**
 * Compute ((g * tweak) + key).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer} key
 */

function publicKeyTweakAdd(key, tweak, compress) {
  return binding.publicKeyTweakAdd(key, tweak, compress);
}

/**
 * Compute (key * tweak).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer} key
 */

function publicKeyTweakMul(key, tweak, compress) {
  return binding.publicKeyTweakMul(key, tweak, compress);
}

/**
 * Add two public keys.
 * @param {Buffer} key1
 * @param {Buffer} key2
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyAdd(key1, key2, compress) {
  return binding.publicKeyAdd(key1, key2, compress);
}

/**
 * Combine public keys.
 * @param {Buffer[]} keys
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyCombine(keys, compress) {
  return binding.publicKeyCombine(keys, compress);
}

/**
 * Negate public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyNegate(key, compress) {
  return binding.publicKeyNegate(key, compress);
}

/**
 * Normalize R/S signature (ensure low S value).
 * @param {Buffer} sig
 * @returns {Buffer}
 */

function signatureNormalize(sig) {
  return binding.signatureNormalize(sig);
}

/**
 * Normalize DER signature (ensure low S value).
 * @param {Buffer} sig
 * @returns {Buffer}
 */

function signatureNormalizeDER(sig) {
  return binding.signatureNormalizeDER(sig);
}

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

function signatureExport(sig) {
  return binding.signatureExport(sig);
}

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

function signatureImport(sig) {
  return binding.signatureImport(sig);
}

/**
 * Test whether a signature has a low S value (R/S).
 * @param {Buffer} sig
 * @returns {Boolean}
 */

function isLowS(raw) {
  return binding.isLowS(raw);
}

/**
 * Test whether a signature has a low S value (DER).
 * @param {Buffer} sig
 * @returns {Boolean}
 */

function isLowDER(raw) {
  return binding.isLowDER(raw);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function sign(msg, key) {
  return binding.sign(truncate(msg), key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Object} R/S-formatted signature and recovery ID.
 */

function signRecoverable(msg, key) {
  return binding.signRecoverable(truncate(msg), key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

function signDER(msg, key) {
  return binding.signDER(truncate(msg), key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Object} DER-formatted signature and recovery ID.
 */

function signRecoverableDER(msg, key) {
  return binding.signRecoverableDER(truncate(msg), key);
}

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  try {
    return binding.verify(truncate(msg), sig, key);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return false;
  }
}

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  try {
    return binding.verifyDER(truncate(msg), sig, key);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return false;
  }
}

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} param
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

function recover(msg, sig, param, compress) {
  try {
    return binding.recover(truncate(msg), sig, param, compress);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return null;
  }
}

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} param
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

function recoverDER(msg, sig, param, compress) {
  try {
    return binding.recoverDER(truncate(msg), sig, param, compress);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return null;
  }
}

/**
 * Perform an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function derive(pub, priv, compress) {
  return binding.derive(pub, priv, compress);
}

/**
 * Sign a message (schnorr).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function schnorrSign(msg, key) {
  return binding.schnorrSign(msg, key);
}

/**
 * Verify a schnorr signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function schnorrVerify(msg, sig, key) {
  try {
    return binding.schnorrVerify(msg, sig, key);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return false;
  }
}

/**
 * Batch verify schnorr signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

function schnorrVerifyBatch(batch) {
  try {
    return binding.schnorrVerifyBatch(batch);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return false;
  }
}

/*
 * Helpers
 */

function truncate(msg) {
  if (!Buffer.isBuffer(msg))
    throw new TypeError('message should be a Buffer');

  if (msg.length < 32) {
    const out = Buffer.allocUnsafe(32);
    const pos = 32 - msg.length;

    out.fill(0x00, 0, pos);
    msg.copy(out, pos);

    return out;
  }

  if (msg.length > 32)
    return msg.slice(0, 32);

  return msg;
}

/*
 * Expose
 */

exports.id = 'SECP256K1';
exports.type = 'ecdsa';
exports.size = 32;
exports.bits = 256;
exports.native = 2;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyExport = privateKeyExport;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExportPKCS8 = privateKeyExportPKCS8;
exports.privateKeyImportPKCS8 = privateKeyImportPKCS8;
exports.privateKeyExportJWK = privateKeyExportJWK;
exports.privateKeyImportJWK = privateKeyImportJWK;
exports.privateKeyTweakAdd = privateKeyTweakAdd;
exports.privateKeyTweakMul = privateKeyTweakMul;
exports.privateKeyReduce = privateKeyReduce;
exports.privateKeyNegate = privateKeyNegate;
exports.privateKeyInvert = privateKeyInvert;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyConvert = publicKeyConvert;
exports.publicKeyFromUniform = publicKeyFromUniform;
exports.publicKeyToUniform = publicKeyToUniform;
exports.publicKeyFromHash = publicKeyFromHash;
exports.publicKeyToHash = publicKeyToHash;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyExport = publicKeyExport;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExportSPKI = publicKeyExportSPKI;
exports.publicKeyImportSPKI = publicKeyImportSPKI;
exports.publicKeyExportJWK = publicKeyExportJWK;
exports.publicKeyImportJWK = publicKeyImportJWK;
exports.publicKeyTweakAdd = publicKeyTweakAdd;
exports.publicKeyTweakMul = publicKeyTweakMul;
exports.publicKeyAdd = publicKeyAdd;
exports.publicKeyCombine = publicKeyCombine;
exports.publicKeyNegate = publicKeyNegate;
exports.signatureNormalize = signatureNormalize;
exports.signatureNormalizeDER = signatureNormalizeDER;
exports.signatureExport = signatureExport;
exports.signatureImport = signatureImport;
exports.isLowS = isLowS;
exports.isLowDER = isLowDER;
exports.sign = sign;
exports.signRecoverable = signRecoverable;
exports.signDER = signDER;
exports.signRecoverableDER = signRecoverableDER;
exports.verify = verify;
exports.verifyDER = verifyDER;
exports.recover = recover;
exports.recoverDER = recoverDER;
exports.derive = derive;
exports.schnorrSign = schnorrSign;
exports.schnorrVerify = schnorrVerify;
exports.schnorrVerifyBatch = schnorrVerifyBatch;
