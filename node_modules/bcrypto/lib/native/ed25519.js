/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').ed25519;
const random = require('./random');
const asn1 = require('../internal/asn1-mini');
const eckey = require('../internal/eckey');

/*
 * Constants
 */

const CURVE_OID = Buffer.from('2b6570', 'hex');

/**
 * Generate a secret.
 * @returns {Buffer}
 */

function privateKeyGenerate() {
  return random.randomBytes(32);
}

/**
 * Generate a clamped scalar.
 * @returns {Buffer}
 */

function scalarGenerate() {
  const scalar = random.randomBytes(32);

  scalar[0] &= -8;
  scalar[31] &= 0x7f;
  scalar[31] |= 0x40;

  return scalar;
}

/**
 * Expand secret.
 * @param {Buffer} secret
 * @returns {Buffer[]}
 */

function privateKeyExpand(secret) {
  return binding.privateKeyExpand(secret);
}

/**
 * Create a private key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

function privateKeyConvert(secret) {
  return binding.privateKeyConvert(secret);
}

/**
 * Validate a secret.
 * @param {Buffer} secret
 * @returns {Boolean}
 */

function privateKeyVerify(secret) {
  assert(Buffer.isBuffer(secret));
  return secret.length === 32;
}

/**
 * Validate a scalar.
 * @param {Buffer} scalar
 * @returns {Boolean}
 */

function scalarVerify(scalar) {
  assert(Buffer.isBuffer(scalar));
  return scalar.length === 32;
}

/**
 * Test scalar for zero.
 * @param {Buffer} scalar
 * @returns {Boolean}
 */

function scalarIsZero(scalar) {
  return binding.scalarIsZero(scalar);
}

/**
 * Clamp a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

function scalarClamp(scalar) {
  assert(Buffer.isBuffer(scalar));
  assert(scalar.length === 32);

  scalar = Buffer.from(scalar);

  scalar[0] &= -8;
  scalar[31] &= 0x7f;
  scalar[31] |= 0x40;

  return scalar;
}

/**
 * Export a private key to ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

function privateKeyExport(secret) {
  if (!privateKeyVerify(secret))
    throw new Error('Invalid private key.');

  return asn1.encodeOct(secret);
}

/**
 * Import a private key from ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

function privateKeyImport(raw) {
  const secret = asn1.decodeOct(raw);

  if (!privateKeyVerify(secret))
    throw new Error('Invalid private key.');

  return secret;
}

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(secret) {
  return asn1.encodePKCS8({
    version: 0,
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: privateKeyExport(secret)
  });
}

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

function privateKeyImportPKCS8(raw) {
  const pki = asn1.decodePKCS8(raw);

  assert(pki.version === 0 || pki.version === 1);
  assert(pki.algorithm.oid.equals(CURVE_OID));
  assert(pki.algorithm.type === asn1.NULL);

  return privateKeyImport(pki.key);
}

/**
 * Export a private key to JWK JSON format.
 * @param {Buffer} secret
 * @returns {Object}
 */

function privateKeyExportJWK(secret) {
  return eckey.privateKeyExportJWK(exports, secret);
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
 * Add tweak value to scalar.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

function scalarTweakAdd(scalar, tweak) {
  return binding.scalarTweakAdd(scalar, tweak);
}

/**
 * Multiply scalar by tweak value.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

function scalarTweakMul(scalar, tweak) {
  return binding.scalarTweakMul(scalar, tweak);
}

/**
 * Compute (scalar mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

function scalarReduce(scalar) {
  return binding.scalarReduce(scalar);
}

/**
 * Compute (-scalar mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

function scalarNegate(scalar) {
  return binding.scalarNegate(scalar);
}

/**
 * Compute (scalar^-1 mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

function scalarInvert(scalar) {
  return binding.scalarInvert(scalar);
}

/**
 * Create a public key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

function publicKeyCreate(secret) {
  return binding.publicKeyCreate(secret);
}

/**
 * Create a public key from a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

function publicKeyFromScalar(scalar) {
  return binding.publicKeyFromScalar(scalar);
}

/**
 * Convert key to an X25519 key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyConvert(key) {
  return binding.publicKeyConvert(key);
}

/**
 * Run uniform bytes through elligator2.
 * @param {Buffer} bytes
 * @returns {Buffer}
 */

function publicKeyFromUniform(bytes) {
  return binding.publicKeyFromUniform(bytes);
}

/**
 * Convert public key to uniform bytes.
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
 * @param {Boolean} [pake=false]
 * @returns {Buffer}
 */

function publicKeyFromHash(bytes, pake = false) {
  return binding.publicKeyFromHash(bytes, pake);
}

/**
 * Create a 64 byte hash from a point.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyToHash(key) {
  return binding.publicKeyToHash(key);
}

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
}

/**
 * Test public key for infinity.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyIsInfinity(key) {
  return binding.publicKeyIsInfinity(key);
}

/**
 * Test whether key is a point of small order.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyIsSmall(key) {
  return binding.publicKeyIsSmall(key);
}

/**
 * Test whether key has a torsion component.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyHasTorsion(key) {
  return binding.publicKeyHasTorsion(key);
}

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  if (!publicKeyVerify(key))
    throw new Error('Invalid public key.');

  return Buffer.from(key);
}

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

function publicKeyImport(raw) {
  if (!publicKeyVerify(raw))
    throw new Error('Invalid public key.');

  return Buffer.from(raw);
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  return asn1.encodeSPKI({
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: publicKeyExport(key)
  });
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

function publicKeyImportSPKI(raw) {
  const spki = asn1.decodeSPKI(raw);

  assert(spki.algorithm.oid.equals(CURVE_OID));
  assert(spki.algorithm.type === asn1.NULL);
  assert(spki.key.length === 32);

  return publicKeyImport(spki.key);
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
 * @returns {Buffer}
 */

function publicKeyImportJWK(json) {
  return eckey.publicKeyImportJWK(exports, json, false);
}

/**
 * Compute ((tweak + key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

function publicKeyTweakAdd(key, tweak) {
  return binding.publicKeyTweakAdd(key, tweak);
}

/**
 * Compute ((tweak * key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

function publicKeyTweakMul(key, tweak) {
  return binding.publicKeyTweakMul(key, tweak);
}

/**
 * Add two public keys.
 * @param {Buffer} key1
 * @param {Buffer} key2
 * @returns {Buffer}
 */

function publicKeyAdd(key1, key2) {
  return binding.publicKeyAdd(key1, key2);
}

/**
 * Combine public keys.
 * @param {Buffer[]} keys
 * @returns {Buffer}
 */

function publicKeyCombine(keys) {
  return binding.publicKeyCombine(keys);
}

/**
 * Negate public key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyNegate(key) {
  return binding.publicKeyNegate(key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

function sign(msg, secret, ph, ctx) {
  return binding.sign(msg, secret, ph, ctx);
}

/**
 * Sign a message with a scalar and raw prefix.
 * @param {Buffer} msg
 * @param {Buffer} scalar
 * @param {Buffer} prefix
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

function signWithScalar(msg, scalar, prefix, ph, ctx) {
  return binding.signWithScalar(msg, scalar, prefix, ph, ctx);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Buffer} tweak
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

function signTweakAdd(msg, secret, tweak, ph, ctx) {
  return binding.signTweakAdd(msg, secret, tweak, ph, ctx);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Buffer} tweak
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

function signTweakMul(msg, secret, tweak, ph, ctx) {
  return binding.signTweakMul(msg, secret, tweak, ph, ctx);
}

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Boolean}
 */

function verify(msg, sig, key, ph, ctx) {
  return binding.verify(msg, sig, key, ph, ctx);
}

/**
 * Verify a signature (cofactor verification).
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Boolean}
 */

function verifySingle(msg, sig, key, ph, ctx) {
  return binding.verifySingle(msg, sig, key, ph, ctx);
}

/**
 * Batch verify signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

function verifyBatch(batch, ph, ctx) {
  return binding.verifyBatch(batch, ph, ctx);
}

/**
 * Perform an ECDH.
 * @param {Buffer} pub
 * @param {Buffer} secret
 * @returns {Buffer}
 */

function derive(pub, secret) {
  return binding.derive(pub, secret);
}

/**
 * Perform an ECDH with a raw scalar.
 * @param {Buffer} pub
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

function deriveWithScalar(pub, scalar) {
  return binding.deriveWithScalar(pub, scalar);
}

/*
 * Expose
 */

exports.id = 'ED25519';
exports.type = 'eddsa';
exports.size = 32;
exports.bits = 255;
exports.native = 2;
exports.privateKeyGenerate = privateKeyGenerate;
exports.scalarGenerate = scalarGenerate;
exports.privateKeyExpand = privateKeyExpand;
exports.privateKeyConvert = privateKeyConvert;
exports.privateKeyVerify = privateKeyVerify;
exports.scalarVerify = scalarVerify;
exports.scalarIsZero = scalarIsZero;
exports.scalarClamp = scalarClamp;
exports.privateKeyExport = privateKeyExport;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExportPKCS8 = privateKeyExportPKCS8;
exports.privateKeyImportPKCS8 = privateKeyImportPKCS8;
exports.privateKeyExportJWK = privateKeyExportJWK;
exports.privateKeyImportJWK = privateKeyImportJWK;
exports.scalarTweakAdd = scalarTweakAdd;
exports.scalarTweakMul = scalarTweakMul;
exports.scalarReduce = scalarReduce;
exports.scalarNegate = scalarNegate;
exports.scalarInvert = scalarInvert;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyFromScalar = publicKeyFromScalar;
exports.publicKeyConvert = publicKeyConvert;
exports.publicKeyFromUniform = publicKeyFromUniform;
exports.publicKeyToUniform = publicKeyToUniform;
exports.publicKeyFromHash = publicKeyFromHash;
exports.publicKeyToHash = publicKeyToHash;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyIsInfinity = publicKeyIsInfinity;
exports.publicKeyIsSmall = publicKeyIsSmall;
exports.publicKeyHasTorsion = publicKeyHasTorsion;
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
exports.sign = sign;
exports.signWithScalar = signWithScalar;
exports.signTweakAdd = signTweakAdd;
exports.signTweakMul = signTweakMul;
exports.verify = verify;
exports.verifySingle = verifySingle;
exports.verifyBatch = verifyBatch;
exports.derive = derive;
exports.deriveWithScalar = deriveWithScalar;
