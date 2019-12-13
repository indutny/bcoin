/*!
 * x448.js - x448 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').x448;
const random = require('./random');
const asn1 = require('../internal/asn1-mini');
const eckey = require('../internal/eckey');

/*
 * Constants
 */

const CURVE_OID = Buffer.from('2b656f', 'hex');

/**
 * Generate a clamped key.
 * @returns {Buffer}
 */

function privateKeyGenerate() {
  const key = random.randomBytes(56);

  key[0] &= -4;
  key[55] &= 0xff;
  key[55] |= 0x80;

  return key;
}

/**
 * Validate a key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return key.length === 56;
}

/**
 * Export a private key to ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  if (!privateKeyVerify(key))
    throw new Error('Invalid private key.');

  return asn1.encodeOct(key);
}

/**
 * Import a private key from ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

function privateKeyImport(raw) {
  const key = asn1.decodeOct(raw);

  if (!privateKeyVerify(key))
    throw new Error('Invalid private key.');

  return key;
}

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  return asn1.encodePKCS8({
    version: 0,
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: privateKeyExport(key)
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
 * Create a public key from a private key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyCreate(key) {
  return binding.publicKeyCreate(key);
}

/**
 * Convert key to an ed448 key.
 * @param {Buffer} key
 * @param {Boolean} sign
 * @returns {Buffer}
 */

function publicKeyConvert(key, sign) {
  return binding.publicKeyConvert(key, sign);
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
 * @param {Buffer} pub
 * @param {Number?} hint
 * @returns {Buffer}
 */

function publicKeyToUniform(pub, hint = random.randomInt()) {
  return binding.publicKeyToUniform(pub, hint);
}

/**
 * Create point from a 112 byte hash.
 * @param {Buffer} bytes
 * @param {Boolean} [pake=false]
 * @returns {Buffer}
 */

function publicKeyFromHash(bytes, pake = false) {
  return binding.publicKeyFromHash(bytes, pake);
}

/**
 * Create a 112 byte hash from a point.
 * @param {Buffer} pub
 * @returns {Buffer}
 */

function publicKeyToHash(pub) {
  return binding.publicKeyToHash(pub);
}

/**
 * Validate a point.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
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
  assert(spki.key.length === 56);

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
 * Perform an ECDH.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

function derive(pub, priv) {
  return binding.derive(pub, priv);
}

/*
 * Expose
 */

exports.id = 'X448';
exports.type = 'ecdh';
exports.size = 56;
exports.bits = 448;
exports.native = 2;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyExport = privateKeyExport;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExportPKCS8 = privateKeyExportPKCS8;
exports.privateKeyImportPKCS8 = privateKeyImportPKCS8;
exports.privateKeyExportJWK = privateKeyExportJWK;
exports.privateKeyImportJWK = privateKeyImportJWK;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyConvert = publicKeyConvert;
exports.publicKeyFromUniform = publicKeyFromUniform;
exports.publicKeyToUniform = publicKeyToUniform;
exports.publicKeyFromHash = publicKeyFromHash;
exports.publicKeyToHash = publicKeyToHash;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyIsSmall = publicKeyIsSmall;
exports.publicKeyHasTorsion = publicKeyHasTorsion;
exports.publicKeyExport = publicKeyExport;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExportSPKI = publicKeyExportSPKI;
exports.publicKeyImportSPKI = publicKeyImportSPKI;
exports.publicKeyExportJWK = publicKeyExportJWK;
exports.publicKeyImportJWK = publicKeyImportJWK;
exports.derive = derive;
