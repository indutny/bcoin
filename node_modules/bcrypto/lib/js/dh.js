/*!
 * dh.js - DH for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Diffie_hellman
 *   https://www.teletrust.de/fileadmin/files/oid/oid_pkcs-3v1-4.pdf
 *   https://github.com/openssl/openssl/blob/master/crypto/dh/dh_gen.c
 *   https://github.com/openssl/openssl/blob/master/crypto/dh/dh_key.c
 *   https://github.com/openssl/openssl/blob/master/crypto/dh/dh_check.c
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const rng = require('../random');
const {countLeft, compareLeft} = require('../encoding/util');
const {isSafePrime} = require('../internal/primes');
const dhkey = require('../internal/dhkey');
const asn1 = require('../encoding/asn1');
const pkcs3 = require('../encoding/pkcs3');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');

const {
  DEFAULT_BITS,
  DEFAULT_GEN,
  MIN_BITS,
  MAX_BITS,
  MIN_GEN,
  MAX_GEN,
  DHKey,
  DHParams,
  DHPublicKey,
  DHPrivateKey
} = dhkey;

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @param {Number} [gen=2]
 * @returns {DHParams}
 */

function paramsGenerate(bits, gen) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (gen == null)
    gen = DEFAULT_GEN;

  assert((bits >>> 0) === bits);
  assert((gen >>> 0) === gen);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (gen < MIN_GEN || gen > MAX_GEN)
    throw new RangeError(`"gen" ranges from ${MIN_GEN} to ${MAX_GEN}.`);

  const g = new BN(gen);

  let p;

  for (;;) {
    p = BN.randomBits(rng, bits);

    p.setn(bits - 1, 1);
    p.setn(0, 1);

    switch (gen) {
      case 2:
        if (p.modrn(24) !== 23)
          continue;
        break;
      case 5:
        if (p.modrn(60) !== 59)
          continue;
        break;
      default:
        if (p.modrn(12) !== 11)
          continue;
        break;
    }

    if (!isSafePrime(p, 64))
      continue;

    break;
  }

  return new DHParams(p.encode(), g.encode());
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @param {Number} [gen=2]
 * @returns {DHParams}
 */

async function paramsGenerateAsync(bits, gen) {
  return paramsGenerate(bits, gen);
}

/**
 * Verify params.
 * @param {DHParams} params
 * @returns {Boolean}
 */

function paramsVerify(params) {
  assert(params instanceof DHParams);

  if (!isSaneParams(params))
    return false;

  const p = BN.decode(params.p);

  return isSafePrime(p, 64);
}

/**
 * Export params in PKCS#3 ASN.1 format.
 * @param {DHParams} params
 * @returns {Buffer}
 */

function paramsExport(params) {
  assert(params instanceof DHParams);

  if (!isSaneParams(params))
    throw new Error('Invalid DH parameters.');

  return new pkcs3.DHParams(
    params.p,
    params.g
  ).encode();
}

/**
 * Import params in PKCS#3 ASN.1 format.
 * @param {Buffer} raw
 * @returns {DHParams}
 */

function paramsImport(raw) {
  const params = pkcs3.DHParams.decode(raw);

  return new DHParams(
    params.p.value,
    params.g.value
  );
}

/**
 * Export a public key to JWK JSON format.
 * @param {DHParams} key
 * @returns {Object}
 */

function paramsExportJWK(key) {
  assert(key instanceof DHParams);
  return key.toParams().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {DHPublicKey}
 */

function paramsImportJWK(json) {
  return DHParams.fromJSON(json);
}

/**
 * Generate private key from params.
 * @param {DHParams} params
 * @returns {DHPrivateKey}
 */

function privateKeyCreate(params) {
  assert(params instanceof DHParams);

  if (!isSaneParams(params))
    throw new Error('Invalid DH parameters.');

  const p = BN.decode(params.p);
  const g = BN.decode(params.g);
  const pm1 = p.subn(1);

  let x, y;

  for (;;) {
    x = BN.random(rng, 1, p);
    y = g.powm(x, p);

    if (y.cmpn(1) <= 0 || y.cmp(pm1) === 0)
      continue;

    break;
  }

  const key = new DHPrivateKey();

  key.setParams(params);
  key.x = x.encode();
  key.y = y.encode();

  return key;
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @param {Number} [gen=2]
 * @returns {DHPrivateKey}
 */

function privateKeyGenerate(bits, gen) {
  const params = paramsGenerate(bits, gen);
  return privateKeyCreate(params);
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DHPrivateKey}
 */

async function privateKeyGenerateAsync(bits) {
  const params = await paramsGenerateAsync(bits);
  return privateKeyCreate(params);
}

/**
 * Pre-compute a private key.
 * @param {DHPrivateKey}
 * @returns {DHPrivateKey}
 */

function privateKeyCompute(key) {
  assert(key instanceof DHPrivateKey);

  if (!isSaneCompute(key))
    throw new Error('Invalid DH private key.');

  if (!needsCompute(key))
    return key;

  const p = BN.decode(key.p);
  const g = BN.decode(key.g);
  const x = BN.decode(key.x);
  const y = g.powm(x, p);

  key.y = y.encode();

  return key;
}

/**
 * Verify a private key.
 * @param {DHPrivateKey} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(key instanceof DHPrivateKey);

  if (!isSanePrivateKey(key))
    return false;

  if (!publicKeyVerify(key))
    return false;

  const p = BN.decode(key.p);
  const g = BN.decode(key.g);
  const x = BN.decode(key.x);
  const y = g.powm(x, p);

  return BN.decode(key.y).eq(y);
}

/**
 * Export a private key in PKCS#3 ASN.1 format.
 * @param {DHPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  return privateKeyExportPKCS8(key);
}

/**
 * Import a private key in PKCS#3 ASN.1 format.
 * @param {Buffer} raw
 * @returns {DHPrivateKey}
 */

function privateKeyImport(raw) {
  return privateKeyImportPKCS8(raw);
}

/**
 * Export a private key in PKCS8 ASN.1 format.
 * @param {DHPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  assert(key instanceof DHPrivateKey);

  if (!isSanePrivateKey(key))
    throw new Error('Invalid DH private key.');

  return new pkcs8.PrivateKeyInfo(
    0,
    asn1.objects.keyAlgs.DH,
    new pkcs3.DHParams(key.p, key.g),
    new asn1.Unsigned(key.x).encode()
  ).encode();
}

/**
 * Import a private key in PKCS8 ASN.1 format.
 * @param {Buffer} key
 * @returns {DHPrivateKey}
 */

function privateKeyImportPKCS8(raw) {
  const pki = pkcs8.PrivateKeyInfo.decode(raw);
  const {algorithm, parameters} = pki.algorithm;

  assert(pki.version.toNumber() === 0);
  assert(algorithm.toString() === asn1.objects.keyAlgs.DH);
  assert(parameters.node.type === asn1.types.SEQUENCE);

  const {p, g} = pkcs3.DHParams.decodeBody(parameters.node.value);
  const x = asn1.Unsigned.decode(pki.privateKey.value);

  const key = new DHPrivateKey(
    p.value,
    g.value,
    null,
    x.value
  );

  privateKeyCompute(key);

  return key;
}

/**
 * Export a private key to JWK JSON format.
 * @param {DHPrivateKey} key
 * @returns {Object}
 */

function privateKeyExportJWK(key) {
  assert(key instanceof DHPrivateKey);
  return key.toJSON();
}

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {DHPrivateKey}
 */

function privateKeyImportJWK(json) {
  const key = DHPrivateKey.fromJSON(json);

  privateKeyCompute(key);

  return key;
}

/**
 * Create a public key from a private key.
 * @param {DHPrivateKey} key
 * @returns {DHPublicKey}
 */

function publicKeyCreate(key) {
  assert(key instanceof DHPrivateKey);

  const pub = new DHPublicKey();

  pub.p = key.p;
  pub.g = key.g;
  pub.y = key.y;

  return pub;
}

/**
 * Verify a public key.
 * @param {DHKey} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  assert(key instanceof DHKey);

  if (!paramsVerify(key))
    return false;

  return isSanePublicKey(key);
}

/**
 * Export a public key to PKCS#3 ASN.1 format.
 * @param {DHKey} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  return publicKeyExportSPKI(key);
}

/**
 * Import a public key from PKCS#3 ASN.1 format.
 * @param {Buffer} raw
 * @returns {DHPublicKey}
 */

function publicKeyImport(raw) {
  return publicKeyImportSPKI(raw);
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DHKey} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  assert(key instanceof DHKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid DH public key.');

  return new x509.SubjectPublicKeyInfo(
    asn1.objects.keyAlgs.DH,
    new pkcs3.DHParams(key.p, key.g),
    new asn1.Unsigned(key.y).encode()
  ).encode();
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {DHPublicKey}
 */

function publicKeyImportSPKI(raw) {
  const spki = x509.SubjectPublicKeyInfo.decode(raw);
  const {algorithm, parameters} = spki.algorithm;

  assert(algorithm.toString() === asn1.objects.keyAlgs.DH);
  assert(parameters.node.type === asn1.types.SEQUENCE);

  const {p, g} = pkcs3.DHParams.decodeBody(parameters.node.value);
  const y = asn1.Unsigned.decode(spki.publicKey.rightAlign());

  return new DHPublicKey(
    p.value,
    g.value,
    y.value
  );
}

/**
 * Export a public key to JWK JSON format.
 * @param {DHKey} key
 * @returns {Object}
 */

function publicKeyExportJWK(key) {
  assert(key instanceof DHKey);
  return key.toPublic().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {DHPublicKey}
 */

function publicKeyImportJWK(json) {
  return DHPublicKey.fromJSON(json);
}

/**
 * Perform a diffie-hellman.
 * @param {DHKey} pub
 * @param {DHPrivateKey} priv
 * @returns {Buffer}
 */

function derive(pub, priv) {
  assert(pub instanceof DHKey);
  assert(priv instanceof DHPrivateKey);

  if (!isSanePublicKey(pub))
    throw new Error('Invalid DH public key.');

  if (!isSanePrivateKey(priv))
    throw new Error('Invalid DH private key.');

  const p0 = BN.decode(pub.p);
  const g0 = BN.decode(pub.g);
  const p = BN.decode(priv.p);
  const g = BN.decode(priv.g);

  if (!p0.eq(p) || !g0.eq(g))
    throw new Error('Incompatible DH parameters.');

  const x = BN.decode(priv.x);
  const y = BN.decode(pub.y);
  const e = y.powm(x, p, true, p.bitLength());

  return e.encode('be', p.byteLength());
}

/**
 * Perform a diffie-hellman.
 * @param {Buffer} pub
 * @param {DHPrivateKey} priv
 * @returns {Buffer}
 */

function exchange(pub, priv) {
  assert(priv instanceof DHPrivateKey);
  return derive(new DHPublicKey(priv.p, priv.g, pub), priv);
}

/*
 * Sanity Checking
 */

function isSaneParams(params) {
  assert(params instanceof DHParams);

  const pb = countLeft(params.p);
  const gb = countLeft(params.g);

  if (pb < MIN_BITS || pb > MAX_BITS)
    return false;

  if (gb < 2 || gb > pb)
    return false;

  if ((params.p[params.p.length - 1] & 1) === 0)
    return false;

  if (compareLeft(params.g, sub1(params.p)) >= 0)
    return false;

  return true;
}

function isSanePublicKey(key) {
  assert(key instanceof DHKey);

  if (!isSaneParams(key))
    return false;

  const pb = countLeft(key.p);
  const yb = countLeft(key.y);

  if (yb < 2 || yb > pb)
    return false;

  if (compareLeft(key.y, sub1(key.p)) >= 0)
    return false;

  return true;
}

function isSanePrivateKey(key) {
  assert(key instanceof DHPrivateKey);

  if (!isSanePublicKey(key))
    return false;

  const pb = countLeft(key.p);
  const xb = countLeft(key.x);

  if (xb === 0 || ((xb + 7) >>> 3) > ((pb + 7) >>> 3))
    return false;

  return true;
}

function isSaneCompute(key) {
  assert(key instanceof DHPrivateKey);

  const pb = countLeft(key.p);
  const gb = countLeft(key.g);
  const yb = countLeft(key.y);
  const xb = countLeft(key.x);

  if (pb < MIN_BITS || pb > MAX_BITS)
    return false;

  if (gb < 2 || gb > pb)
    return false;

  if ((key.p[key.p.length - 1] & 1) === 0)
    return false;

  if (yb > pb)
    return false;

  if (xb === 0 || ((xb + 7) >>> 3) > ((pb + 7) >>> 3))
    return false;

  if (compareLeft(key.g, sub1(key.p)) >= 0)
    return false;

  if (compareLeft(key.y, key.p) >= 0)
    return false;

  return true;
}

function needsCompute(key) {
  assert(key instanceof DHPrivateKey);
  return countLeft(key.y) === 0;
}

function sub1(p) {
  assert(Buffer.isBuffer(p));
  assert((p[p.length - 1] & 1) !== 0);

  const pm1 = Buffer.from(p);

  pm1[pm1.length - 1] -= 1;

  return pm1;
}

/*
 * Expose
 */

exports.native = 0;
exports.DHParams = DHParams;
exports.DHKey = DHKey;
exports.DHPublicKey = DHPublicKey;
exports.DHPrivateKey = DHPrivateKey;
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
exports.derive = derive;
exports.exchange = exchange;
