/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on indutny/miller-rabin:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/miller-rabin
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RSA_(cryptosystem)
 *   https://tools.ietf.org/html/rfc3447
 *   https://tools.ietf.org/html/rfc8017
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_ossl.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_sign.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_oaep.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pss.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pk1.c
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/pkcs1v15.go
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/pss.go
 *   https://github.com/golang/go/blob/master/src/crypto/subtle/constant_time.go
 *   https://github.com/ARMmbed/mbed-crypto/blob/master/library/rsa.c
 *
 * References:
 *
 *   [RFC8017] PKCS #1: RSA Cryptography Specifications Version 2.2
 *     K. Moriarty, B. Kaliski, J. Jonsson, A. Rusch
 *     https://tools.ietf.org/html/rfc8017
 *
 *   [FIPS186] Federal Information Processing Standards Publication 186-4
 *     National Institute of Standards and Technology
 *     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const rsakey = require('../internal/rsakey');
const rng = require('../random');
const {randomPrime} = require('../internal/primes');
const {countLeft} = require('../encoding/util');
const base64 = require('../encoding/base64');
const asn1 = require('../encoding/asn1');
const pkcs1 = require('../encoding/pkcs1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const safe = require('../safe');

const {
  DEFAULT_BITS,
  DEFAULT_EXP,
  MIN_BITS,
  MAX_BITS,
  MIN_EXP,
  MAX_EXP,
  MIN_EXP_BITS,
  MAX_EXP_BITS,
  RSAKey,
  RSAPrivateKey,
  RSAPublicKey
} = rsakey;

const {
  safeEqual,
  safeEqualByte,
  safeSelect,
  safeLTE
} = safe;

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const PREFIX = Buffer.alloc(8, 0x00);
const SALT_LENGTH_AUTO = 0;
const SALT_LENGTH_HASH = -1;

/**
 * PKCS1v1.5+ASN.1 DigestInfo prefixes.
 * @see [RFC8017] Page 45, Section 9.2.
 * @see [RFC8017] Page 63, Section B.1.
 * @const {Object}
 */

const digestInfo = {
  BLAKE2B160: Buffer.from('3027300f060b2b060104018d3a0c02010505000414', 'hex'),
  BLAKE2B256: Buffer.from('3033300f060b2b060104018d3a0c02010805000420', 'hex'),
  BLAKE2B384: Buffer.from('3043300f060b2b060104018d3a0c02010c05000430', 'hex'),
  BLAKE2B512: Buffer.from('3053300f060b2b060104018d3a0c02011005000440', 'hex'),
  BLAKE2S128: Buffer.from('3023300f060b2b060104018d3a0c02020405000410', 'hex'),
  BLAKE2S160: Buffer.from('3027300f060b2b060104018d3a0c02020505000414', 'hex'),
  BLAKE2S224: Buffer.from('302f300f060b2b060104018d3a0c0202070500041c', 'hex'),
  BLAKE2S256: Buffer.from('3033300f060b2b060104018d3a0c02020805000420', 'hex'),
  GOST94: Buffer.from('302e300a06062a850302021405000420', 'hex'),
  KECCAK224: Buffer.from('302d300d06096086480165030402070500041c', 'hex'),
  KECCAK256: Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  KECCAK384: Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  KECCAK512: Buffer.from('3051300d060960864801650304020a05000440', 'hex'),
  MD2: Buffer.from('3020300c06082a864886f70d020205000410', 'hex'),
  MD4: Buffer.from('3020300c06082a864886f70d020405000410', 'hex'),
  MD5: Buffer.from('3020300c06082a864886f70d020505000410', 'hex'),
  MD5SHA1: Buffer.alloc(0),
  RIPEMD160: Buffer.from('3022300a060628cf0603003105000414', 'hex'),
  SHA1: Buffer.from('3021300906052b0e03021a05000414', 'hex'),
  SHA224: Buffer.from('302d300d06096086480165030402040500041c', 'hex'),
  SHA256: Buffer.from('3031300d060960864801650304020105000420', 'hex'),
  SHA384: Buffer.from('3041300d060960864801650304020205000430', 'hex'),
  SHA512: Buffer.from('3051300d060960864801650304020305000440', 'hex'),
  SHA3_224: Buffer.from('302d300d06096086480165030402070500041c', 'hex'),
  SHA3_256: Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  SHA3_384: Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  SHA3_512: Buffer.from('3051300d060960864801650304020a05000440', 'hex'),
  SHAKE128: Buffer.from('3021300d060960864801650304020b05000410', 'hex'),
  SHAKE256: Buffer.from('3031300d060960864801650304020c05000420', 'hex'),
  WHIRLPOOL: Buffer.from('304e300a060628cf0603003705000440', 'hex')
};

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

  return generateKey(bits, exponent);
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

  try {
    return await generateSubtle(bits, exponent);
  } catch (e) {
    return generateKey(bits, exponent);
  }
}

/**
 * Pre-compute a private key.
 * @param {RSAPrivateKey}
 * @returns {RSAPrivateKey}
 */

function privateKeyCompute(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(key instanceof RSAPrivateKey);

  if (!isSaneCompute(key))
    throw new Error('Invalid RSA private key.');

  if (!needsCompute(key))
    return key;

  const p = BN.decode(key.p);
  const q = BN.decode(key.q);

  let n = BN.decode(key.n);
  let e = BN.decode(key.e);
  let d = BN.decode(key.d);
  let dp = BN.decode(key.dp);
  let dq = BN.decode(key.dq);
  let qi = BN.decode(key.qi);

  if (n.isZero()) {
    n = p.mul(q);
    key.n = n.encode();
  }

  if (e.isZero()) {
    const phi = p.subn(1).mul(q.subn(1));
    e = d.invert(phi);
    key.e = e.encode();
  }

  if (d.isZero()) {
    const phi = p.subn(1).mul(q.subn(1));
    d = e.invert(phi);
    key.d = d.encode();
  }

  if (dp.isZero()) {
    dp = d.mod(p.subn(1));
    key.dp = dp.encode();
  }

  if (dq.isZero()) {
    dq = d.mod(q.subn(1));
    key.dq = dq.encode();
  }

  if (qi.isZero()) {
    qi = q.invert(p);
    key.qi = qi.encode();
  }

  return key;
}

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(key instanceof RSAPrivateKey);

  if (!isSanePrivateKey(key))
    return false;

  const p = BN.decode(key.p);
  const q = BN.decode(key.q);
  const n = BN.decode(key.n);
  const e = BN.decode(key.e);
  const d = BN.decode(key.d);
  const dp = BN.decode(key.dp);
  const dq = BN.decode(key.dq);
  const qi = BN.decode(key.qi);
  const pm1 = p.subn(1);
  const qm1 = q.subn(1);
  const lam = pm1.lcm(qm1);

  // n != 0
  if (n.isZero())
    return false;

  // n == p * q
  if (p.mul(q).cmp(n) !== 0)
    return false;

  // e * d mod lcm(p - 1, q - 1) == 1
  if (e.mul(d).imod(lam).cmpn(1) !== 0)
    return false;

  // dp == d mod (p - 1)
  if (d.mod(pm1).cmp(dp) !== 0)
    return false;

  // dq == d mod (q - 1)
  if (d.mod(qm1).cmp(dq) !== 0)
    return false;

  // q * qi mod p == 1
  if (q.mul(qi).imod(p).cmpn(1) !== 0)
    return false;

  return true;
}

/**
 * Export a private key to PKCS1 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  // [RFC8017] Page 55, Section A.1.2.
  assert(key instanceof RSAPrivateKey);

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  return new pkcs1.RSAPrivateKey(
    0,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ).encode();
}

/**
 * Import a private key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

function privateKeyImport(raw) {
  // [RFC8017] Page 55, Section A.1.2.
  const key = pkcs1.RSAPrivateKey.decode(raw);

  assert(key.version.toNumber() === 0);

  return new RSAPrivateKey(
    key.n.value,
    key.e.value,
    key.d.value,
    key.p.value,
    key.q.value,
    key.dp.value,
    key.dq.value,
    key.qi.value
  );
}

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  assert(key instanceof RSAPrivateKey);

  return new pkcs8.PrivateKeyInfo(
    0,
    asn1.objects.keyAlgs.RSA,
    new asn1.Null(),
    privateKeyExport(key)
  ).encode();
}

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

function privateKeyImportPKCS8(raw) {
  const pki = pkcs8.PrivateKeyInfo.decode(raw);
  const {algorithm, parameters} = pki.algorithm;

  assert(pki.version.toNumber() === 0);
  assert(algorithm.toString() === asn1.objects.keyAlgs.RSA);
  assert(parameters.node.type === asn1.types.NULL);

  return privateKeyImport(pki.privateKey.value);
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
  // [RFC8017] Page 8, Section 3.1.
  assert(key instanceof RSAKey);
  return isSanePublicKey(key);
}

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  // [RFC8017] Page 54, Section A.1.1.
  assert(key instanceof RSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  return new pkcs1.RSAPublicKey(key.n, key.e).encode();
}

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

function publicKeyImport(raw) {
  // [RFC8017] Page 54, Section A.1.1.
  const key = pkcs1.RSAPublicKey.decode(raw);
  return new RSAPublicKey(key.n.value, key.e.value);
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  return new x509.SubjectPublicKeyInfo(
    asn1.objects.keyAlgs.RSA,
    new asn1.Null(),
    publicKeyExport(key)
  ).encode();
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

function publicKeyImportSPKI(raw) {
  const spki = x509.SubjectPublicKeyInfo.decode(raw);
  const {algorithm, parameters} = spki.algorithm;

  assert(algorithm.toString() === asn1.objects.keyAlgs.RSA);
  assert(parameters.node.type === asn1.types.NULL);

  return publicKeyImport(spki.publicKey.rightAlign());
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

function sign(hash, msg, key, decipher = decryptRaw) {
  // [RFC8017] Page 36, Section 8.2.1.
  //           Page 45, Section 9.2.
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(hash == null || typeof hash === 'string');
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);
  assert(typeof decipher === 'function');

  const [prefix, hlen] = getDigestInfo(hash, msg);

  if (!prefix)
    throw new Error('Unknown RSA hash function.');

  if (msg.length !== hlen)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  const tlen = prefix.length + hlen;
  const klen = key.size();

  if (klen < tlen + 11)
    throw new Error('Message too long.');

  // EM = 0x00 || 0x01 || PS || 0x00 || T
  const em = Buffer.allocUnsafe(klen);

  em[0] = 0x00;
  em[1] = 0x01;

  for (let i = 2; i < klen - tlen - 1; i++)
    em[i] = 0xff;

  em[klen - tlen - 1] = 0x00;

  prefix.copy(em, klen - tlen);
  msg.copy(em, klen - hlen);

  return decipher(em, key);
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function verify(hash, msg, sig, key, encipher = encryptRaw) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(hash == null || typeof hash === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAKey);
  assert(typeof encipher === 'function');

  try {
    return _verify(hash, msg, sig, key, encipher);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature (PKCS1v1.5).
 * @private
 * @param {String} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function _verify(hash, msg, sig, key, encipher) {
  // [RFC8017] Page 37, Section 8.2.2.
  //           Page 45, Section 9.2.
  const [prefix, hlen] = getDigestInfo(hash, msg);

  if (!prefix)
    return false;

  if (msg.length !== hlen)
    return false;

  const klen = key.size();

  if (sig.length !== klen)
    return false;

  if (!isSanePublicKey(key))
    return false;

  const tlen = prefix.length + hlen;

  if (klen < tlen + 11)
    return false;

  const em = encipher(sig, key);

  // EM = 0x00 || 0x01 || PS || 0x00 || T
  let ok = 1;

  ok &= safeEqualByte(em[0], 0x00);
  ok &= safeEqualByte(em[1], 0x01);

  for (let i = 2; i < klen - tlen - 1; i++)
    ok &= safeEqualByte(em[i], 0xff);

  ok &= safeEqualByte(em[klen - tlen - 1], 0x00);
  ok &= safeEqual(em.slice(klen - tlen, klen - hlen), prefix);
  ok &= safeEqual(em.slice(klen - hlen, klen), msg);

  return ok === 1;
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function verifyLax(hash, msg, sig, key, encipher) {
  assert(key instanceof RSAKey);
  return verify(hash, msg, key.pad(sig), key, encipher);
}

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encrypt(msg, key, encipher = encryptRaw) {
  // [RFC8017] Page 28, Section 7.2.1.
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAKey);
  assert(typeof encipher === 'function');

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  const klen = key.size();

  if (msg.length > klen - 11)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || 0x02 || PS || 0x00 || M
  const em = Buffer.allocUnsafe(klen);
  const mlen = msg.length;
  const plen = klen - mlen - 3;

  em[0] = 0x00;
  em[1] = 0x02;

  randomNonzero(em, 2, plen);

  em[klen - mlen - 1] = 0x00;

  msg.copy(em, klen - mlen);

  return encipher(em, key);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decrypt(msg, key, decipher = decryptRaw) {
  // [RFC8017] Page 29, Section 7.2.2.
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);
  assert(typeof decipher === 'function');

  const klen = key.size();

  if (msg.length !== klen)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  if (klen < 11)
    throw new Error('Invalid RSA private key.');

  // EM = 0x00 || 0x02 || PS || 0x00 || M
  const em = decipher(msg, key);
  const zero = safeEqualByte(em[0], 0x00);
  const two = safeEqualByte(em[1], 0x02);

  let index = 0;
  let looking = 1;

  for (let i = 2; i < em.length; i++) {
    const equals0 = safeEqualByte(em[i], 0x00);

    index = safeSelect(index, i, looking & equals0);
    looking = safeSelect(looking, 0, equals0);
  }

  const validPS = safeLTE(2 + 8, index);
  const valid = zero & two & (looking ^ 1) & validPS;
  const offset = safeSelect(0, index + 1, valid);

  if (valid === 0)
    throw new Error('Invalid ciphertext.');

  return em.slice(offset);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptLax(msg, key, decipher) {
  assert(key instanceof RSAKey);
  return decrypt(key.pad(msg), key, decipher);
}

/**
 * Encrypt a message with public key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function encryptOAEP(hash, msg, key, label, encipher = encryptRaw) {
  // [RFC8017] Page 22, Section 7.1.1.
  if (label == null)
    label = EMPTY;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(label));
  assert(key instanceof RSAKey);
  assert(typeof encipher === 'function');

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  const klen = key.size();
  const mlen = msg.length;
  const hlen = hash.size;

  if (mlen > klen - 2 * hlen - 2)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || (seed) || (Hash(L) || PS || 0x01 || M)
  const em = Buffer.allocUnsafe(klen);
  const lhash = hash.digest(label);
  const seed = em.slice(1, 1 + hlen);
  const db = em.slice(1 + hlen);
  const dlen = db.length;

  em[0] = 0x00;

  rng.randomFill(seed, 0, seed.length);

  lhash.copy(db, 0);
  db.fill(0x00, hlen, dlen - mlen - 1);
  db[dlen - mlen - 1] = 0x01;
  msg.copy(db, dlen - mlen);

  mgf1xor(hash, db, seed);
  mgf1xor(hash, seed, db);

  return encipher(em, key);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEP(hash, msg, key, label, decipher = decryptRaw) {
  // [RFC8017] Page 25, Section 7.1.2.
  if (label == null)
    label = EMPTY;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(label));
  assert(key instanceof RSAPrivateKey);
  assert(typeof decipher === 'function');

  const klen = key.size();
  const mlen = msg.length;
  const hlen = hash.size;

  if (mlen !== klen)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  if (klen < hlen * 2 + 2)
    throw new Error('Invalid RSA private key size.');

  // EM = 0x00 || (seed) || (Hash(L) || PS || 0x01 || M)
  const em = decipher(msg, key);
  const expect = hash.digest(label);
  const zero = safeEqualByte(em[0], 0x00);
  const seed = em.slice(1, hlen + 1);
  const db = em.slice(hlen + 1);

  mgf1xor(hash, seed, db);
  mgf1xor(hash, db, seed);

  const lhash = db.slice(0, hlen);
  const lvalid = safeEqual(lhash, expect);
  const rest = db.slice(hlen);

  let looking = 1;
  let index = 0;
  let invalid = 0;

  for (let i = 0; i < rest.length; i++) {
    const equals0 = safeEqualByte(rest[i], 0x00);
    const equals1 = safeEqualByte(rest[i], 0x01);

    index = safeSelect(index, i, looking & equals1);
    looking = safeSelect(looking, 0, equals1);
    invalid = safeSelect(invalid, 1, looking & (equals0 ^ 1));
  }

  const valid = zero & lvalid & (invalid ^ 1) & (looking ^ 1);

  if (valid === 0)
    throw new Error('Invalid RSA ciphertext.');

  return rest.slice(index + 1);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEPLax(hash, msg, key, label, decipher) {
  assert(key instanceof RSAKey);
  return decryptOAEP(hash, key.pad(msg), key, label, decipher);
}

/**
 * Sign a message (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Buffer} PSS-formatted signature.
 */

function signPSS(hash, msg, key, saltLen, decipher = decryptRaw) {
  // [RFC8017] Page 33, Section 8.1.1.
  if (saltLen == null)
    saltLen = SALT_LENGTH_HASH;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);
  assert(saltLen === -1 || (saltLen >>> 0) === saltLen);
  assert(typeof decipher === 'function');

  if (msg.length !== hash.size)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  if (saltLen === SALT_LENGTH_AUTO)
    saltLen = key.size() - 2 - hash.size;
  else if (saltLen === SALT_LENGTH_HASH)
    saltLen = hash.size;

  const salt = rng.randomBytes(saltLen);
  const bits = key.bits();
  const em = pssEncode(hash, msg, bits - 1, salt);

  // Note that `em` may be one byte less
  // than the modulus size in the case
  // of (bits - 1) mod 8 == 0.
  //
  // This isn't a problem for us since
  // our decryption function is fairly
  // lax about size requirements.
  return decipher(em, key);
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

function verifyPSS(hash, msg, sig, key, saltLen, encipher = encryptRaw) {
  if (saltLen == null)
    saltLen = SALT_LENGTH_HASH;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAKey);
  assert(saltLen === -1 || (saltLen >>> 0) === saltLen);
  assert(typeof encipher === 'function');

  try {
    return _verifyPSS(hash, msg, sig, key, saltLen, encipher);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature (PSS).
 * @private
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {RSAKey} key
 * @param {Number} saltLen
 * @returns {Boolean}
 */

function _verifyPSS(hash, msg, sig, key, saltLen, encipher) {
  // [RFC8017] Page 34, Section 8.1.2.
  if (msg.length !== hash.size)
    return false;

  if (sig.length !== key.size())
    return false;

  if (!isSanePublicKey(key))
    return false;

  const bits = key.bits();

  let em = encipher(sig, key);

  // Edge case: the encoding crossed a
  // a byte boundary. Our encryption
  // function pads to the modulus size
  // by default, meaning there's one
  // extra zero byte prepended.
  if (((bits - 1) & 7) === 0) {
    if (em[0] !== 0x00)
      return false;

    em = em.slice(1);
  }

  if (saltLen === SALT_LENGTH_AUTO)
    saltLen = 0; // Handled in pssVerify.
  else if (saltLen === SALT_LENGTH_HASH)
    saltLen = hash.size;

  return pssVerify(hash, msg, em, bits - 1, saltLen);
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

function verifyPSSLax(hash, msg, sig, key, saltLen, encipher) {
  assert(key instanceof RSAKey);
  return verifyPSS(hash, msg, key.pad(sig), key, saltLen, encipher);
}

/**
 * Raw encryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encryptRaw(msg, key) {
  // [RFC8017] Page 13, Section 5.1.1.
  //           Page 16, Section 5.2.2.
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAKey);

  // OpenSSL behavior for public encryption.
  if (msg.length !== key.size())
    throw new Error('Invalid RSA message size.');

  const n = BN.decode(key.n);
  const e = BN.decode(key.e);

  if (n.isZero() || e.isZero())
    throw new Error('Invalid RSA public key.');

  const m = BN.decode(msg);

  if (m.cmp(n) >= 0)
    throw new Error('Invalid RSA message size.');

  // c = m^e mod n
  const c = m.powm(e, n);

  return c.encode('be', n.byteLength());
}

/**
 * Raw decryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptRaw(msg, key) {
  // [RFC8017] Page 13, Section 5.1.2.
  //           Page 15, Section 5.2.1.
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);

  let n = BN.decode(key.n);
  let e = BN.decode(key.e);

  // Recompute modulus.
  if (n.isZero()) {
    const p = BN.decode(key.p);
    const q = BN.decode(key.q);

    if (p.isZero() || q.isZero())
      throw new Error('Invalid RSA private key.');

    // n = p * q
    n = p.imul(q);
  }

  // Recompute public exponent.
  if (e.isZero()) {
    const d = BN.decode(key.d);
    const p = BN.decode(key.p);
    const q = BN.decode(key.q);

    if (d.isZero() || p.isZero() || q.isZero())
      throw new Error('Invalid RSA private key.');

    // phi = (p - 1) * (q - 1)
    const phi = p.subn(1).mul(q.subn(1));

    // e = d^-1 mod phi
    try {
      e = d.invert(phi);
    } catch (e) {
      throw new Error('Invalid RSA private key.');
    }
  }

  // Decode message.
  const c = BN.decode(msg);

  // Validate params.
  if (c.cmp(n) >= 0 || n.isZero())
    throw new Error('Invalid RSA message size.');

  // Generate blinding factor.
  const [b, bi] = getBlinding(n, e);

  // Blind.
  c.imul(b).imod(n);

  // Decrypt.
  let m = null;

  // Potentially use precomputed values.
  if (needsCompute(key)) {
    // Decrypt with private exponent.
    let d = BN.decode(key.d);

    // Recompute private exponent.
    if (d.isZero()) {
      const p = BN.decode(key.p);
      const q = BN.decode(key.q);

      if (p.isZero() || q.isZero())
        throw new Error('Invalid RSA private key.');

      // phi = (p - 1) * (q - 1)
      const phi = p.subn(1).mul(q.subn(1));

      // d = e^-1 mod phi
      try {
        d = e.invert(phi);
      } catch (e) {
        throw new Error('Invalid RSA private key.');
      }
    }

    // m = c^d mod n
    m = c.powm(d, n);
  } else {
    // Decrypt with precomputed values.
    //
    // This will leverage Chinese Remainder
    // Theorem to avoid a large exponentiation.
    //
    // We can use Montgomery reduction here
    // since our moduli are prime.
    const p = BN.decode(key.p);
    const q = BN.decode(key.q);
    const dp = BN.decode(key.dp);
    const dq = BN.decode(key.dq);
    const qi = BN.decode(key.qi);

    // mp = c^(d mod p-1) mod p
    // mq = c^(d mod q-1) mod q
    // md = (mp - mq) / q mod p
    const mp = c.powm(dp, p, true);
    const mq = c.powm(dq, q, true);
    const md = mp.isub(mq).imul(qi).imod(p);

    // m = (md * q + mq) mod n
    m = md.imul(q).iadd(mq).imod(n);

    // In reality we would want to
    // throw an error here, however,
    // OpenSSL swallows the error
    // and does a slower exponentation.
    if (m.powm(e, n).cmp(c) !== 0) {
      const d = BN.decode(key.d);

      // m = c^d mod n
      m = c.powm(d, n);
    }
  }

  // Unblind.
  m.imul(bi).imod(n);

  return m.encode('be', n.byteLength());
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function veil(msg, bits, key) {
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);
  assert(key instanceof RSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  if (msg.length !== key.size())
    throw new Error('Invalid RSA ciphertext.');

  if (bits < key.bits())
    throw new Error('Cannot make ciphertext smaller.');

  const bytes = (bits + 7) >>> 3;
  const n = BN.decode(key.n);
  const c = BN.decode(msg);

  if (c.cmp(n) >= 0)
    throw new Error('Invalid ciphertext.');

  const vmax = BN.shift(1, bits);
  const rmax = vmax.sub(c).iadd(n).isubn(1).div(n);

  assert(rmax.sign() > 0);

  let v = vmax;

  while (v.cmp(vmax) >= 0) {
    const r = BN.random(rng, 0, rmax);

    v = c.add(r.imul(n));
  }

  assert(v.mod(n).cmp(c) === 0);
  assert(v.bitLength() <= bits);

  return v.encode('be', bytes);
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
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);
  assert(key instanceof RSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  const klen = key.size();

  if (msg.length < klen)
    throw new Error('Invalid RSA ciphertext.');

  if (countLeft(msg) > bits)
    throw new Error('Invalid RSA ciphertext.');

  const n = BN.decode(key.n);
  const v = BN.decode(msg);
  const c = v.imod(n);

  return c.encode('be', klen);
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

/**
 * Generate private key.
 * @private
 * @param {Number} bits
 * @param {Number} exponent
 * @returns {RSAPrivateKey}
 */

function generateKey(bits, exponent) {
  // [RFC8017] Page 9, Section 3.2.
  // [FIPS186] Page 51, Appendix B.3.1
  //           Page 55, Appendix B.3.3
  //
  // There are two methods for choosing `d`.
  // Implementations differ on whether they
  // use Euler's totient or the Carmichael
  // function.
  //
  // The best explanation of Euler's phi vs.
  // Carmichael's lambda I've seen comes from
  // the crypto stackexchange[1].
  //
  // Note that both functions are _equivalent_
  // when used with RSA, however, Carmichael's
  // may lend itself to some perf benefits.
  //
  // We currently use Euler's totient in order
  // to maintain compatibility with OpenSSL.
  //
  // [1] https://crypto.stackexchange.com/a/29595
  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);
  assert(bits >= 64);
  assert(exponent >= 3 && (exponent & 1) !== 0);

  const e = new BN(exponent);

  for (;;) {
    const p = randomPrime((bits >>> 1) + (bits & 1));
    const q = randomPrime(bits >>> 1);

    if (p.cmp(q) === 0)
      continue;

    if (p.cmp(q) < 0)
      p.swap(q);

    if (p.sub(q).bitLength() <= (bits >> 1) - 99)
      continue;

    const n = p.mul(q);

    if (n.bitLength() !== bits)
      continue;

    const pm1 = p.subn(1);
    const qm1 = q.subn(1);
    const phi = pm1.mul(qm1);

    let d;
    try {
      d = e.invert(phi);
    } catch (e) {
      continue;
    }

    const dp = d.mod(pm1);
    const dq = d.mod(qm1);
    const qi = q.invert(p);
    const key = new RSAPrivateKey();

    key.n = n.encode();
    key.e = e.encode();
    key.d = d.encode();
    key.p = p.encode();
    key.q = q.encode();
    key.dp = dp.encode();
    key.dq = dq.encode();
    key.qi = qi.encode();

    return key;
  }
}

/*
 * Subtle
 */

async function generateSubtle(bits, exponent) {
  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);
  assert(bits >= 64);
  assert(exponent >= 3 && (exponent & 1) !== 0);

  const crypto = global.crypto || global.msCrypto;

  if (!crypto)
    throw new Error('Crypto API not available.');

  const {subtle} = crypto;

  if (!subtle)
    throw new Error('Subtle API not available.');

  if (!subtle.generateKey || !subtle.exportKey)
    throw new Error('Subtle key generation not available.');

  const hi = (exponent * (1 / 0x100000000)) >>> 0;
  const lo = exponent >>> 0;
  const exp = new Uint8Array(8);

  exp[0] = 0;
  exp[1] = 0;
  exp[2] = hi >>> 8;
  exp[3] = hi;
  exp[4] = lo >>> 24;
  exp[5] = lo >>> 16;
  exp[6] = lo >>> 8;
  exp[7] = lo;

  const algo = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: bits,
    publicExponent: exp,
    hash: { name: 'SHA-256' }
  };

  const ck = await subtle.generateKey(algo, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', ck.privateKey);
  const p = BN.decode(base64.decodeURL(jwk.p));
  const q = BN.decode(base64.decodeURL(jwk.q));

  if (p.cmp(q) === 0)
    throw new Error('Subtle bug: modulus is a perfect square.');

  if (p.cmp(q) < 0)
    p.swap(q);

  const n = p.mul(q);

  if (n.bitLength() !== bits)
    throw new Error('Subtle returned incorrectly sized key.');

  const pm1 = p.subn(1);
  const qm1 = q.subn(1);
  const phi = pm1.mul(qm1);
  const e = new BN(exponent);
  const d = e.invert(phi);
  const dp = d.mod(pm1);
  const dq = d.mod(qm1);
  const qi = q.invert(p);
  const key = new RSAPrivateKey();

  key.n = n.encode();
  key.e = e.encode();
  key.d = d.encode();
  key.p = p.encode();
  key.q = q.encode();
  key.dp = dp.encode();
  key.dq = dq.encode();
  key.qi = qi.encode();

  return key;
}

/*
 * Randomization
 */

function getBlinding(n, e) {
  assert(n instanceof BN);
  assert(e instanceof BN);

  // Generate blinding factor.
  for (;;) {
    // s = random integer in [1,n-1]
    const s = BN.random(rng, 1, n);

    // bi = s^-1 mod n
    let bi;
    try {
      bi = s.invert(n);
    } catch (e) {
      continue;
    }

    // b = s^e mod n
    const b = s.powm(e, n);

    return [b, bi];
  }
}

/*
 * PSS
 */

function pssEncode(hash, msg, embits, salt) {
  // [RFC8017] Page 42, Section 9.1.1.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert((embits >>> 0) === embits);
  assert(Buffer.isBuffer(salt));

  const hlen = hash.size;
  const slen = salt.length;
  const emlen = (embits + 7) >>> 3;

  if (msg.length !== hlen)
    throw new Error('Invalid RSA message size.');

  if (emlen < hlen + slen + 2)
    throw new Error('Message too long.');

  // EM = (PS || 0x01 || salt) || H || 0xbc
  const em = Buffer.allocUnsafe(emlen);
  const db = em.slice(0, emlen - hlen - 1);
  const h = em.slice(emlen - hlen - 1, emlen - 1);
  const h0 = hash.multi(PREFIX, msg, salt);
  const mask = 0xff >>> (8 * emlen - embits);

  db.fill(0x00, 0, emlen - slen - hlen - 2);
  db[emlen - slen - hlen - 2] = 0x01;
  salt.copy(db, emlen - slen - hlen - 1);
  h0.copy(h, 0);
  em[emlen - 1] = 0xbc;

  mgf1xor(hash, db, h);

  db[0] &= mask;

  return em;
}

function pssVerify(hash, msg, em, embits, slen) {
  // [RFC8017] Page 44, Section 9.1.2.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(em));
  assert((embits >>> 0) === embits);
  assert((slen >>> 0) === slen);

  const hlen = hash.size;
  const emlen = (embits + 7) >>> 3;

  if (msg.length !== hlen)
    return false;

  if (emlen < hlen + slen + 2)
    return false;

  if (em[emlen - 1] !== 0xbc)
    return false;

  // EM = (PS || 0x01 || salt) || H || 0xbc
  const db = em.slice(0, emlen - hlen - 1);
  const h = em.slice(emlen - hlen - 1, emlen - 1);
  const mask = 0xff >>> (8 * emlen - embits);

  if (em[0] & ~mask)
    return false;

  mgf1xor(hash, db, h);

  db[0] &= mask;

  if (slen === 0) { // Auto
    slen = -1;

    for (let i = 0; i < db.length; i++) {
      if (db[i] === 0x00)
        continue;

      if (db[i] === 0x01) {
        slen = db.length - (i + 1);
        break;
      }

      return false;
    }

    if (slen === -1)
      return false;
  } else {
    const len = db.length - slen - 1;

    for (let i = 0; i < len; i++) {
      if (db[i] !== 0x00)
        return false;
    }

    if (db[len] !== 0x01)
      return false;
  }

  const salt = db.slice(db.length - slen);
  const h0 = hash.multi(PREFIX, msg, salt);

  return h0.equals(h);
}

/*
 * Sanity Checking
 */

function isSanePublicKey(key) {
  // [RFC8017] Page 8, Section 3.1.
  assert(key instanceof RSAKey);

  const nb = countLeft(key.n);

  if (nb < MIN_BITS || nb > MAX_BITS)
    return false;

  const eb = countLeft(key.e);

  if (eb < MIN_EXP_BITS || eb > MAX_EXP_BITS)
    return false;

  if ((key.e[key.e.length - 1] & 1) === 0)
    return false;

  return true;
}

function isSanePrivateKey(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(key instanceof RSAPrivateKey);

  if (!isSanePublicKey(key))
    return false;

  // n == p * q
  const nb = countLeft(key.n);
  const pb = countLeft(key.p);
  const qb = countLeft(key.q);

  if (nb > pb + qb)
    return false;

  // d < (p - 1) * (q - 1)
  const db = countLeft(key.d);

  if (db === 0 || db > nb)
    return false;

  // dp < p - 1
  const dpb = countLeft(key.dp);

  if (dpb === 0 || dpb > pb)
    return false;

  // dq < q - 1
  const dqb = countLeft(key.dq);

  if (dqb === 0 || dqb > qb)
    return false;

  // q < p
  const qib = countLeft(key.qi);

  if (qib === 0 || qib > pb)
    return false;

  return true;
}

function isSaneCompute(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(key instanceof RSAPrivateKey);

  const nb = countLeft(key.n);
  const eb = countLeft(key.e);
  const db = countLeft(key.d);
  const pb = countLeft(key.p);
  const qb = countLeft(key.q);
  const dpb = countLeft(key.dp);
  const dqb = countLeft(key.dq);
  const qib = countLeft(key.qi);

  // p != 0 and q != 0
  if (pb === 0 || qb === 0)
    return false;

  // e != 0 or d != 0
  if (eb === 0 && db === 0)
    return false;

  // n == p * q
  if (nb !== 0) {
    if (nb < MIN_BITS || nb > MAX_BITS)
      return false;

    if (nb > pb + qb)
      return false;
  }

  // e < (p - 1) * (q - 1)
  if (eb !== 0) {
    if (eb < MIN_EXP_BITS || eb > MAX_EXP_BITS)
      return false;

    if ((key.e[key.e.length - 1] & 1) === 0)
      return false;
  }

  // d < (p - 1) * (q - 1)
  if (db !== 0) {
    if (db > pb + qb)
      return false;
  }

  // dp < p - 1
  if (dpb !== 0) {
    if (dpb > pb)
      return false;
  }

  // dq < q - 1
  if (dqb !== 0) {
    if (dqb > qb)
      return false;
  }

  // q < p
  if (qib !== 0) {
    if (qib > pb)
      return false;
  }

  return true;
}

function needsCompute(key) {
  assert(key instanceof RSAPrivateKey);

  return countLeft(key.n) === 0
      || countLeft(key.e) === 0
      || countLeft(key.d) === 0
      || countLeft(key.dp) === 0
      || countLeft(key.dq) === 0
      || countLeft(key.qi) === 0;
}

/*
 * Helpers
 */

function randomNonzero(data, offset, size) {
  assert(Buffer.isBuffer(data));
  assert((offset >>> 0) === offset);
  assert((size >>> 0) === size);

  rng.randomFill(data, offset, size);

  const len = offset + size;

  for (let i = offset; i < len; i++) {
    while (data[i] === 0x00)
      rng.randomFill(data, i, 1);
  }
}

function mgf1xor(hash, out, seed) {
  // [RFC8017] Page 67, Section B.2.1.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(out));
  assert(Buffer.isBuffer(seed));

  const ctr = Buffer.alloc(4, 0x00);

  let i = 0;

  while (i < out.length) {
    const digest = hash.multi(seed, ctr);

    let j = 0;

    while (i < out.length && j < digest.length)
      out[i++] ^= digest[j++];

    for (j = 3; j >= 0; j--) {
      ctr[j] += 1;

      if (ctr[j] !== 0x00)
        break;
    }
  }
}

function getDigestInfo(name, msg) {
  // [RFC8017] Page 63, Section B.1.
  assert(name == null || typeof name === 'string');
  assert(Buffer.isBuffer(msg));

  if (name == null)
    return [EMPTY, msg.length];

  const prefix = digestInfo[name];

  if (!Buffer.isBuffer(prefix))
    return [null, 0];

  return [
    prefix,
    prefix.length > 0
      ? prefix[prefix.length - 1]
      : 36
  ];
}

/*
 * Expose
 */

exports.native = 0;
exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
exports.SALT_LENGTH_AUTO = SALT_LENGTH_AUTO;
exports.SALT_LENGTH_HASH = SALT_LENGTH_HASH;
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
