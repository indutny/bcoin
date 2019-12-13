/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * References:
 *
 *   [FIPS186] Federal Information Processing Standards Publication
 *     National Institute of Standards and Technology
 *     http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
 *
 *   [DSA] Digital Signature Algorithm (wikipedia)
 *     https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
 *
 *   [RFC6979] Deterministic Usage of the Digital Signature
 *             Algorithm (DSA) and Elliptic Curve Digital
 *             Signature Algorithm (ECDSA)
 *     T. Pornin
 *     https://tools.ietf.org/html/rfc6979
 *
 *   [RFC3279] Algorithms and Identifiers for the Internet X.509
 *             Public Key Infrastructure Certificate and Certificate
 *             Revocation List (CRL) Profile
 *     W. Polk, R. Housley, L. Bassham
 *     https://tools.ietf.org/html/rfc3279
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const rng = require('../random');
const HmacDRBG = require('../hmac-drbg');
const SHA256 = require('../sha256');
const {countLeft, compareLeft} = require('../encoding/util');
const {probablyPrime} = require('../internal/primes');
const dsakey = require('../internal/dsakey');
const Signature = require('../internal/signature');
const asn1 = require('../encoding/asn1');
const openssl = require('../encoding/openssl');
const pkcs8 = require('../encoding/pkcs8');
const rfc3279 = require('../encoding/rfc3279');
const x509 = require('../encoding/x509');

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
  if (bits == null)
    bits = DEFAULT_BITS;

  assert((bits >>> 0) === bits);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  // OpenSSL behavior.
  const L = bits;
  const N = bits < 2048 ? 160 : 256;

  return generateParams(L, N);
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

async function paramsGenerateAsync(bits) {
  return paramsGenerate(bits);
}

/**
 * Verify params.
 * @param {DSAParams} params
 * @returns {Boolean}
 */

function paramsVerify(params) {
  assert(params instanceof DSAParams);

  if (!isSaneParams(params))
    return false;

  const p = BN.decode(params.p);
  const q = BN.decode(params.q);
  const g = BN.decode(params.g);

  return g.powm(q, p).cmpn(1) === 0;
}

/**
 * Export params in OpenSSL ASN.1 format.
 * @param {DSAParams} params
 * @returns {Buffer}
 */

function paramsExport(params) {
  assert(params instanceof DSAParams);

  if (!isSaneParams(params))
    throw new Error('Invalid DSA parameters.');

  return new openssl.DSAParams(
    params.p,
    params.q,
    params.g
  ).encode();
}

/**
 * Import params in OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAParams}
 */

function paramsImport(raw) {
  const params = openssl.DSAParams.decode(raw);

  return new DSAParams(
    params.p.value,
    params.q.value,
    params.g.value
  );
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
  // [FIPS186] Page 46, Appendix B.1.
  // [DSA] "Per-user keys".
  assert(params instanceof DSAParams);

  if (!isSaneParams(params))
    throw new Error('Invalid DSA parameters.');

  const q = BN.decode(params.q);
  const p = BN.decode(params.p);
  const g = BN.decode(params.g);
  const x = BN.random(rng, 1, q);
  const y = g.powm(x, p);
  const key = new DSAPrivateKey();

  key.setParams(params);
  key.x = x.encode();
  key.y = y.encode();

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

  if (!isSaneCompute(key))
    throw new Error('Invalid DSA private key.');

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
 * @param {DSAPrivateKey} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(key instanceof DSAPrivateKey);

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
 * Export a private key in OpenSSL ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  assert(key instanceof DSAPrivateKey);

  if (!isSanePrivateKey(key))
    throw new Error('Invalid DSA private key.');

  return new openssl.DSAPrivateKey(
    0,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ).encode();
}

/**
 * Import a private key in OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPrivateKey}
 */

function privateKeyImport(raw) {
  const key = openssl.DSAPrivateKey.decode(raw);

  assert(key.version.toNumber() === 0);

  return new DSAPrivateKey(
    key.p.value,
    key.q.value,
    key.g.value,
    key.y.value,
    key.x.value
  );
}

/**
 * Export a private key in PKCS8 ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  assert(key instanceof DSAPrivateKey);

  if (!isSanePrivateKey(key))
    throw new Error('Invalid DSA private key.');

  return new pkcs8.PrivateKeyInfo(
    0,
    asn1.objects.keyAlgs.DSA,
    new rfc3279.DSAParams(key.p, key.q, key.g),
    new asn1.Unsigned(key.x).encode()
  ).encode();
}

/**
 * Import a private key in PKCS8 ASN.1 format.
 * @param {Buffer} key
 * @returns {DSAPrivateKey}
 */

function privateKeyImportPKCS8(raw) {
  const pki = pkcs8.PrivateKeyInfo.decode(raw);
  const {algorithm, parameters} = pki.algorithm;

  assert(pki.version.toNumber() === 0);
  assert(algorithm.toString() === asn1.objects.keyAlgs.DSA);
  assert(parameters.node.type === asn1.types.SEQUENCE);

  const {p, q, g} = rfc3279.DSAParams.decodeBody(parameters.node.value);
  const x = asn1.Unsigned.decode(pki.privateKey.value);

  const key = new DSAPrivateKey(
    p.value,
    q.value,
    g.value,
    null,
    x.value
  );

  privateKeyCompute(key);

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

  if (!paramsVerify(key))
    return false;

  if (!isSanePublicKey(key))
    return false;

  const p = BN.decode(key.p);
  const q = BN.decode(key.q);
  const y = BN.decode(key.y);

  return y.powm(q, p).cmpn(1) === 0;
}

/**
 * Export a public key to OpenSSL ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  assert(key instanceof DSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid DSA public key.');

  return new openssl.DSAPublicKey(
    key.y,
    key.p,
    key.q,
    key.g
  ).encode();
}

/**
 * Import a public key from OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

function publicKeyImport(raw) {
  const key = openssl.DSAPublicKey.decode(raw);

  return new DSAPublicKey(
    key.p.value,
    key.q.value,
    key.g.value,
    key.y.value
  );
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  // [RFC3279] Page 9, Section 2.3.2.
  assert(key instanceof DSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid DSA public key.');

  return new x509.SubjectPublicKeyInfo(
    asn1.objects.keyAlgs.DSA,
    new rfc3279.DSAParams(key.p, key.q, key.g),
    new asn1.Unsigned(key.y).encode()
  ).encode();
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

function publicKeyImportSPKI(raw) {
  // [RFC3279] Page 9, Section 2.3.2.
  const spki = x509.SubjectPublicKeyInfo.decode(raw);
  const {algorithm, parameters} = spki.algorithm;

  assert(algorithm.toString() === asn1.objects.keyAlgs.DSA);
  assert(parameters.node.type === asn1.types.SEQUENCE);

  const {p, q, g} = rfc3279.DSAParams.decodeBody(parameters.node.value);
  const y = asn1.Unsigned.decode(spki.publicKey.rightAlign());

  return new DSAPublicKey(
    p.value,
    q.value,
    g.value,
    y.value
  );
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
  if (size == null) {
    assert(Buffer.isBuffer(sig));
    assert((sig.length & 1) === 0);
    size = sig.length >>> 1;
  }

  return Signature.toDER(sig, size);
}

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} R/S-formatted signature.
 */

function signatureImport(sig, size) {
  return Signature.toRS(sig, size);
}

/**
 * Sign a message (R/S).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function sign(msg, key) {
  const S = _sign(msg, key);
  return S.encode(key.size());
}

/**
 * Sign a message (DER).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

function signDER(msg, key) {
  const S = _sign(msg, key);
  return S.toDER(key.size());
}

/**
 * Sign a message.
 * @private
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key
 * @returns {Signature}
 */

function _sign(msg, key) {
  // DSA Signing.
  //
  // [FIPS186] Page 19, Section 4.6.
  // [DSA] "Signing".
  // [RFC6979] Page 9, Section 2.4.
  // [RFC6979] Page 10, Section 3.2.
  //
  // Assumptions:
  //
  //   - Let `m` be an integer reduced from bytes.
  //   - Let `x` be a secret non-zero scalar.
  //   - Let `k` be a random non-zero scalar.
  //   - r != 0, s != 0.
  //
  // Computation:
  //
  //   k = random integer in [1,q-1]
  //   r' = g^k mod p
  //   r = r' mod q
  //   s = (r * x + m) / k mod q
  //   S = (r, s)
  //
  // Note that `k` must remain secret,
  // otherwise an attacker can compute:
  //
  //   x = (s * k - m) / r mod q
  //
  // This means that if two signatures
  // share the same `r` value, an attacker
  // can compute:
  //
  //   k = (m1 - m2) / (s1 - s2) mod q
  //   x = (s1 * k - m1) / r mod q
  //
  // Assuming:
  //
  //   s1 = (r * x + m1) / k mod q
  //   s2 = (r * x + m2) / k mod q
  //
  // To mitigate this, `k` can be generated
  // deterministically using the HMAC-DRBG
  // construction described in [RFC6979].
  assert(Buffer.isBuffer(msg));
  assert(key instanceof DSAPrivateKey);

  if (!isSanePrivateKey(key))
    throw new Error('Invalid DSA private key.');

  const p = BN.decode(key.p);
  const q = BN.decode(key.q);
  const g = BN.decode(key.g);
  const x = BN.decode(key.x);
  const bytes = q.byteLength();
  const m = reduce(msg, q);
  const keyX = x.encode('be', bytes);
  const nonce = m.encode('be', bytes);
  const drbg = new HmacDRBG(SHA256, keyX, nonce);

  for (;;) {
    const k = truncate(drbg.generate(bytes), q);

    if (k.isZero() || k.cmp(q) >= 0)
      continue;

    const re = powBlind(g, k, p, q);
    const r = re.mod(q);

    if (r.isZero())
      continue;

    const [b, bi] = getBlinding(q);
    const ki = k.fermat(q);
    const bx = x.mul(b).imod(q);
    const bm = m.mul(b).imod(q);
    const sk = r.mul(bx).iadd(bm).imod(q);
    const s = sk.imul(ki).imod(q);

    s.imul(bi).imod(q);

    if (s.isZero())
      continue;

    const S = new Signature();

    S.r = r.encode('be', bytes);
    S.s = s.encode('be', bytes);

    return S;
  }
}

/**
 * Verify a signature (R/S).
 * @private
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof DSAKey);

  if (sig.length !== key.size() * 2)
    return false;

  const S = Signature.decode(sig, key.size());

  try {
    return _verify(msg, S, key);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature (DER).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof DSAKey);

  let S;
  try {
    S = Signature.fromDER(sig, key.size());
  } catch (e) {
    return false;
  }

  return _verify(msg, S, key);
}

/**
 * Verify a signature.
 * @private
 * @param {Buffer} msg
 * @param {Signature} S
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function _verify(msg, S, key) {
  // DSA Verification.
  //
  // [FIPS186] Page 19, Section 4.7.
  // [DSA] "Verifying a signature".
  //
  // Assumptions:
  //
  //   - Let `m` be an integer reduced from bytes.
  //   - Let `r` and `s` be signature elements.
  //   - Let `y` be a valid group element.
  //   - r != 0, r < q.
  //   - s != 0, s < q.
  //
  // Computation:
  //
  //   u1 = m / s mod q
  //   u2 = r / s mod q
  //   r' = g^u1 * y^u2 mod p
  //   r == r' mod q
  const k = key.size();

  if (S.r.length !== k)
    return false;

  if (S.s.length !== k)
    return false;

  if (!isSanePublicKey(key))
    return false;

  const p = BN.decode(key.p);
  const q = BN.decode(key.q);
  const g = BN.decode(key.g);
  const y = BN.decode(key.y);
  const r = BN.decode(S.r);
  const s = BN.decode(S.s);

  if (r.isZero() || r.cmp(q) >= 0)
    return false;

  if (s.isZero() || s.cmp(q) >= 0)
    return false;

  const m = reduce(msg, q);
  const si = s.invert(q);
  const u1 = m.imul(si).imod(q);
  const u2 = r.mul(si).imod(q);
  const e1 = g.powm(u1, p);
  const e2 = y.powm(u2, p);
  const re = e1.imul(e2).imod(p);

  return re.imod(q).eq(r);
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

  if (!isSanePublicKey(pub))
    throw new Error('Invalid DSA public key.');

  if (!isSanePrivateKey(priv))
    throw new Error('Invalid DSA private key.');

  const p0 = BN.decode(pub.p);
  const q0 = BN.decode(pub.q);
  const g0 = BN.decode(pub.g);
  const p = BN.decode(priv.p);
  const q = BN.decode(priv.q);
  const g = BN.decode(priv.g);

  if (!p0.eq(p) || !q0.eq(q) || !g0.eq(g))
    throw new Error('Incompatible DSA parameters.');

  const x = BN.decode(priv.x);
  const y = BN.decode(pub.y);

  if (y.powm(q, p).cmpn(1) !== 0)
    throw new Error('Invalid DSA public key.');

  const e = powConst(y, x, p, q);

  return e.encode('be', p.byteLength());
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

/**
 * Generate params from L and N.
 * @private
 * @param {Number} L
 * @param {Number} N
 * @returns {DSAParams}
 */

function generateParams(L, N) {
  // [FIPS186] Page 31, Appendix A.1.
  //           Page 41, Appendix A.2.
  // [DSA] "Parameter generation".
  assert((L >>> 0) === L);
  assert((N >>> 0) === N);

  if (!(L === 1024 && N === 160)
      && !(L === 2048 && N === 224)
      && !(L === 2048 && N === 256)
      && !(L === 3072 && N === 256)) {
    throw new Error('Invalid parameter sizes.');
  }

  if (L < MIN_BITS || L > MAX_BITS || (N & 7) !== 0)
    throw new Error('Invalid parameter sizes.');

  const qb = Buffer.alloc(N >>> 3);
  const pb = Buffer.alloc((L + 7) >>> 3);

  let q = null;
  let p = null;

generate:
  for (;;) {
    rng.randomFill(qb, 0, qb.length);

    qb[0] |= 0x80;
    qb[qb.length - 1] |= 1;

    q = BN.decode(qb);

    if (!probablyPrime(q, 64))
      continue;

    for (let i = 0; i < 4 * L; i++) {
      rng.randomFill(pb, 0, pb.length);

      pb[0] |= 0x80;
      pb[pb.length - 1] |= 1;

      p = BN.decode(pb);

      const rem = p.mod(q);
      rem.isubn(1);
      p.isub(rem);

      const bits = p.bitLength();

      if (bits < L || bits > MAX_BITS)
        continue;

      if (!probablyPrime(p, 64))
        continue;

      break generate;
    }
  }

  const h = new BN(2);
  const pm1 = p.subn(1);
  const e = pm1.div(q);

  for (;;) {
    const g = h.powm(e, p);

    if (g.cmpn(1) === 0) {
      h.iaddn(1);
      continue;
    }

    const params = new DSAParams();

    params.p = p.encode();
    params.q = q.encode();
    params.g = g.encode();

    return params;
  }
}

/*
 * Sanity Checking
 */

function isSaneParams(params) {
  assert(params instanceof DSAParams);

  const pb = countLeft(params.p);
  const qb = countLeft(params.q);
  const gb = countLeft(params.g);

  if (pb < MIN_BITS || pb > MAX_BITS)
    return false;

  if (qb !== 160 && qb !== 224 && qb !== 256)
    return false;

  if (gb < 2 || gb > pb)
    return false;

  if ((params.p[params.p.length - 1] & 1) === 0)
    return false;

  if ((params.q[params.q.length - 1] & 1) === 0)
    return false;

  if (compareLeft(params.g, sub1(params.p)) >= 0)
    return false;

  return true;
}

function isSanePublicKey(key) {
  assert(key instanceof DSAKey);

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
  assert(key instanceof DSAPrivateKey);

  if (!isSanePublicKey(key))
    return false;

  const qb = countLeft(key.q);
  const xb = countLeft(key.x);

  if (xb === 0 || xb > qb)
    return false;

  if (compareLeft(key.x, key.q) >= 0)
    return false;

  return true;
}

function isSaneCompute(key) {
  assert(key instanceof DSAPrivateKey);

  const pb = countLeft(key.p);
  const qb = countLeft(key.q);
  const gb = countLeft(key.g);
  const yb = countLeft(key.y);
  const xb = countLeft(key.x);

  if (pb < MIN_BITS || pb > MAX_BITS)
    return false;

  if (qb !== 160 && qb !== 224 && qb !== 256)
    return false;

  if (gb < 2 || gb > pb)
    return false;

  if ((key.p[key.p.length - 1] & 1) === 0)
    return false;

  if ((key.q[key.q.length - 1] & 1) === 0)
    return false;

  if (yb > pb)
    return false;

  if (xb === 0 || xb > qb)
    return false;

  if (compareLeft(key.g, sub1(key.p)) >= 0)
    return false;

  if (compareLeft(key.y, key.p) >= 0)
    return false;

  if (compareLeft(key.x, key.q) >= 0)
    return false;

  return true;
}

function needsCompute(key) {
  assert(key instanceof DSAPrivateKey);
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
 * Helpers
 */

function truncate(msg, q) {
  // Byte array to integer conversion.
  //
  // [FIPS186] Page 68, Appendix C.2.
  //
  // Note that the FIPS186 behavior
  // differs from OpenSSL's behavior.
  // We replicate OpenSSL which takes
  // the left-most ceil(log2(n)) bits
  // modulo `q`.
  assert(Buffer.isBuffer(msg));
  assert(q instanceof BN);

  const bits = q.bitLength();

  assert((bits & 7) === 0);

  const bytes = bits >>> 3;

  if (msg.length > bytes)
    msg = msg.slice(0, bytes);

  return BN.decode(msg);
}

function reduce(msg, q) {
  return truncate(msg, q).imod(q);
}

function powBlind(g, x, p, q, mont = false, size = null) {
  // Idea: exponentiate by scalar with a
  // blinding factor, similar to how we
  // blind multiplications in EC. Note
  // that it would be safer if we had the
  // blinding factor pregenerated for each
  // key.
  //
  // Computation:
  //
  //   b = random integer in [1,q-1]
  //   u = -b mod q
  //   k = (x + b) mod q
  //   e = g^k * g^u mod p
  //
  // In theory, we could also speed up
  // the calculation of `e` with a multi
  // exponentiation algorithm.
  assert(g instanceof BN);
  assert(x instanceof BN);
  assert(p instanceof BN);
  assert(q instanceof BN);

  const b = BN.random(rng, 1, q);
  const u = b.neg().imod(q);
  const k = x.add(b).imod(q);
  const e1 = g.powm(k, p, mont, size);
  const e2 = g.powm(u, p, mont, size);

  return e1.imul(e2).imod(p);
}

function powConst(g, x, p, q) {
  assert(q instanceof BN);
  return powBlind(g, x, p, q, true, q.bitLength());
}

function getBlinding(q) {
  assert(q instanceof BN);

  // Scalar blinding factor.
  const b = BN.random(rng, 1, q);
  const bi = b.fermat(q);

  return [b, bi];
}

/*
 * Expose
 */

exports.native = 0;
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
