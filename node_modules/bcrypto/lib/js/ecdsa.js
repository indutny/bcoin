/*!
 * ecdsa.js - ECDSA for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * References:
 *
 *   [SEC1] SEC 1: Elliptic Curve Cryptography, Version 2.0
 *     Certicom Research
 *     http://www.secg.org/sec1-v2.pdf
 *
 *   [FIPS186] Suite B Implementer's Guide to FIPS 186-3 (ECDSA)
 *     https://tinyurl.com/fips186-guide
 *
 *   [GECC] Guide to Elliptic Curve Cryptography
 *     D. Hankerson, A. Menezes, and S. Vanstone
 *     https://tinyurl.com/guide-to-ecc
 *
 *   [RFC6979] Deterministic Usage of the Digital Signature
 *             Algorithm (DSA) and Elliptic Curve Digital
 *             Signature Algorithm (ECDSA)
 *     T. Pornin
 *     https://tools.ietf.org/html/rfc6979
 *
 *   [RFC5915] Elliptic Curve Private Key Structure
 *     S. Turner, D. Brown
 *     https://tools.ietf.org/html/rfc5915
 *
 *   [RFC5480] Elliptic Curve Cryptography Subject Public Key Information
 *     S. Turner, D. Brown, K. Yiu, R. Housley, T. Polk
 *     https://tools.ietf.org/html/rfc5480
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const eckey = require('../internal/eckey');
const Signature = require('../internal/signature');
const asn1 = require('../encoding/asn1');
const sec1 = require('../encoding/sec1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const rng = require('../random');
const Schnorr = require('./schnorr-legacy');
const HmacDRBG = require('../hmac-drbg');
const elliptic = require('./elliptic');

/**
 * ECDSA
 */

class ECDSA {
  constructor(name, hash, pre) {
    assert(typeof name === 'string');
    assert(hash);

    this.id = name;
    this.type = 'ecdsa';
    this.hash = hash;
    this.native = 0;

    this._pre = pre || null;
    this._curve = null;
    this._schnorr = null;
  }

  get curve() {
    if (!this._curve) {
      this._curve = elliptic.curve(this.id, this._pre);
      this._curve.precompute(rng);
      this._pre = null;
    }
    return this._curve;
  }

  get schnorr() {
    if (!this._schnorr)
      this._schnorr = new Schnorr(this.curve, this.hash);
    return this._schnorr;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  privateKeyGenerate() {
    const a = this.curve.randomScalar(rng);
    return this.curve.encodeScalar(a);
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let a;
    try {
      a = this.curve.decodeScalar(key);
    } catch (e) {
      return false;
    }

    return !a.isZero() && a.cmp(this.curve.n) < 0;
  }

  privateKeyExport(key, compress) {
    // [RFC5915] Page 2, Section 3.
    const pub = this.publicKeyCreate(key, compress);
    return new sec1.ECPrivateKey(1, key, this.id, pub).encode();
  }

  privateKeyImport(raw) {
    // [RFC5915] Page 2, Section 3.
    const key = sec1.ECPrivateKey.decode(raw);
    const curve = key.namedCurveOID.toString();

    assert(key.version.toNumber() === 1);
    assert(curve === asn1.objects.curves[this.id]
        || curve === asn1.objects.NONE);

    const {value} = key.privateKey;

    if (value.length > this.curve.scalarSize)
      throw new Error('Invalid private key.');

    const a = BN.decode(value, this.curve.endian);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(a);
  }

  privateKeyExportPKCS8(key, compress) {
    // [RFC5915] Page 2, Section 3.
    const pub = this.publicKeyCreate(key, compress);
    const curve = asn1.objects.NONE;

    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.keyAlgs.ECDSA,
      new asn1.OID(asn1.objects.curves[this.id]),
      new sec1.ECPrivateKey(1, key, curve, pub).encode()
    ).encode();
  }

  privateKeyImportPKCS8(raw) {
    // [RFC5915] Page 2, Section 3.
    const pki = pkcs8.PrivateKeyInfo.decode(raw);
    const {algorithm, parameters} = pki.algorithm;

    assert(pki.version.toNumber() === 0);
    assert(algorithm.toString() === asn1.objects.keyAlgs.ECDSA);
    assert(parameters.node.type === asn1.types.OID);
    assert(parameters.node.toString() === asn1.objects.curves[this.id]);

    return this.privateKeyImport(pki.privateKey.value);
  }

  privateKeyExportJWK(key) {
    return eckey.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  privateKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.iadd(t).imod(this.curve.n);

    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(k);
  }

  privateKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.imul(t).imod(this.curve.n);

    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(k);
  }

  privateKeyReduce(key) {
    assert(Buffer.isBuffer(key));

    if (key.length > this.curve.scalarSize)
      key = key.slice(0, this.curve.scalarSize);

    const a = BN.decode(key, this.curve.endian).imod(this.curve.n);

    if (a.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(a);
  }

  privateKeyNegate(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.ineg().imod(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  privateKeyInvert(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.invert(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  publicKeyCreate(key, compress) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mulBlind(a);

    return A.encode(compress);
  }

  publicKeyConvert(key, compress) {
    const A = this.curve.decodePoint(key);
    return A.encode(compress);
  }

  publicKeyFromUniform(bytes, compress) {
    const u = this.curve.decodeUniform(bytes);
    const A = this.curve.pointFromUniform(u);

    return A.encode(compress);
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    const A = this.curve.decodePoint(key);
    const u = this.curve.pointToUniform(A, hint);

    return this.curve.encodeUniform(u, rng);
  }

  publicKeyFromHash(bytes, compress) {
    const A = this.curve.pointFromHash(bytes);
    return A.encode(compress);
  }

  publicKeyToHash(key) {
    const A = this.curve.decodePoint(key);
    return this.curve.pointToHash(A, rng);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyExport(key) {
    return this.publicKeyConvert(key, false).slice(1);
  }

  publicKeyImport(raw, compress) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.curve.fieldSize * 2);

    const key = Buffer.allocUnsafe(1 + raw.length);
    key[0] = 0x04;
    raw.copy(key, 1);

    return this.publicKeyConvert(key, compress);
  }

  publicKeyExportSPKI(key, compress) {
    // [RFC5480] Page 7, Section 2.2.
    return new x509.SubjectPublicKeyInfo(
      asn1.objects.keyAlgs.ECDSA,
      new asn1.OID(asn1.objects.curves[this.id]),
      this.publicKeyConvert(key, compress)
    ).encode();
  }

  publicKeyImportSPKI(raw, compress) {
    // [RFC5480] Page 7, Section 2.2.
    const spki = x509.SubjectPublicKeyInfo.decode(raw);
    const {algorithm, parameters} = spki.algorithm;

    assert(algorithm.toString() === asn1.objects.keyAlgs.ECDSA);
    assert(parameters.node.type === asn1.types.OID);
    assert(parameters.node.toString() === asn1.objects.curves[this.id]);

    return this.publicKeyConvert(spki.publicKey.rightAlign(), compress);
  }

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json, compress) {
    return eckey.publicKeyImportJWK(this, json, compress);
  }

  publicKeyTweakAdd(key, tweak, compress) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodePoint(key);
    const T = this.curve.g.jmul(t);
    const P = T.add(A);

    return P.encode(compress);
  }

  publicKeyTweakMul(key, tweak, compress) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodePoint(key);
    const P = A.mul(t);

    return P.encode(compress);
  }

  publicKeyAdd(key1, key2, compress) {
    const A1 = this.curve.decodePoint(key1);
    const A2 = this.curve.decodePoint(key2);
    const P = A1.add(A2);

    return P.encode(compress);
  }

  publicKeyCombine(keys, compress) {
    assert(Array.isArray(keys));

    let P = this.curve.jpoint();

    for (const key of keys) {
      const A = this.curve.decodePoint(key);

      P = P.add(A);
    }

    return P.encode(compress);
  }

  publicKeyNegate(key, compress) {
    const A = this.curve.decodePoint(key);
    const P = A.neg();

    return P.encode(compress);
  }

  signatureNormalize(raw) {
    const S = Signature.decode(raw, this.curve.scalarSize);

    this._signatureNormalize(S);

    return S.encode(this.curve.scalarSize);
  }

  signatureNormalizeDER(raw) {
    const S = Signature.fromDER(raw, this.curve.scalarSize);

    this._signatureNormalize(S);

    return S.toDER(this.curve.scalarSize);
  }

  _signatureNormalize(S) {
    const r = this.curve.decodeScalar(S.r);
    const s = this.curve.decodeScalar(S.s);

    if (r.isZero() || r.cmp(this.curve.n) >= 0)
      throw new Error('Invalid R value.');

    if (s.isZero() || s.cmp(this.curve.n) >= 0)
      throw new Error('Invalid S value.');

    if (s.cmp(this.curve.nh) > 0)
      S.s = this.curve.encodeScalar(s.ineg().imod(this.curve.n));

    return S;
  }

  signatureExport(sig) {
    return Signature.toDER(sig, this.curve.scalarSize);
  }

  signatureImport(sig) {
    return Signature.toRS(sig, this.curve.scalarSize);
  }

  isLowS(sig) {
    assert(Buffer.isBuffer(sig));

    if (sig.length !== this.curve.scalarSize * 2)
      return false;

    const S = Signature.decode(sig, this.curve.scalarSize);

    return this._isLowS(S);
  }

  isLowDER(sig) {
    assert(Buffer.isBuffer(sig));

    let S;
    try {
      S = Signature.fromDER(sig, this.curve.scalarSize);
    } catch (e) {
      return false;
    }

    return this._isLowS(S);
  }

  _isLowS(S) {
    const r = this.curve.decodeScalar(S.r);
    const s = this.curve.decodeScalar(S.s);

    if (r.isZero() || r.cmp(this.curve.n) >= 0)
      return false;

    if (s.isZero() || s.cmp(this.curve.n) >= 0)
      return false;

    return s.cmp(this.curve.nh) <= 0;
  }

  sign(msg, key) {
    const S = this._sign(msg, key);
    return S.encode(this.curve.scalarSize);
  }

  signRecoverable(msg, key) {
    const S = this._sign(msg, key);
    return [S.encode(this.curve.scalarSize), S.param];
  }

  signDER(msg, key) {
    const S = this._sign(msg, key);
    return S.toDER(this.curve.scalarSize);
  }

  signRecoverableDER(msg, key) {
    const S = this._sign(msg, key);
    return [S.toDER(this.curve.scalarSize), S.param];
  }

  _sign(msg, key) {
    // ECDSA Signing.
    //
    // [SEC1] Page 44, Section 4.1.3.
    // [GECC] Algorithm 4.29, Page 184, Section 4.4.1.
    // [RFC6979] Page 9, Section 2.4.
    // [RFC6979] Page 10, Section 3.2.
    //
    // Assumptions:
    //
    //   - Let `m` be an integer reduced from bytes.
    //   - Let `a` be a secret non-zero scalar.
    //   - Let `k` be a random non-zero scalar.
    //   - R != O, r != 0, s != 0.
    //
    // Computation:
    //
    //   k = random integer in [1,n-1]
    //   R = G * k
    //   r = x(R) mod n
    //   s = (r * a + m) / k mod n
    //   s = -s mod n, if s > n / 2
    //   S = (r, s)
    //
    // Note that `k` must remain secret,
    // otherwise an attacker can compute:
    //
    //   a = (s * k - m) / r mod n
    //
    // This means that if two signatures
    // share the same `r` value, an attacker
    // can compute:
    //
    //   k = (m1 - m2) / (+-s1 - +-s2) mod n
    //   a = (s1 * k - m1) / r mod n
    //
    // Assuming:
    //
    //   s1 = (r * a + m1) / k mod n
    //   s2 = (r * a + m2) / k mod n
    //
    // To mitigate this, `k` can be generated
    // deterministically using the HMAC-DRBG
    // construction described in [RFC6979].
    const {n, nh} = this.curve;
    const G = this.curve.g;
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(n) >= 0)
      throw new Error('Invalid private key.');

    const m = this._reduce(msg);
    const nonce = this.curve.encodeScalar(m);
    const drbg = new HmacDRBG(this.hash, key, nonce);

    for (;;) {
      const bytes = drbg.generate(this.curve.scalarSize);
      const k = this._truncate(bytes);

      if (k.isZero() || k.cmp(n) >= 0)
        continue;

      const R = G.mulBlind(k);

      if (R.isInfinity())
        continue;

      const x = R.getX();
      const r = x.mod(n);

      if (r.isZero())
        continue;

      const [b, bi] = this.curve.getBlinding();
      const ki = k.fermat(n);
      const ba = a.mul(b).imod(n);
      const bm = m.mul(b).imod(n);
      const sk = r.mul(ba).iadd(bm).imod(n);
      const s = sk.imul(ki).imod(n);

      s.imul(bi).imod(n);

      if (s.isZero())
        continue;

      let param = R.sign() | (!x.eq(r) << 1);

      if (s.cmp(nh) > 0) {
        s.ineg().imod(n);
        param ^= 1;
      }

      const S = new Signature();

      S.r = this.curve.encodeScalar(r);
      S.s = this.curve.encodeScalar(s);
      S.param = param;

      return S;
    }
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.curve.scalarSize * 2)
      return false;

    const S = Signature.decode(sig, this.curve.scalarSize);

    try {
      return this._verify(msg, S, key);
    } catch (e) {
      return false;
    }
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    let S;
    try {
      S = Signature.fromDER(sig, this.curve.scalarSize);
    } catch (e) {
      return false;
    }

    try {
      return this._verify(msg, S, key);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, S, key) {
    // ECDSA Verification.
    //
    // [SEC1] Page 46, Section 4.1.4.
    // [GECC] Algorithm 4.30, Page 184, Section 4.4.1.
    //
    // Assumptions:
    //
    //   - Let `m` be an integer reduced from bytes.
    //   - Let `r` and `s` be signature elements.
    //   - Let `A` be a valid group element.
    //   - r != 0, r < n.
    //   - s != 0, s < n.
    //   - R != O.
    //
    // Computation:
    //
    //   u1 = m / s mod n
    //   u2 = r / s mod n
    //   R = G * u1 + A * u2
    //   r == x(R) mod n
    //
    // Note that the signer can verify their
    // own signatures more efficiently with:
    //
    //   R = G * ((u1 + u2 * a) mod n)
    //
    // Furthermore, we can avoid affinization
    // of `R` by scaling `r` by `z^2` and
    // repeatedly adding `n * z^2` to it up
    // to a certain threshold.
    const {n} = this.curve;
    const G = this.curve.g;
    const m = this._reduce(msg);
    const A = this.curve.decodePoint(key);
    const r = this.curve.decodeScalar(S.r);
    const s = this.curve.decodeScalar(S.s);

    if (r.isZero() || r.cmp(n) >= 0)
      return false;

    if (s.isZero() || s.cmp(n) >= 0)
      return false;

    const si = s.invert(n);
    const u1 = m.imul(si).imod(n);
    const u2 = r.mul(si).imod(n);
    const R = G.jmulAdd(u1, A, u2);

    return R.eqXToP(r);
  }

  recover(msg, sig, param, compress) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert((param & 3) === param, 'The recovery param is more than two bits.');

    if (sig.length !== this.curve.scalarSize * 2)
      return null;

    const S = Signature.decode(sig, this.curve.scalarSize);

    let A;
    try {
      A = this._recover(msg, S, param);
    } catch (e) {
      return null;
    }

    return A.encode(compress);
  }

  recoverDER(msg, sig, param, compress) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert((param & 3) === param, 'The recovery param is more than two bits.');

    let S;
    try {
      S = Signature.fromDER(sig, this.curve.scalarSize);
    } catch (e) {
      return null;
    }

    let A;
    try {
      A = this._recover(msg, S, param);
    } catch (e) {
      return null;
    }

    return A.encode(compress);
  }

  _recover(msg, S, param) {
    // ECDSA Public Key Recovery.
    //
    // [SEC1] Page 47, Section 4.1.6.
    //
    // Assumptions:
    //
    //   - Let `m` be an integer reduced from bytes.
    //   - Let `r` and `s` be signature elements.
    //   - Let `i` be an integer in [0,3].
    //   - x^3 + a * x + b is square in F(p).
    //   - If i > 1 then r < (p mod n).
    //   - r != 0, r < n.
    //   - s != 0, s < n.
    //   - A != O.
    //
    // Computation:
    //
    //   x = r + n, if i > 1
    //     = r, otherwise
    //   R' = (x, sqrt(x^3 + a * x + b))
    //   R = -R', if i mod 2 == 1
    //     = +R', otherwise
    //   s1 = m / r mod n
    //   s2 = s / r mod n
    //   A = R * s2 - G * s1
    //
    // Note that this implementation will have
    // trouble on curves where `p / n > 1`.
    const {p, n} = this.curve;
    const G = this.curve.g;
    const m = this._reduce(msg);
    const r = this.curve.decodeScalar(S.r);
    const s = this.curve.decodeScalar(S.s);

    if (r.isZero() || r.cmp(n) >= 0)
      throw new Error('Invalid R value.');

    if (s.isZero() || s.cmp(n) >= 0)
      throw new Error('Invalid S value.');

    const sign = (param & 1) !== 0;
    const high = param >>> 1;

    let x = r;

    if (high) {
      if (x.cmp(p.mod(n)) >= 0)
        throw new Error('Invalid R value.');

      x = x.add(n);
    }

    const R = this.curve.pointFromX(x, sign);
    const ri = r.invert(n);
    const s1 = m.imul(ri).ineg().imod(n);
    const s2 = s.imul(ri).imod(n);
    const A = G.mulAdd(s1, R, s2);

    if (A.isInfinity())
      throw new Error('Invalid point.');

    return A;
  }

  derive(pub, priv, compress) {
    const A = this.curve.decodePoint(pub);
    const a = this.curve.decodeScalar(priv);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    if (this.curve.h.cmpn(1) > 0) {
      if (A.isSmall())
        throw new Error('Invalid point.');
    }

    const P = A.mulConst(a, rng);

    return P.encode(compress);
  }

  /*
   * Schnorr
   */

  schnorrSign(msg, key) {
    return this.schnorr.sign(msg, key);
  }

  schnorrVerify(msg, sig, key) {
    return this.schnorr.verify(msg, sig, key);
  }

  schnorrVerifyBatch(batch) {
    return this.schnorr.verifyBatch(batch);
  }

  /*
   * Helpers
   */

  _truncate(msg) {
    // Byte array to integer conversion.
    //
    // [SEC1] Step 5, Page 45, Section 4.1.3.
    // [FIPS186] Page 25, Section B.2.
    //
    // The two sources above disagree on this.
    //
    // FIPS186 simply modulos the entire byte
    // array by the order, whereas SEC1 takes
    // the left-most ceil(log2(n)) bits modulo
    // the order (and maybe does other stuff).
    //
    // Instead of trying to decipher all of
    // this nonsense, we simply replicate the
    // OpenSSL behavior (which, in actuality,
    // is more similar to the SEC1 behavior).
    assert(Buffer.isBuffer(msg));

    const bits = this.curve.n.bitLength();
    const bytes = (bits + 7) >>> 3;

    if (msg.length > bytes)
      msg = msg.slice(0, bytes);

    const m = BN.decode(msg, this.curve.endian);
    const d = msg.length * 8 - bits;

    if (d > 0)
      m.iushrn(d);

    return m;
  }

  _reduce(msg) {
    return this._truncate(msg).imod(this.curve.n);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
