/*!
 * dsaies.js - dsaies for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
 *   https://nacl.cr.yp.to/secretbox.html
 */

'use strict';

const assert = require('bsert');
const dsa = require('./dsa');
const random = require('./random');
const box = require('./secretbox');
const {padLeft} = require('./encoding/util');

/*
 * DSAIES
 */

function encrypt(kdf, msg, pub, priv = null) {
  assert(kdf != null);
  assert(Buffer.isBuffer(msg));
  assert(pub instanceof dsa.DSAKey);
  assert(priv == null || (priv instanceof dsa.DSAPrivateKey));

  if (priv == null)
    priv = dsa.privateKeyCreate(pub);

  const klen = (pub.bits() + 7) >>> 3;
  const ourPub = dsa.publicKeyCreate(priv);
  const secret = dsa.derive(pub, priv);
  const key = box.derive(secret, kdf);
  const nonce = random.randomBytes(24);
  const ourY = padLeft(ourPub.y, klen);
  const sealed = box.seal(msg, key, nonce);

  return Buffer.concat([ourY, nonce, sealed]);
}

function decrypt(kdf, msg, priv) {
  assert(kdf != null);
  assert(Buffer.isBuffer(msg));
  assert(priv instanceof dsa.DSAPrivateKey);

  const klen = (priv.bits() + 7) >>> 3;

  if (msg.length < klen + 24)
    throw new Error('Invalid ciphertext.');

  const theirY = msg.slice(0, klen);

  const theirPub = new dsa.DSAPublicKey(
    priv.p,
    priv.q,
    priv.g,
    theirY
  );

  const nonce = msg.slice(klen, klen + 24);
  const sealed = msg.slice(klen + 24);
  const secret = dsa.derive(theirPub, priv);
  const key = box.derive(secret, kdf);

  return box.open(sealed, key, nonce);
}

/*
 * Expose
 */

exports.encrypt = encrypt;
exports.decrypt = decrypt;
