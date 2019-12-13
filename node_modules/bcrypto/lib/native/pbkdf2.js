/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const backend = require('./binding');
const binding = backend.pbkdf2;

/**
 * Perform key derivation using PBKDF2.
 * @param {Function} hash
 * @param {Buffer} pass
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Buffer}
 */

function derive(hash, pass, salt, iter, len) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  assert(hash && typeof hash.id === 'string');

  backend.load();

  if (!binding.hasHash(hash.id))
    return fallback().derive(hash, pass, salt, iter, len);

  return binding.derive(hash.id, pass, salt, iter, len);
}

/**
 * Execute pbkdf2 asynchronously.
 * @param {Function} hash
 * @param {Buffer} pass
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Promise}
 */

async function deriveAsync(hash, pass, salt, iter, len) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  assert(hash && typeof hash.id === 'string');

  backend.load();

  if (!binding.hasHash(hash.id))
    return fallback().deriveAsync(hash, pass, salt, iter, len);

  return new Promise((resolve, reject) => {
    const cb = (err, key) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(key);
    };

    try {
      binding.deriveAsync(hash.id, pass, salt, iter, len, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/*
 * Helpers
 */

let fb = null;

function fallback() {
  if (!fb)
    fb = require('../js/pbkdf2');
  return fb;
}

/*
 * Expose
 */

exports.native = 2;
exports.derive = derive;
exports.deriveAsync = deriveAsync;
