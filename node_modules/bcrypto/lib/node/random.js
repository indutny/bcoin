/*!
 * random.js - random number generator for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://wiki.openssl.org/index.php/Random_Numbers
 *   https://csrc.nist.gov/projects/random-bit-generation/
 *   http://www.pcg-random.org/posts/bounded-rands.html
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

function randomBytes(size) {
  return crypto.randomBytes(size);
}

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} data
 * @param {Number} [off=0]
 * @param {Number} [size=data.length-off]
 * @returns {Buffer}
 */

function randomFill(data, off, size) {
  return crypto.randomFillSync(data, off, size);
}

/**
 * Generate a random uint32.
 * @returns {Number}
 */

function randomInt() {
  return crypto.randomBytes(4).readUInt32LE(0);
}

/**
 * Generate a random uint32 within a range.
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

function randomRange(min, max) {
  assert((min >>> 0) === min);
  assert((max >>> 0) === max);
  assert(max >= min);

  const space = max - min;

  if (space === 0)
    return min;

  const top = -space >>> 0;
  const data = Buffer.allocUnsafe(4);

  let x, r;

  do {
    crypto.randomFillSync(data, 0, 4);

    x = 0;
    x += data[0];
    x += data[1] * 0x100;
    x += data[2] * 0x10000;
    x += data[3] * 0x1000000;

    r = x % space;
  } while (x - r > top);

  return r + min;
}

/*
 * Expose
 */

exports.native = 1;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
