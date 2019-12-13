/*!
 * util.js - encoding utils for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const ZERO = Buffer.alloc(1, 0x00);
const cache = [];

/*
 * Util
 */

function countLeft(data) {
  assert(Buffer.isBuffer(data));

  let i = 0;

  for (; i < data.length; i++) {
    if (data[i] !== 0x00)
      break;
  }

  let bits = (data.length - i) * 8;

  if (bits === 0)
    return 0;

  bits -= 8;

  let oct = data[i];

  while (oct) {
    bits += 1;
    oct >>>= 1;
  }

  return bits;
}

function countRight(data) {
  assert(Buffer.isBuffer(data));

  let i = data.length - 1;

  for (; i >= 0; i--) {
    if (data[i] !== 0x00)
      break;
  }

  let bits = (i + 1) * 8;

  if (bits === 0)
    return 0;

  bits -= 8;

  let oct = data[i];

  while (oct) {
    bits += 1;
    oct >>>= 1;
  }

  return bits;
}

function compareLeft(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  let xp = 0;
  let xl = x.length;
  let yp = 0;
  let yl = y.length;

  while (xl > 0 && x[xp] === 0)
    xp++, xl--;

  while (yl > 0 && y[yp] === 0)
    yp++, yl--;

  if (xl < yl)
    return -1;

  if (xl > yl)
    return 1;

  for (let i = 0; i < xl; i++) {
    if (x[xp + i] < y[yp + i])
      return -1;

    if (x[xp + i] > y[yp + i])
      return 1;
  }

  return 0;
}

function compareRight(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  let xl = x.length;
  let yl = y.length;

  while (xl > 0 && x[xl - 1] === 0)
    xl--;

  while (yl > 0 && y[yl - 1] === 0)
    yl--;

  if (xl < yl)
    return -1;

  if (xl > yl)
    return 1;

  for (let i = xl - 1; i >= 0; i--) {
    if (x[i] < y[i])
      return -1;

    if (x[i] > y[i])
      return 1;
  }

  return 0;
}

function trimLeft(data) {
  if (data == null)
    return ZERO;

  assert(Buffer.isBuffer(data));

  let i = 0;

  for (; i < data.length; i++) {
    if (data[i] !== 0x00)
      break;
  }

  if (i !== 0)
    data = data.slice(i);

  if (data.length === 0)
    return ZERO;

  return data;
}

function trimRight(data) {
  if (data == null)
    return ZERO;

  assert(Buffer.isBuffer(data));

  let i = data.length - 1;

  for (; i >= 0; i--) {
    if (data[i] !== 0x00)
      break;
  }

  if (i + 1 !== data.length)
    data = data.slice(0, i + 1);

  if (data.length === 0)
    return ZERO;

  return data;
}

function padLeft(data, size) {
  if (data == null)
    return getZero(size);

  assert(Buffer.isBuffer(data));
  assert((size >>> 0) === size);

  if (data.length > size)
    data = trimLeft(data);

  if (data.length > size)
    throw new RangeError(`Buffer expected to be ${size} bytes in size.`);

  if (data.length === size)
    return data;

  const out = Buffer.allocUnsafe(size);
  const pos = size - data.length;

  out.fill(0x00, 0, pos);
  data.copy(out, pos);

  return out;
}

function padRight(data, size) {
  if (data == null)
    return getZero(size);

  assert(Buffer.isBuffer(data));
  assert((size >>> 0) === size);

  if (data.length > size)
    data = trimRight(data);

  if (data.length > size)
    throw new RangeError(`Buffer expected to be ${size} bytes in size.`);

  if (data.length === size)
    return data;

  const out = Buffer.allocUnsafe(size);

  data.copy(out, 0);
  out.fill(0x00, data.length, size);

  return out;
}

/*
 * Helpers
 */

function getZero(size) {
  assert((size >>> 0) === size);
  assert(size <= 128);

  while (cache.length <= size)
    cache.push(null);

  let zero = cache[size];

  if (!zero) {
    zero = Buffer.alloc(size, 0x00);
    cache[size] = zero;
  }

  return zero;
}

/*
 * Expose
 */

exports.countLeft = countLeft;
exports.countRight = countRight;
exports.compareLeft = compareLeft;
exports.compareRight = compareRight;
exports.trimLeft = trimLeft;
exports.trimRight = trimRight;
exports.padLeft = padLeft;
exports.padRight = padRight;
