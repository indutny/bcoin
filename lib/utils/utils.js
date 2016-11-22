/*!
 * utils.js - utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/* global gc */

/**
 * @exports utils
 */

var utils = exports;

var assert = require('assert');
var base58 = require('./base58');
var BN = require('bn.js');
var util = require('util');
var Number, Math, Date;
var fs, lazy;

/**
 * Reference to the global object.
 * @const {Object}
 */

utils.global = (function() {
  /* global self */

  if (this)
    return this;

  if (typeof window !== 'undefined')
    return window;

  if (typeof self !== 'undefined')
    return self;

  if (typeof global !== 'undefined')
    return global;
})();

/**
 * Whether we're in a browser or not.
 * @const {Boolean}
 */

utils.isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

if (!utils.isBrowser)
  fs = require('fs');

Number = utils.global.Number;
Math = utils.global.Math;
Date = utils.global.Date;

/**
 * The home directory.
 * @const {String}
 */

try {
  utils.HOME = require('os').homedir();
} catch (e) {
  utils.HOME = process.env.HOME
    || process.env.USERPROFILE
    || process.env.HOMEPATH
    || '/';
}

/**
 * Global NOP function.
 * @type function
 * @static
 * @method
 */

utils.nop = function() {};

/**
 * Garbage collector for `--expose-gc`.
 * @type function
 * @static
 * @method
 */

utils.gc = !utils.isBrowser && typeof gc === 'function' ? gc : utils.nop;

/**
 * Clone a buffer.
 * @param {Buffer} data
 * @returns {Buffer}
 */

utils.copy = function copy(data) {
  var clone = new Buffer(data.length);
  data.copy(clone, 0, 0, data.length);
  return clone;
};

/**
 * Concatenate two buffers.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Buffer}
 */

utils.concat = function concat(a, b) {
  var data = new Buffer(a.length + b.length);
  a.copy(data, 0);
  b.copy(data, a.length);
  return data;
};

/**
 * Encode a base58 string.
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 * @function
 * @param {Buffer} data
 * @returns {Base58String}
 */

utils.toBase58 = base58.toBase58;

/**
 * Decode a base58 string.
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 * @function
 * @param {Base58String} str
 * @returns {Buffer}
 * @throws on non-base58 character.
 */

utils.fromBase58 = base58.fromBase58;

/**
 * Test whether a string is base58 (note that you
 * may get a false positive on a hex string).
 * @param {String?} obj
 * @returns {Boolean}
 */

utils.isBase58 = function isBase58(obj) {
  return typeof obj === 'string' && /^[1-9a-zA-Z]+$/.test(obj);
};

/**
 * Return hrtime (shim for browser).
 * @param {Array} time
 * @returns {Array}
 */

utils.hrtime = function hrtime(time) {
  var now, ms, sec;

  if (utils.isBrowser) {
    now = utils.ms();
    if (time) {
      time = time[0] * 1000 + time[1] / 1e6;
      now -= time;
    }
    ms = now % 1000;
    sec = (now - ms) / 1000;
    return [sec, ms * 1e6];
  }

  if (time)
    return process.hrtime(time);

  return process.hrtime();
};

/**
 * Test whether a string is hex. Note that this
 * _could_ yield a false positive on base58
 * strings.
 * @param {String?} obj
 * @returns {Boolean}
 */

utils.isHex = function isHex(obj) {
  return typeof obj === 'string'
    && /^[0-9a-f]+$/i.test(obj)
    && obj.length % 2 === 0;
};

/**
 * Test whether two buffers are equal.
 * @param {Buffer?} a
 * @param {Buffer?} b
 * @returns {Boolean}
 */

utils.equal = function equal(a, b) {
  var i;

  if (!Buffer.isBuffer(a))
    return false;

  if (!Buffer.isBuffer(b))
    return false;

  if (a.compare)
    return a.compare(b) === 0;

  if (a.length !== b.length)
    return false;

  for (i = 0; i < a.length; i++) {
    if (a[i] !== b[i])
      return false;
  }

  return true;
};

/**
 * Call `setImmediate`, `process.nextTick`,
 * or `setInterval` depending.
 * @name nextTick
 * @function
 * @returns {Promise}
 */

if (utils.isBrowser)
  require('../../vendor/setimmediate');

if (typeof setImmediate === 'function') {
  utils.nextTick = setImmediate;
} else if (!utils.isBrowser) {
  utils.nextTick = process.nextTick;
} else {
  utils.nextTick = function nextTick(fn) {
    setTimeout(fn, 1);
  };
}

/**
 * Reverse a hex-string (used because of
 * bitcoind's affinity for uint256le).
 * @param {String} data - Hex string.
 * @returns {String} Reversed hex string.
 */

utils.revHex = function revHex(data) {
  var out = '';
  var i;

  assert(typeof data === 'string');

  for (i = 0; i < data.length; i += 2)
    out = data.slice(i, i + 2) + out;

  return out;
};

/**
 * Shallow merge between multiple objects.
 * @param {Object} target
 * @param {...Object} args
 * @returns {Object} target
 */

utils.merge = function merge(target) {
  var i, j, obj, keys, key;

  for (i = 1; i < arguments.length; i++) {
    obj = arguments[i];
    keys = Object.keys(obj);
    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      target[key] = obj[key];
    }
  }

  return target;
};

if (Object.assign)
  utils.merge = Object.assign;

/**
 * Safely convert satoshis to a BTC string.
 * This function explicitly avoids any
 * floating point arithmetic.
 * @param {Amount} value - Satoshis.
 * @returns {String} BTC string.
 */

utils.btc = function btc(value) {
  var negative = false;
  var hi, lo, result;

  if (utils.isFloat(value))
    return value;

  assert(utils.isInt(value), 'Non-satoshi value for conversion.');

  if (value < 0) {
    value = -value;
    negative = true;
  }

  assert(value <= utils.MAX_SAFE_INTEGER, 'Number exceeds 2^53-1.');

  value = value.toString(10);

  assert(value.length <= 16, 'Number exceeds 2^53-1.');

  while (value.length < 9)
    value = '0' + value;

  hi = value.slice(0, -8);
  lo = value.slice(-8);

  lo = lo.replace(/0+$/, '');

  if (lo.length === 0)
    lo += '0';

  result = hi + '.' + lo;

  if (negative)
    result = '-' + result;

  return result;
};

/**
 * Safely convert a BTC string to satoshis.
 * This function explicitly avoids any
 * floating point arithmetic. It also does
 * extra validation to ensure the resulting
 * Number will be 53 bits or less.
 * @param {String} value - BTC
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

utils.satoshi = function satoshi(value) {
  var negative = false;
  var parts, hi, lo, result;

  if (utils.isInt(value))
    return value;

  assert(utils.isFloat(value), 'Non-BTC value for conversion.');

  if (value[0] === '-') {
    negative = true;
    value = value.substring(1);
  }

  parts = value.split('.');

  assert(parts.length <= 2, 'Bad decimal point.');

  hi = parts[0] || '0';
  lo = parts[1] || '0';

  hi = hi.replace(/^0+/, '');
  lo = lo.replace(/0+$/, '');

  assert(hi.length <= 8, 'Number exceeds 2^53-1.');
  assert(lo.length <= 8, 'Too many decimal places.');

  if (hi.length === 0)
    hi = '0';

  while (lo.length < 8)
    lo += '0';

  hi = parseInt(hi, 10);
  lo = parseInt(lo, 10);

  assert(hi < 90071992 || (hi === 90071992 && lo <= 54740991),
    'Number exceeds 2^53-1.');

  result = hi * 100000000 + lo;

  if (negative)
    result = -result;

  return result;
};

/**
 * Test whether a number is below MAX_SAFE_INTEGER.
 * @param {Number} value
 * @returns {Boolean}
 */

utils.isSafeInteger = function isSafeInteger(value) {
  if (Number.isSafeInteger)
    return Number.isSafeInteger(value);
  return Math.abs(value) <= utils.MAX_SAFE_INTEGER;
};

/**
 * Test whether a number is Number,
 * finite, and below MAX_SAFE_INTEGER.
 * @param {Number?} value
 * @returns {Boolean}
 */

utils.isNumber = function isNumber(value) {
  return typeof value === 'number'
    && isFinite(value)
    && utils.isSafeInteger(value);
};

/**
 * Test whether an object is an int.
 * @param {Number?} value
 * @returns {Boolean}
 */

utils.isInt = function isInt(value) {
  return utils.isNumber(value) && value % 1 === 0;
};

/**
 * Test whether an object is an int32.
 * @param {Number?} value
 * @returns {Boolean}
 */

utils.isInt32 = function isInt32(value) {
  return utils.isInt(value) && Math.abs(value) <= 0x7fffffff;
};

/**
 * Test whether an object is a uint32.
 * @param {Number?} value
 * @returns {Boolean}
 */

utils.isUInt32 = function isUInt32(value) {
  return utils.isInt(value) && value >= 0 && value <= 0xffffffff;
};

/**
 * Test whether an object is a 160 bit hash (hex string).
 * @param {String?} value
 * @returns {Boolean}
 */

utils.isHex160 = function isHex160(hash) {
  return utils.isHex(hash) && hash.length === 40;
};

/**
 * Test whether an object is a 256 bit hash (hex string).
 * @param {String?} value
 * @returns {Boolean}
 */

utils.isHex256 = function isHex256(hash) {
  return utils.isHex(hash) && hash.length === 64;
};

/**
 * Test whether a string qualifies as a float.
 * @param {String?} value
 * @returns {Boolean}
 */

utils.isFloat = function isFloat(value) {
  return typeof value === 'string'
    && /^-?(\d+)?(?:\.\d*)?$/.test(value)
    && value.length !== 0
    && value !== '-';
};

/**
 * Test and validate a satoshi value (Number).
 * @param {Number?} value
 * @returns {Boolean}
 */

utils.isSatoshi = function isSatoshi(value) {
  try {
    utils.satoshi(value);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Test and validate a BTC string.
 * @param {String?} value
 * @returns {Boolean}
 */

utils.isBTC = function isBTC(value) {
  try {
    utils.btc(value);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * util.inspect() with 20 levels of depth.
 * @param {Object|String} obj
 * @param {Boolean?} color
 * @return {String}
 */

utils.inspectify = function inspectify(obj, color) {
  return typeof obj !== 'string'
    ? util.inspect(obj, null, 20, color !== false)
    : obj;
};

/**
 * Format a string.
 * @function
 */

utils.fmt = util.format;

/**
 * Format a string.
 * @param {Array} args
 * @param {Boolean?} color
 * @return {String}
 */

utils.format = function format(args, color) {
  color = color
    ? (process.stdout ? process.stdout.isTTY : false)
    : false;

  return typeof args[0] === 'object'
    ? utils.inspectify(args[0], color)
    : util.format.apply(util, args);
};

/**
 * Write a message to stdout (console in browser).
 * @param {Object|String} obj
 * @param {...String} args
 */

utils.log = function log() {
  var args = new Array(arguments.length);
  var i, msg;

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  if (utils.isBrowser) {
    msg = typeof args[0] !== 'object'
      ? utils.format(args, false)
      : args[0];
    console.log(msg);
    return;
  }

  msg = utils.format(args, true);
  process.stdout.write(msg + '\n');
};

/**
 * Write a message to stderr (console in browser).
 * @param {Object|String} obj
 * @param {...String} args
 */

utils.error = function error() {
  var args = new Array(arguments.length);
  var i, msg;

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  if (utils.isBrowser) {
    msg = typeof args[0] !== 'object'
      ? utils.format(args, false)
      : args[0];
    console.error(msg);
    return;
  }

  msg = utils.format(args, true);
  process.stderr.write(msg + '\n');
};

/**
 * Sort public keys lexicographically.
 * @param {Buffer[]} keys
 * @returns {Buffer[]} Sorted keys.
 */

utils.sortKeys = function sortKeys(keys) {
  return keys.slice().sort(function(a, b) {
    return utils.cmp(a, b);
  });
};

/**
 * Unique-ify an array of strings.
 * @param {String[]} obj
 * @returns {String[]}
 */

utils.uniq = function uniq(obj) {
  var table = {};
  var out = [];
  var i = 0;

  for (; i < obj.length; i++) {
    if (!table[obj[i]]) {
      out.push(obj[i]);
      table[obj[i]] = true;
    }
  }

  return out;
};

/**
 * Convert a compact number to a big number.
 * Used for `block.bits` -> `target` conversion.
 * @param {Number} compact
 * @returns {BN}
 */

utils.fromCompact = function fromCompact(compact) {
  var exponent = compact >>> 24;
  var negative = (compact >>> 23) & 1;
  var mantissa = compact & 0x7fffff;
  var num;

  if (compact === 0)
    return new BN(0);

  // Logic ported from btcd since
  // the bitcoind code is a nightmare.
  if (exponent <= 3) {
    mantissa >>>= 8 * (3 - exponent);
    num = new BN(mantissa);
  } else {
    num = new BN(mantissa);
    num.iushln(8 * (exponent - 3));
  }

  if (negative)
    num.ineg();

  return num;
};

/**
 * Convert a big number to a compact number.
 * Used for `target` -> `block.bits` conversion.
 * @param {BN} num
 * @returns {Number}
 */

utils.toCompact = function toCompact(num) {
  var mantissa, exponent, compact;

  if (num.cmpn(0) === 0)
    return 0;

  exponent = num.byteLength();

  // Logic ported from btcd since
  // the bitcoind code is a nightmare.
  if (exponent <= 3) {
    mantissa = num.toNumber();
    mantissa <<= 8 * (3 - exponent);
  } else {
    mantissa = num.ushrn(8 * (exponent - 3)).toNumber();
  }

  if (mantissa & 0x800000) {
    mantissa >>= 8;
    exponent++;
  }

  compact = (exponent << 24) | mantissa;

  if (num.isNeg())
    compact |= 0x800000;

  compact >>>= 0;

  return compact;
};

/**
 * Test hash against a target.
 * @param {Buffer|Hash} hash
 * @param {BN|Number} target - Compact number or big number.
 * @returns {Boolean} True if hash is less than target.
 */

utils.testTarget = function testTarget(hash, target) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  if (typeof target === 'number')
    target = utils.fromCompact(target);

  if (target.isNeg() || target.cmpn(0) === 0)
    return false;

  hash = new BN(hash, 'le');

  if (hash.cmp(target) > 0)
    return false;

  return true;
};

/**
 * Get current time in unix time (seconds).
 * @returns {Number}
 */

utils.now = function now() {
  return Math.floor(utils.ms() / 1000);
};

/**
 * Get current time in unix time (milliseconds).
 * @returns {Number}
 */

utils.ms = function ms() {
  if (Date.now)
    return Date.now();
  return +new Date();
};

/**
 * Create a Date ISO string from time in unix time (seconds).
 * @param {Number?} ts - Seconds in unix time.
 * @returns {String}
 */

utils.date = function date(ts) {
  if (ts == null)
    ts = utils.now();

  return new Date(ts * 1000).toISOString().slice(0, -5) + 'Z';
};

/**
 * Get unix seconds from a Date string.
 * @param {String} date - Date ISO String.
 * @returns {Number}
 */

utils.time = function time(date) {
  if (date == null)
    return utils.now();

  return new Date(date) / 1000 | 0;
};

/**
 * UINT32_MAX
 * @const {BN}
 */

utils.U32 = new BN(0xffffffff);

/**
 * UINT64_MAX
 * @const {BN}
 */

utils.U64 = new BN('ffffffffffffffff', 'hex');

/**
 * Create a 64 bit nonce.
 * @returns {BN}
 */

utils.nonce = function _nonce(buffer) {
  var nonce = new Buffer(8);

  nonce.writeUInt32LE((Math.random() * 0x100000000) >>> 0, 0, true);
  nonce.writeUInt32LE((Math.random() * 0x100000000) >>> 0, 4, true);

  if (buffer)
    return nonce;

  return new BN(nonce);
};

/**
 * Read uint64le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

utils.readU64 = function readU64(data, off) {
  var num;
  off = off >>> 0;
  num = data.slice(off, off + 8);
  return new BN(num, 'le');
};

/**
 * Read uint64be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

utils.readU64BE = function readU64BE(data, off) {
  var num;
  off = off >>> 0;
  num = data.slice(off, off + 8);
  return new BN(num, 'be');
};

/**
 * Read int64le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

utils.read64 = function read64(data, off) {
  var num;

  off = off >>> 0;

  num = data.slice(off, off + 8);

  if (num[num.length - 1] & 0x80)
    return new BN(num, 'le').notn(64).addn(1).neg();

  return new BN(num, 'le');
};

/**
 * Read int64be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

utils.read64BE = function read64BE(data, off) {
  var num;

  off = off >>> 0;

  num = data.slice(off, off + 8);

  if (num[0] & 0x80)
    return new BN(num, 'be').notn(64).addn(1).neg();

  return new BN(num, 'be');
};

/**
 * Write uint64le.
 * @param {BN|Number} value
 */

utils.writeU64 = function writeU64(dst, num, off) {
  return utils.write64(dst, num, off);
};

/**
 * Write uint64be.
 * @param {BN|Number} value
 */

utils.writeU64BE = function writeU64BE(dst, num, off) {
  return utils.write64BE(dst, num, off);
};

/**
 * Write a javascript number as a uint64le (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.writeU64N = function writeU64N(dst, num, off) {
  return utils.write64N(dst, num, off);
};

/**
 * Write a javascript number as a uint64be (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.writeU64NBE = function writeU64NBE(dst, num, off) {
  return utils.write64NBE(dst, num, off);
};

/**
 * Max safe integer (53 bits).
 * @const {Number}
 * @default
 */

utils.MAX_SAFE_INTEGER = 0x1fffffffffffff;

/**
 * Max 52 bit integer (safe for additions).
 * `(MAX_SAFE_INTEGER - 1) / 2`
 * @const {Number}
 * @default
 */

utils.MAX_SAFE_ADDITION = 0xfffffffffffff;

/**
 * Write a javascript number as an int64le (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.write64N = function write64N(dst, num, off, be) {
  var negative, hi, lo;

  assert(typeof num === 'number');

  off = off >>> 0;

  negative = num < 0;

  if (negative) {
    num = -num;
    num -= 1;
  }

  assert(num <= utils.MAX_SAFE_INTEGER, 'Number exceeds 2^53-1');

  lo = num % 0x100000000;
  hi = (num - lo) / 0x100000000;

  if (negative) {
    hi = ~hi >>> 0;
    lo = ~lo >>> 0;
  }

  if (be) {
    dst[off + 0] = (hi >>> 24) & 0xff;
    dst[off + 1] = (hi >>> 16) & 0xff;
    dst[off + 2] = (hi >>> 8) & 0xff;
    dst[off + 3] = (hi >>> 0) & 0xff;
    dst[off + 4] = (lo >>> 24) & 0xff;
    dst[off + 5] = (lo >>> 16) & 0xff;
    dst[off + 6] = (lo >>> 8) & 0xff;
    dst[off + 7] = (lo >>> 0) & 0xff;
  } else {
    dst[off + 0] = (lo >>> 0) & 0xff;
    dst[off + 1] = (lo >>> 8) & 0xff;
    dst[off + 2] = (lo >>> 16) & 0xff;
    dst[off + 3] = (lo >>> 24) & 0xff;
    dst[off + 4] = (hi >>> 0) & 0xff;
    dst[off + 5] = (hi >>> 8) & 0xff;
    dst[off + 6] = (hi >>> 16) & 0xff;
    dst[off + 7] = (hi >>> 24) & 0xff;
  }

  return off + 8;
};

/**
 * Write a javascript number as an int64be (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.write64NBE = function write64NBE(dst, num, off) {
  return utils.write64N(dst, num, off, true);
};

/**
 * Read uint64le as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.readU64N = function readU64N(data, off, force53, be) {
  var hi, lo;

  off = off >>> 0;

  if (be) {
    hi = data.readUInt32BE(off, true);
    lo = data.readUInt32BE(off + 4, true);
  } else {
    hi = data.readUInt32LE(off + 4, true);
    lo = data.readUInt32LE(off, true);
  }

  if (force53)
    hi &= 0x1fffff;

  assert((hi & 0xffe00000) === 0, 'Number exceeds 2^53-1');

  return (hi * 0x100000000) + lo;
};

/**
 * Read uint64be as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.readU64NBE = function readU64NBE(data, off, force53) {
  return utils.readU64N(data, off, force53, true);
};

/**
 * Read int64le as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.read64N = function read64N(data, off, force53, be) {
  var hi, lo;

  off = off >>> 0;

  if (be) {
    hi = data.readUInt32BE(off, true);
    lo = data.readUInt32BE(off + 4, true);
  } else {
    hi = data.readUInt32LE(off + 4, true);
    lo = data.readUInt32LE(off, true);
  }

  if (hi & 0x80000000) {
    hi = ~hi >>> 0;
    lo = ~lo >>> 0;

    if (force53)
      hi &= 0x1fffff;

    assert((hi & 0xffe00000) === 0, 'Number exceeds 2^53-1');

    return -(hi * 0x100000000 + lo + 1);
  }

  if (force53)
    hi &= 0x1fffff;

  assert((hi & 0xffe00000) === 0, 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
};

/**
 * Read int64be as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.read64NBE = function read64NBE(data, off, force53) {
  return utils.read64N(data, off, force53, true);
};

/**
 * Write int64le.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write64 = function write64(dst, num, off) {
  var i;

  if (typeof num === 'number')
    return utils.write64N(dst, num, off);

  off = off >>> 0;

  if (num.isNeg())
    num = num.neg().inotn(64).iaddn(1);

  if (num.bitLength() > 64)
    num = num.uand(utils.U64);

  num = num.toArray('le', 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i];

  return off;
};

/**
 * Write int64be.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write64BE = function write64BE(dst, num, off) {
  var i;

  if (typeof num === 'number')
    return utils.write64NBE(dst, num, off);

  off = off >>> 0;

  if (num.isNeg())
    num = num.neg().inotn(64).iaddn(1);

  if (num.bitLength() > 64)
    num = num.uand(utils.U64);

  num = num.toArray('be', 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i];

  return off;
};

/**
 * Read a varint.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean?} big - Whether to read as a big number.
 * @returns {Object}
 */

utils.readVarint = function readVarint(data, off, big) {
  var value, size;

  off = off >>> 0;

  assert(off < data.length);

  switch (data[off]) {
    case 0xff:
      size = 9;
      assert(off + size <= data.length);
      if (big) {
        value = utils.readU64(data, off + 1);
        assert(value.bitLength() > 32);
      } else {
        value = utils.readU64N(data, off + 1);
        assert(value > 0xffffffff);
      }
      break;
    case 0xfe:
      size = 5;
      assert(off + size <= data.length);
      value = data.readUInt32LE(off + 1, true);
      assert(value > 0xffff);
      if (big)
        value = new BN(value);
      break;
    case 0xfd:
      size = 3;
      assert(off + size <= data.length);
      value = data[off + 1] | (data[off + 2] << 8);
      assert(value >= 0xfd);
      if (big)
        value = new BN(value);
      break;
    default:
      size = 1;
      value = data[off];
      if (big)
        value = new BN(value);
      break;
  }

  return { size: size, value: value };
};

/**
 * Write a varint.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.writeVarint = function writeVarint(dst, num, off) {
  off = off >>> 0;

  if (BN.isBN(num)) {
    if (num.bitLength() > 32) {
      dst[off] = 0xff;
      utils.writeU64(dst, num, off + 1);
      return off + 9;
    }
    num = num.toNumber();
  }

  num = +num;

  if (num < 0xfd) {
    dst[off] = num & 0xff;
    return off + 1;
  }

  if (num <= 0xffff) {
    dst[off] = 0xfd;
    dst[off + 1] = num & 0xff;
    dst[off + 2] = (num >>> 8) & 0xff;
    return off + 3;
  }

  if (num <= 0xffffffff) {
    dst[off] = 0xfe;
    dst[off + 1] = num & 0xff;
    dst[off + 2] = (num >>> 8) & 0xff;
    dst[off + 3] = (num >>> 16) & 0xff;
    dst[off + 4] = (num >>> 24) & 0xff;
    return off + 5;
  }

  dst[off] = 0xff;
  utils.writeU64N(dst, num, off + 1);

  return off + 9;
};

/**
 * Calculate size of varint.
 * @param {BN|Number} num
 * @returns {Number} size
 */

utils.sizeVarint = function sizeVarint(num) {
  if (BN.isBN(num)) {
    if (num.bitLength() > 32)
      return 9;
    num = num.toNumber();
  }

  if (num < 0xfd)
    return 1;

  if (num <= 0xffff)
    return 3;

  if (num <= 0xffffffff)
    return 5;

  return 9;
};

/**
 * Read a varint (type 2).
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean?} big - Whether to read as a big number.
 * @returns {Object}
 */

utils.readVarint2 = function readVarint2(data, off, big) {
  var num = 0;
  var size = 0;
  var bnum, ch;

  off = off >>> 0;

  for (;;) {
    assert(off < data.length);

    ch = data[off++];
    size++;

    if (num >= 0x3fffffffffff) {
      assert(big, 'Number exceeds 2^53-1.');
      bnum = new BN(num);
      num = 0;
    }

    if (bnum) {
      assert(bnum.bitLength() <= 256);
      bnum.iushln(7).iaddn(ch & 0x7f);
      if ((ch & 0x80) === 0)
        break;
      bnum.iaddn(1);
      continue;
    }

    num = (num * 0x80) + (ch & 0x7f);
    if ((ch & 0x80) === 0)
      break;
    num++;
  }

  if (bnum)
    return { size: size, value: bnum };

  if (big)
    num = new BN(num);

  return { size: size, value: num };
};

/**
 * Write a varint (type 2).
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.writeVarint2 = function writeVarint2(dst, num, off) {
  var tmp = [];
  var len = 0;

  if (BN.isBN(num)) {
    if (num.bitLength() > 53) {
      for (;;) {
        tmp[len] = (num.words[0] & 0x7f) | (len ? 0x80 : 0x00);
        if (num.cmpn(0x7f) <= 0)
          break;
        num.iushrn(7).isubn(1);
        len++;
      }

      assert(off + len <= dst.length);

      do {
        dst[off++] = tmp[len];
      } while (len--);

      return off;
    }

    num = num.toNumber();
  }

  off = off >>> 0;
  num = +num;

  for (;;) {
    tmp[len] = (num & 0x7f) | (len ? 0x80 : 0x00);
    if (num <= 0x7f)
      break;
    num = ((num - (num % 0x80)) / 0x80) - 1;
    len++;
  }

  assert(off + len <= dst.length);

  do {
    dst[off++] = tmp[len];
  } while (len--);

  return off;
};

/**
 * Calculate size of varint (type 2).
 * @param {BN|Number} num
 * @returns {Number} size
 */

utils.sizeVarint2 = function sizeVarint2(num) {
  var size = 0;

  if (BN.isBN(num)) {
    if (num.bitLength() > 53) {
      num = num.clone();

      for (;;) {
        size++;
        if (num.cmpn(0x7f) <= 0)
          break;
        num.iushrn(7).isubn(1);
      }

      return size;
    }

    num = num.toNumber();
  }

  num = +num;

  for (;;) {
    size++;
    if (num <= 0x7f)
      break;
    num = ((num - (num % 0x80)) / 0x80) - 1;
  }

  return size;
};

/**
 * Test whether a buffer is all zeroes.
 * @param {Buffer} data
 * @returns {Boolean}
 */

utils.isZero = function isZero(data) {
  var i;

  assert(Buffer.isBuffer(data));

  for (i = 0; i < data.length; i++) {
    if (data[i] !== 0)
      return false;
  }

  return true;
};

/**
 * String comparator (memcmp + length comparison).
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Number} -1, 1, or 0.
 */

utils.strcmp = function strcmp(a, b) {
  var len = Math.min(a.length, b.length);
  var i;

  for (i = 0; i < len; i++) {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }

  if (a.length < b.length)
    return -1;

  if (a.length > b.length)
    return 1;

  return 0;
};

/**
 * Buffer comparator (memcmp + length comparison).
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Number} -1, 1, or 0.
 */

utils.cmp = function cmp(a, b) {
  return a.compare(b);
};

// Warning: polymorphism.
if (!Buffer.prototype.compare)
  utils.cmp = utils.strcmp;

/**
 * Memcmp for comparing a needle to a haystack.
 * @param {Buffer} target - Haystack.
 * @param {Buffer} data - Needle.
 * @param {Number} start - Index in haystack to begin the comparison.
 * @returns {Number} -1, 1, or 0.
 */

utils.icmp = function icmp(target, data, start) {
  var i, a, b;

  if (target.length - start < data.length)
    return -1;

  for (i = 0; i < data.length; i++) {
    a = target[i + start];
    b = data[i];
    if (a < b)
      return -1;
    if (a > b)
      return 1;
  }

  return 0;
};

/**
 * Convert bytes to mb.
 * @param {Number} size
 * @returns {Number} mb
 */

utils.mb = function mb(size) {
  return size / 1024 / 1024 | 0;
};

/**
 * Inheritance.
 * @param {Function} obj - Constructor to inherit.
 * @param {Function} from - Parent constructor.
 */

utils.inherits = function inherits(obj, from) {
  var f;

  obj.super_ = from;

  if (Object.setPrototypeOf) {
    Object.setPrototypeOf(obj.prototype, from.prototype);
    Object.defineProperty(obj.prototype, 'constructor', {
      value: obj,
      enumerable: false
    });
    return;
  }

  if (Object.create) {
    obj.prototype = Object.create(from.prototype, {
      constructor: {
        value: obj,
        enumerable: false
      }
    });
    return;
  }

  f = function() {};
  f.prototype = from.prototype;
  obj.prototype = new f;
  obj.prototype.constructor = obj;
};

/**
 * Find index of a buffer in an array of buffers.
 * @param {Buffer[]} obj
 * @param {Buffer} data - Target buffer to find.
 * @returns {Number} Index (-1 if not found).
 */

utils.indexOf = function indexOf(obj, data) {
  var i;

  assert(Array.isArray(obj));
  assert(Buffer.isBuffer(data));

  for (i = 0; i < obj.length; i++) {
    if (!Buffer.isBuffer(obj[i]))
      continue;
    if (utils.equal(obj[i], data))
      return i;
  }

  return -1;
};

/**
 * Convert a number to a padded uint32
 * string (10 digits in decimal).
 * @param {Number} num
 * @returns {String} Padded number.
 */

utils.pad32 = function pad32(num) {
  assert(num >= 0);
  num = num + '';
  switch (num.length) {
    case 1:
      return '000000000' + num;
    case 2:
      return '00000000' + num;
    case 3:
      return '0000000' + num;
    case 4:
      return '000000' + num;
    case 5:
      return '00000' + num;
    case 6:
      return '0000' + num;
    case 7:
      return '000' + num;
    case 8:
      return '00' + num;
    case 9:
      return '0' + num;
    case 10:
      return num;
    default:
      assert(false);
  }
};

/**
 * Convert a number to a padded uint32
 * string (8 digits in hex).
 * @param {Number} num
 * @returns {String} Padded number.
 */

utils.hex32 = function hex32(num) {
  assert(num >= 0);
  num = num.toString(16);
  switch (num.length) {
    case 1:
      return '0000000' + num;
    case 2:
      return '000000' + num;
    case 3:
      return '00000' + num;
    case 4:
      return '0000' + num;
    case 5:
      return '000' + num;
    case 6:
      return '00' + num;
    case 7:
      return '0' + num;
    case 8:
      return num;
    default:
      assert(false);
  }
};

/**
 * Convert an array to a map.
 * @param {String[]} obj
 * @returns {Object} Map.
 */

utils.toMap = function toMap(obj) {
  var map = {};
  var i, value;

  for (i = 0; i < obj.length; i++) {
    value = obj[i];
    map[value] = true;
  }

  return map;
};

/**
 * Reverse a map.
 * @param {Object} map
 * @returns {Object} Reversed map.
 */

utils.revMap = function revMap(map) {
  var reversed = {};
  var keys = Object.keys(map);
  var i, key;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    reversed[map[key]] = key;
  }

  return reversed;
};

/**
 * Get object values.
 * @param {Object} map
 * @returns {Array} Values.
 */

utils.values = function values(map) {
  var keys = Object.keys(map);
  var out = [];
  var i, key;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    out.push(map[key]);
  }

  return out;
};

/**
 * Perform a binary search on a sorted array.
 * @param {Array} items
 * @param {Object} key
 * @param {Function} compare
 * @param {Boolean?} insert
 * @returns {Number} Index.
 */

utils.binarySearch = function binarySearch(items, key, compare, insert) {
  var start = 0;
  var end = items.length - 1;
  var pos, cmp;

  while (start <= end) {
    pos = (start + end) >>> 1;
    cmp = compare(items[pos], key);

    if (cmp === 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (!insert)
    return -1;

  return start;
};

/**
 * Perform a binary insert on a sorted array.
 * @param {Array} items
 * @param {Object} item
 * @param {Function} compare
 * @returns {Number} index
 */

utils.binaryInsert = function binaryInsert(items, item, compare, uniq) {
  var i = utils.binarySearch(items, item, compare, true);

  if (uniq && i < items.length) {
    if (compare(items[i], item) === 0)
      return -1;
  }

  if (i === 0)
    items.unshift(item);
  else if (i === items.length)
    items.push(item);
  else
    items.splice(i, 0, item);

  return i;
};

/**
 * Perform a binary removal on a sorted array.
 * @param {Array} items
 * @param {Object} item
 * @param {Function} compare
 * @returns {Boolean}
 */

utils.binaryRemove = function binaryRemove(items, item, compare) {
  var i = utils.binarySearch(items, item, compare, false);
  if (i === -1)
    return false;
  items.splice(i, 1);
  return true;
};

/**
 * Unique-ify and sort an array of buffers.
 * @param {Buffer[]} items
 * @returns {Buffer[]}
 */

utils.uniqBuffer = function uniqBuffer(items) {
  var out = [];
  var i, j, item;

  for (i = 0; i < items.length; i++) {
    item = items[i];
    j = utils.binarySearch(out, item, utils.cmp, true);

    if (j < out.length && utils.cmp(out[j], item) === 0)
      continue;

    if (j === 0)
      out.unshift(item);
    else if (j === out.length)
      out.push(item);
    else
      out.splice(j, 0, item);
  }

  return out;
};

/**
 * Normalize a path.
 * @param {String} path
 * @param {Boolean?} dirname
 */

utils.normalize = function normalize(path, dirname) {
  var parts;

  path = path.replace(/\\/g, '/');
  path = path.replace(/(^|\/)\.\//, '$1');
  path = path.replace(/\/+\.?$/, '');
  parts = path.split(/\/+/);

  if (dirname)
    parts.pop();

  return parts.join('/');
};

/**
 * Create a full directory structure.
 * @param {String} path
 */

utils.mkdirp = function mkdirp(path) {
  var i, parts, stat;

  if (!fs)
    return;

  path = path.replace(/\\/g, '/');
  path = path.replace(/(^|\/)\.\//, '$1');
  path = path.replace(/\/+\.?$/, '');
  parts = path.split(/\/+/);
  path = '';

  if (process.platform === 'win32') {
    if (parts[0].indexOf(':') !== -1)
      path = parts.shift() + '/';
  }

  if (parts[0].length === 0) {
    parts.shift();
    path = '/';
  }

  for (i = 0; i < parts.length; i++) {
    path += parts[i];

    try {
      stat = fs.statSync(path);
      if (!stat.isDirectory())
        throw new Error('Could not create directory.');
    } catch (e) {
      if (e.code === 'ENOENT')
        fs.mkdirSync(path, 488 /* 0750 */);
      else
        throw e;
    }

    path += '/';
  }
};

/**
 * Ensure a directory.
 * @param {String} path
 * @param {Boolean?} dirname
 */

utils.mkdir = function mkdir(path, dirname) {
  if (utils.isBrowser)
    return;

  path = utils.normalize(path, dirname);

  if (utils._paths[path])
    return;

  utils._paths[path] = true;

  return utils.mkdirp(path);
};

/**
 * Cached mkdirp paths.
 * @private
 * @type {Object}
 */

utils._paths = {};

/**
 * Test whether a string is eligible
 * to be used as a name or ID.
 * @param {String} key
 * @returns {Boolean}
 */

utils.isName = function isName(key) {
  if (typeof key !== 'string')
    return false;

  if (!/^[\-\._0-9A-Za-z]+$/.test(key))
    return false;

  return key.length >= 1 && key.length <= 40;
};

/**
 * Ensure hidden-class mode for object.
 * @param {Object} obj
 */

utils.fastProp = function fastProp(obj) {
  ({ __proto__: obj });
};

/**
 * Verication result.
 * @constructor
 */

utils.VerifyResult = function VerifyResult() {
  this.reason = 'unknown';
  this.score = 0;
};

/**
 * Serialize number as a u32le.
 * @param {Number} num
 * @returns {Buffer}
 */

utils.U32 = function U32(num) {
  var data = new Buffer(4);
  data.writeUInt32LE(num, 0, true);
  return data;
};

/**
 * Create a lazy loader.
 * @param {Function} require
 * @param {Object} exports
 */

utils.lazy = require('./lazy');

/*
 * Expose other objects.
 */

lazy = utils.lazy(require, exports);

lazy('AsyncObject', './async');
lazy('bloom', './bloom');
lazy('errors', './errors');
lazy('ip', './ip');
lazy('Locker', './locker');
lazy('LRU', './lru');
lazy('murmur3', './murmur3');
lazy('co', './co');
lazy('uri', './uri');
lazy('BufferReader', './reader');
lazy('BufferWriter', './writer');
lazy('assert', 'assert');
