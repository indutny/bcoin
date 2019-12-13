/*!
 * whirlpool.js - whirlpool for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Whirlpool} = require('./binding');
const HMAC = require('../internal/hmac');

/*
 * Whirpool
 */

Whirlpool.hash = function hash() {
  return new Whirlpool();
};

Whirlpool.hmac = function hmac() {
  return new HMAC(Whirlpool, 64);
};

Whirlpool.mac = function mac(data, key) {
  return Whirlpool.hmac().init(key).update(data).final();
};

/*
 * Static
 */

Whirlpool.native = 2;
Whirlpool.id = 'WHIRLPOOL';
Whirlpool.size = 64;
Whirlpool.bits = 512;
Whirlpool.blockSize = 64;
Whirlpool.zero = Buffer.alloc(64, 0x00);
Whirlpool.ctx = new Whirlpool();

/*
 * Expose
 */

module.exports = Whirlpool;
