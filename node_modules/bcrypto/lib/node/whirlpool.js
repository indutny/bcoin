/*!
 * whirlpool.js - whirlpool implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const HMAC = require('../internal/hmac');

if (crypto.getHashes().indexOf('whirlpool') === -1)
  throw new Error('Hash not supported.');

/**
 * Whirlpool
 */

class Whirlpool {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('whirlpool');
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(this.ctx, 'Context is not initialized.');
    this.ctx.update(data);
    return this;
  }

  final() {
    assert(this.ctx, 'Context is not initialized.');
    const hash = this.ctx.digest();
    this.ctx = null;
    return hash;
  }

  static hash() {
    return new Whirlpool();
  }

  static hmac() {
    return new HMAC(Whirlpool, 64);
  }

  static digest(data) {
    return Whirlpool.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 64);
    assert(Buffer.isBuffer(right) && right.length === 64);
    return Whirlpool.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = Whirlpool;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return Whirlpool.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

Whirlpool.native = 1;
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
