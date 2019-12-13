/*!
 * cleanse.js - memzero for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');

/*
 * State
 */

let counter = 0;

/**
 * A maybe-secure memzero.
 * @param {Buffer} data
 */

function cleanse(data) {
  assert(Buffer.isBuffer(data));

  let ctr = counter;

  for (let i = 0; i < data.length; i++) {
    data[i] = ctr & 0xff;
    ctr += i;
  }

  counter = ctr >>> 0;
}

/*
 * Static
 */

cleanse.native = 0;

/*
 * Expose
 */

module.exports = cleanse;
