/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const EDDSA = require('./eddsa');
const SHA512 = require('../sha512');
const pre = require('../js/precomputed/ed25519.json');

/*
 * Expose
 */

module.exports = new EDDSA('ED25519', 'X25519', SHA512, pre);
