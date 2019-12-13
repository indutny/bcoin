/*!
 * ed448.js - ed448 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const EDDSA = require('./eddsa');
const SHAKE256 = require('../shake256');

/*
 * Expose
 */

module.exports = new EDDSA('ED448', 'X448', SHAKE256);
