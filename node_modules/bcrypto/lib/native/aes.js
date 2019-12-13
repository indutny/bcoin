/*!
 * aes.js - aes for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {aes} = require('./binding');

/*
 * Expose
 */

exports.native = 2;
exports.encipher = aes.encipher;
exports.decipher = aes.decipher;
