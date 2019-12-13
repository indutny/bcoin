/*!
 * base58.js - base58 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('../native/base58');
} catch (e) {
  module.exports = require('../js/base58');
}
