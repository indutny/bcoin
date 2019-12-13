/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('../native/bech32');
} catch (e) {
  module.exports = require('../js/bech32');
}
