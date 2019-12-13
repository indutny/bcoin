/*!
 * x25519.js - x25519 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/x25519');
} catch (e) {
  module.exports = require('./js/x25519');
}
