/*!
 * aead.js - aead for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/aead');
} catch (e) {
  module.exports = require('./js/aead');
}
