/*!
 * salsa20.js - salsa20 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/salsa20');
} catch (e) {
  module.exports = require('./js/salsa20');
}
