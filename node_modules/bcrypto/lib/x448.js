/*!
 * x448.js - x448 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/x448');
} catch (e) {
  module.exports = require('./js/x448');
}
