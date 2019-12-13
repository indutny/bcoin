/*!
 * cash32.js - cashaddr for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('../native/cash32');
} catch (e) {
  module.exports = require('../js/cash32');
}
