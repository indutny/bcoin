/*!
 * ripemd160.js - ripemd160 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/ripemd160');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js') {
    module.exports = require('./js/ripemd160');
  } else {
    try {
      module.exports = require('./node/ripemd160');
    } catch (e) {
      module.exports = require('./js/ripemd160');
    }
  }
}
