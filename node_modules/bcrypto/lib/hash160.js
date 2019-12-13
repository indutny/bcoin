/*!
 * hash160.js - hash160 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/hash160');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js') {
    module.exports = require('./js/hash160');
  } else {
    try {
      module.exports = require('./node/hash160');
    } catch (e) {
      module.exports = require('./js/hash160');
    }
  }
}
