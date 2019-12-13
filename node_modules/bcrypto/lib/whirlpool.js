/*!
 * whirlpool.js - whirlpool for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/whirlpool');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js') {
    module.exports = require('./js/whirlpool');
  } else {
    try {
      module.exports = require('./node/whirlpool');
    } catch (e) {
      module.exports = require('./js/whirlpool');
    }
  }
}
