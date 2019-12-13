/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

let backend = process.env.NODE_BACKEND || 'native';

if (process.env.BCRYPTO_FORCE_GMP)
  backend = 'native';
else if (process.env.BCRYPTO_FORCE_BIGINT)
  backend = 'node';

switch (backend) {
  case 'native': {
    try {
      module.exports = require('./native/bn.js');
      break;
    } catch (e) {
      ;
    }
  }
  case 'node': {
    try {
      module.exports = require('./node/bn.js');
      break;
    } catch (e) {
      ;
    }
  }
  default: {
    module.exports = require('./js/bn.js');
    break;
  }
}
