/*!
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var AsyncObject = require('../utils/async');
var utils = require('../utils/utils');
var co = require('../utils/co');
var assert = require('assert');
var Network = require('../protocol/network');
var Logger = require('./logger');
var time = require('../net/timedata');
var workers = require('../workers/workers');

/**
 * Base class from which every other
 * Node-like object inherits.
 * @exports Node
 * @constructor
 * @abstract
 * @param {Object} options
 */

function Node(options) {
  if (!(this instanceof Node))
    return new Node(options);

  AsyncObject.call(this);

  if (!options)
    options = {};

  this.parseOptions(options);

  this.options = options;
  this.network = Network.get(options.network);
  this.prefix = options.prefix;

  this.logger = options.logger;
  this.chain = null;
  this.fees = null;
  this.mempool = null;
  this.pool = null;
  this.miner = null;
  this.walletdb = null;
  this.wallet = null;
  this.http = null;

  this._bound = [];
  this.stack = [];
  this.plugins = {};

  this.__init();
}

utils.inherits(Node, AsyncObject);

/**
 * Initialize node.
 * @private
 */

Node.prototype.__init = function __init() {
  var self = this;

  if (!this.logger) {
    this.logger = new Logger({
      level: this.options.logLevel || 'none',
      console: this.options.logConsole,
      file: this.options.logFile
    });
  }

  this.on('preopen', function() {
    self._onOpen();
  });
  this.on('close', function() {
    self._onClose();
  });
};

/**
 * Open node. Bind all events.
 * @private
 */

Node.prototype._onOpen = function _onOpen() {
  var self = this;

  this.logger.open();

  this._bind(time, 'offset', function(offset) {
    self.logger.info('Time offset: %d (%d minutes).', offset, offset / 60 | 0);
  });

  this._bind(time, 'sample', function(sample, total) {
    self.logger.debug('Added time data: samples=%d, offset=%d (%d minutes).',
      total, sample, sample / 60 | 0);
  });

  this._bind(time, 'mismatch', function() {
    self.logger.warning('Please make sure your system clock is correct!');
  });

  this._bind(workers.pool, 'spawn', function(child) {
    self.logger.info('Spawning worker process: %d.', child.id);
  });

  this._bind(workers.pool, 'exit', function(code, child) {
    self.logger.warning('Worker %d exited: %s.', child.id, code);
  });

  this._bind(workers.pool, 'error', function(err, child) {
    if (child) {
      self.logger.error('Worker %d error: %s', child.id, err.message);
      return;
    }
    self.emit('error', err);
  });
};

/**
 * Close node. Unbind all events.
 * @private
 */

Node.prototype._onClose = function _onClose() {
  var i, bound;

  this.logger.close();

  for (i = 0; i < this._bound.length; i++) {
    bound = this._bound[i];
    bound[0].removeListener(bound[1], bound[2]);
  }

  this._bound.length = 0;
};

/**
 * Bind to an event on `obj`, save listener for removal.
 * @private
 * @param {EventEmitter} obj
 * @param {String} event
 * @param {Function} listener
 */

Node.prototype._bind = function _bind(obj, event, listener) {
  this._bound.push([obj, event, listener]);
  obj.on(event, listener);
};

/**
 * Emit and log an error.
 * @private
 * @param {Error} err
 */

Node.prototype._error = function _error(err) {
  if (!err)
    return;

  switch (err.reason) {
    case 'insufficient priority':
    case 'non-final':
      this.logger.spam(err.message);
      break;
    default:
      this.logger.error(err);
      break;
  }

  this.emit('error', err);
};

/**
 * Parse options object.
 * @private
 * @param {Object} options
 * @returns {Object}
 */

Node.prototype.parseOptions = function parseOptions(options) {
  options.network = Network.get(options.network);

  if (!options.prefix)
    options.prefix = utils.HOME + '/.bcoin';

  if (!options.db)
    options.db = 'memory';

  options.prefix = utils.normalize(options.prefix);

  if (options.logFile && typeof options.logFile !== 'string') {
    options.logFile = options.prefix;
    if (options.network.type !== 'main')
      options.logFile += '/' + options.network.type;
    options.logFile += '/debug.log';
  }

  options.logFile = options.logFile
    ? utils.normalize(options.logFile)
    : null;

  if (options.fast) {
    options.headers = true;
    options.useCheckpoints = true;
    options.coinCache = true;
  }

  if (options.witness == null)
    options.witness = options.network.witness;

  return options;
};

/**
 * Create a file path from a name
 * as well as the node's prefix.
 * @param {String} name
 * @returns {String}
 */

Node.prototype.location = function location(name) {
  var path = this.prefix;
  if (this.network.type !== 'main')
    path += '/' + this.network.type;
  path += '/' + name;
  return path;
};

/**
 * Attach a plugin.
 * @param {Object} plugin
 */

Node.prototype.use = function use(plugin) {
  assert(plugin && typeof plugin === 'object', 'Plugin must be an object.');
  assert(typeof plugin.init === 'function', '`init` must be a function.');
  assert(typeof plugin.open === 'function', '`open` must be a function.');
  assert(typeof plugin.close === 'function', '`close` must be a function.');

  assert(!this.loaded, 'Cannot add plugin after node is loaded.');

  if (plugin.name) {
    assert(typeof plugin.name === 'string', '`name` must be a string.');

    // Reserved names
    switch (plugin.name) {
      case 'logger':
      case 'chain':
      case 'fees':
      case 'mempool':
      case 'miner':
      case 'pool':
      case 'walletdb':
        assert(false, plugin.name + ' is already added.');
        break;
    }

    assert(!this.plugins[plugin.name], plugin.name + ' is already added.');

    this.plugins[plugin.name] = plugin;
  }

  this.stack.push(plugin);

  plugin.init(this);
};

/**
 * Require a plugin.
 * @param {String} name
 * @returns {Object}
 */

Node.prototype.require = function require(name) {
  var plugin;

  assert(typeof name === 'string', 'Plugin name must be a string.');

  switch (name) {
    case 'logger':
      assert(this.logger, 'logger is not loaded.');
      return this.logger;
    case 'chain':
      assert(this.chain, 'chain is not loaded.');
      return this.chain;
    case 'fees':
      assert(this.fees, 'fees is not loaded.');
      return this.fees;
    case 'mempool':
      assert(this.mempool, 'mempool is not loaded.');
      return this.mempool;
    case 'miner':
      assert(this.miner, 'miner is not loaded.');
      return this.miner;
    case 'pool':
      assert(this.pool, 'pool is not loaded.');
      return this.pool;
    case 'walletdb':
      assert(this.walletdb, 'walletdb is not loaded.');
      return this.walletdb;
  }

  plugin = this.plugins[name];
  assert(plugin, name + ' is not loaded.');

  return plugin;
};

/**
 * Open plugins.
 * @private
 */

Node.prototype.openPlugins = co(function* openPlugins() {
  var i, plugin;

  for (i = 0; i < this.stack.length; i++) {
    plugin = this.stack[i];
    yield plugin.open(this);
  }
});

/**
 * Close plugins.
 * @private
 */

Node.prototype.closePlugins = co(function* closePlugins() {
  var i, plugin;

  for (i = 0; i < this.stack.length; i++) {
    plugin = this.stack[i];
    yield plugin.close(this);
  }
});

/**
 * Open and ensure primary wallet.
 * @returns {Promise}
 */

Node.prototype.openWallet = co(function* openWallet() {
  var options, wallet;

  assert(!this.wallet);

  options = {
    id: 'primary',
    passphrase: this.options.passphrase
  };

  wallet = yield this.walletdb.ensure(options);

  this.logger.info(
    'Loaded wallet with id=%s wid=%d address=%s',
    wallet.id, wallet.wid, wallet.getAddress());

  // Set the miner payout address if the
  // programmer didn't pass one in.
  if (this.miner) {
    if (!this.options.payoutAddress)
      this.miner.address = wallet.getAddress();
  }

  this.wallet = wallet;
});

/**
 * Get chain tip.
 * @returns {Promise}
 */

Node.prototype.getTip = function getTip() {
  return Promise.resolve(this.chain.tip);
};

/**
 * Get chain entry.
 * @param {Hash} hash
 * @returns {Promise}
 */

Node.prototype.getEntry = co(function* getEntry(hash) {
  var entry = yield this.chain.db.get(hash);

  if (!entry)
    return;

  if (!(yield entry.isMainChain()))
    return;

  return entry;
});

/**
 * Send a transaction. Do not wait for promise.
 * @param {TX} tx
 * @returns {Promise}
 */

Node.prototype.send = function send(tx) {
  var onError = this._error.bind(this);

  this.sendTX(tx).catch(onError);

  return Promise.resolve();
};

/*
 * Expose
 */

module.exports = Node;
