/*!
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const Amount = require('../btc/amount');
const Network = require('../protocol/network');
const Address = require('../primitives/address');
const Script = require('../script/script');
const consensus = require('../protocol/consensus');
const policy = require('../protocol/policy');

/**
 * Represents a transaction output.
 * @alias module:primitives.Output
 * @property {Amount} value
 * @property {Script} script
 */

class Output extends bio.Struct {
  /**
   * Create an output.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    super();

    this.value = 0;
    this.script = new Script();

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'Output data is required.');

    if (options.value) {
      assert(Number.isSafeInteger(options.value) && options.value >= 0,
        'Value must be a uint64.');
      this.value = options.value;
    }

    if (options.script)
      this.script.fromOptions(options.script);

    if (options.address)
      this.script.fromAddress(options.address);

    return this;
  }

  /**
   * Inject properties from script/value pair.
   * @private
   * @param {Script|Address} script
   * @param {Amount} value
   * @returns {Output}
   */

  fromScript(script, value) {
    if (typeof script === 'string')
      script = Address.fromString(script);

    if (script instanceof Address)
      script = Script.fromAddress(script);

    assert(script instanceof Script, 'Script must be a Script.');
    assert(Number.isSafeInteger(value) && value >= 0,
      'Value must be a uint64.');

    this.script = script;
    this.value = value;

    return this;
  }

  /**
   * Instantiate output from script/value pair.
   * @param {Script|Address} script
   * @param {Amount} value
   * @returns {Output}
   */

  static fromScript(script, value) {
    return new this().fromScript(script, value);
  }

  /**
   * Clone the output.
   * @param {Output} output
   * @returns {Output}
   */

  inject(output) {
    this.value = output.value;
    this.script.inject(output.script);
    return output;
  }

  /**
   * Test equality against another output.
   * @param {Output} output
   * @returns {Boolean}
   */

  equals(output) {
    assert(Output.isOutput(output));
    return this.value === output.value
      && this.script.equals(output.script);
  }

  /**
   * Compare against another output (BIP69).
   * @param {Output} output
   * @returns {Number}
   */

  compare(output) {
    assert(Output.isOutput(output));

    const cmp = this.value - output.value;

    if (cmp !== 0)
      return cmp;

    return this.script.compare(output.script);
  }

  /**
   * Get the script type as a string.
   * @returns {ScriptType} type
   */

  getType() {
    return Script.typesByVal[this.script.getType()].toLowerCase();
  }

  /**
   * Get the address.
   * @returns {Address} address
   */

  getAddress() {
    return this.script.getAddress();
  }

  /**
   * Get the address hash.
   * @returns {Hash} hash
   */

  getHash() {
    const addr = this.getAddress();

    if (!addr)
      return null;

    return addr.getHash();
  }

  /**
   * Convert the input to a more user-friendly object.
   * @returns {Object}
   */

  format() {
    return {
      type: this.getType(),
      value: Amount.btc(this.value),
      script: this.script,
      address: this.getAddress()
    };
  }

  /**
   * Convert the output to an object suitable
   * for JSON serialization.
   * @returns {Object}
   */

  toJSON() {
    return this.getJSON();
  }

  /**
   * Convert the output to an object suitable
   * for JSON serialization.
   * @param {Network} network
   * @returns {Object}
   */

  getJSON(network) {
    let addr = this.getAddress();

    network = Network.get(network);

    if (addr)
      addr = addr.toString(network);

    return {
      value: this.value,
      script: this.script.toJSON(),
      address: addr
    };
  }

  /**
   * Calculate the dust threshold for this
   * output, based on serialize size and rate.
   * @param {Rate?} rate
   * @returns {Amount}
   */

  getDustThreshold(rate) {
    const scale = consensus.WITNESS_SCALE_FACTOR;

    if (this.script.isUnspendable())
      return 0;

    let size = this.getSize();

    if (this.script.isProgram()) {
      // 75% segwit discount applied to script size.
      size += 32 + 4 + 1 + (107 / scale | 0) + 4;
    } else {
      size += 32 + 4 + 1 + 107 + 4;
    }

    return 3 * policy.getMinFee(size, rate);
  }

  /**
   * Calculate size of serialized output.
   * @returns {Number}
   */

  getSize() {
    return 8 + this.script.getVarSize();
  }

  /**
   * Test whether the output should be considered dust.
   * @param {Rate?} rate
   * @returns {Boolean}
   */

  isDust(rate) {
    return this.value < this.getDustThreshold(rate);
  }

  /**
   * Inject properties from a JSON object.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    assert(json, 'Output data is required.');
    assert(Number.isSafeInteger(json.value) && json.value >= 0,
      'Value must be a uint64.');
    this.value = json.value;
    this.script.fromJSON(json.script);
    return this;
  }

  /**
   * Write the output to a buffer writer.
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeI64(this.value);
    this.script.write(bw);
    return bw;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   * @returns {Output}
   */

  read(br) {
    this.value = br.readI64();
    this.script.read(br);
    return this;
  }

  /**
   * Test an object to see if it is an Output.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isOutput(obj) {
    return obj instanceof Output;
  }
}

/*
 * Expose
 */

module.exports = Output;
