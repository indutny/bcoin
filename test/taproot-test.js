/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const TX = require('../lib/primitives/tx');
const {TaggedHash} = require('../lib/utils/taggedhash');
const common = require('./util/common');

// Test data from https://github.com/pinheadmz/bitcoin/tree/taproottest1
const taprootTXs = require('./data/taproot_tx_data_single_input.json');

const tests = taprootTXs.tests;

describe('Taproot', function() {
  it('should create a generic tagged hash', () => {
    // Without 'bytes' argument
    const testHash1 = new TaggedHash('test');
    const digest1 = testHash1.digest(Buffer.alloc(32, 12));

    // With 'bytes' argument
    const testHash2 = new TaggedHash('test', Buffer.alloc(32, 12));
    assert.bufferEqual(digest1, testHash2);

    // Test vector created with
    // https://github.com/bitcoinops/bitcoin/blob/
    //   a1d284e50b8831ef20669198e0c9f5ab99e460a2/
    //   test/functional/test_framework/script.py#L619
    // TaggedHash('test', bytearray([12]*32)).hex()
    assert.bufferEqual(
      digest1,
      Buffer.from(
        'f88d26c35028f6e63b5cfc3fc67b4a3ae6da9c48d9f0be94df97a94ab64d5a68',
        'hex'
      )
    );
  });

  it('should get annex from witness', () => {
    // None of the legacy or SegWit TXs in ./data are Taproot-spenders
    for (let i = 1; i < 11; i++) {
      const txContext = common.readTX(`tx${i}`);
      const [tx] = txContext.getTX();
      for (const input of tx.inputs) {
        const witness = input.witness;
        assert.strictEqual(witness.getAnnex(), null);
      }
    }

    for (const test of tests) {
      // Ignore fail tests
      if (test.fail_input < test.inputs.length)
        continue;

      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      for (let i = 0; i < tx.inputs.length; i++) {
        const expected = test.inputs[i].annex;
        const actual = tx.inputs[i].witness.getAnnex();

        if (expected == null)
          assert.strictEqual(actual, null);
        else
          assert.bufferEqual(Buffer.from(expected, 'hex'), actual);
      }
    }
  });

  it('should get spend type from witness', () => {
    for (const test of tests) {
      // Ignore fail tests
      if (test.fail_input < test.inputs.length)
        continue;

      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      for (let i = 0; i < tx.inputs.length; i++) {
        const spendtype = tx.inputs[i].witness.getSpendType();

        if (test.inputs[i].annex != null)
          assert(spendtype & (1 << 0));

        if (test.inputs[i].annex == null)
          assert(~spendtype & (1 << 0));

        if (test.inputs[i].script != null)
          assert(spendtype & (1 << 1));

        if (test.inputs[i].script == null)
          assert(~spendtype & (1 << 1));
      }
    }
  });
});
