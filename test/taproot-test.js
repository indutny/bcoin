/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const CoinView = require('../lib/coins/coinview');
const TX = require('../lib/primitives/tx');
const Coin = require('../lib/primitives/coin');
const {TaggedHash} = require('../lib/utils/taggedhash');
const Script = require('../lib/script/script');
const {flags} = require('../lib/script/common');
const {digests} = Script;
const common = require('./util/common');
const Schnorr = require('bcrypto/lib/js/schnorr');

// Test data from https://github.com/pinheadmz/bitcoin/tree/taproottest1
const taprootTXs = require('./data/taproot_tx_data_single_input.json');

const tests = taprootTXs.tests;
const UTXOs = taprootTXs.UTXOs;

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

  it('should not find annex in non-taproot TX', () => {
    // None of the legacy or SegWit TXs in ./data are Taproot-spenders
    for (let i = 1; i < 11; i++) {
      const txContext = common.readTX(`tx${i}`);
      const [tx] = txContext.getTX();
      for (const input of tx.inputs) {
        const witness = input.witness;
        assert.strictEqual(witness.getAnnex(), null);
      }
    }
  });

  describe('Get annex from witness', function() {
    for (const test of tests) {
      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      for (let i = 0; i < tx.inputs.length; i++) {
        it(`${test.inputs[i].comment}`, () => {
          if (test.fail_input === i)
            this.skip();

            const expected = test.inputs[i].annex;
            const actual = tx.inputs[i].witness.getAnnex();

            if (expected == null)
              assert.strictEqual(actual, null);
            else
              assert.bufferEqual(Buffer.from(expected, 'hex'), actual);
        });
      }
    }
  });

  describe('Get spend type from witness', function() {
    for (const test of tests) {
      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      for (let i = 0; i < tx.inputs.length; i++) {
        it(`${test.inputs[i].comment}`, () => {
          if (test.fail_input === i)
            this.skip();

          const spendtype = tx.inputs[i].witness.getSpendType();

          if (test.inputs[i].annex != null)
            assert(spendtype & (1 << 0));

          if (test.inputs[i].annex == null)
            assert(~spendtype & (1 << 0));

          if (test.inputs[i].script != null)
            assert(spendtype & (1 << 1));

          if (test.inputs[i].script == null)
            assert(~spendtype & (1 << 1));
        });
      }
    }
  });

  describe('Get tapleaf (script) from witness', function() {
    for (const test of tests) {
      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      for (let i = 0; i < tx.inputs.length; i++) {
        it(`${test.inputs[i].comment}`, () => {
          if (test.fail_input === i)
            this.skip();

          const actual = tx.inputs[i].witness.getTapleaf();
          const expected = test.inputs[i].script;

          if (test.inputs[i].script == null)
            assert(actual == null);
          else
            assert.bufferEqual(Buffer.from(expected, 'hex'), actual);
        });
      }
    }
  });

  describe('Compute sighash', function() {
    for (const test of tests) {
      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      // Collect all inputs to this TX
      const coins = [];
      for (let i = 0; i < tx.inputs.length; i++) {
        const key = tx.inputs[i].prevout.toKey();

        const utxo = UTXOs[key.toString('hex')];

        const coin = Coin.fromKey(key);
        coin.value = utxo.value;
        coin.script = Script.fromJSON(utxo.scriptPubKey);

        coins.push(coin);
      }

      for (let i = 0; i < tx.inputs.length; i++) {
        it(`${test.inputs[i].comment}`, () => {
          if (test.fail_input === i)
            this.skip();

          // Not all tests have a sighash ("alwaysvalid")
          if (test.inputs[i].sighash == null)
            this.skip();

          // For most of these tests, the top witness stack item is the signature
          const sig = tx.inputs[i].witness.items[0];

          // In Taproot, SIGHASH_ALL is default
          let type = 0;
          if (sig.length === 65)
            type = sig[sig.length - 1];
          else if (sig.length !== 64)
            this.skip();

          // Find the last executed OP_CODESEPARATOR (default/none = 0xffffffff).
          // Normally computed in Script.execute() but since we're not preocessing
          // any script at all for this test, we'll cheat based on
          // bitcoin/test/functional/feature_taproot.py build_spenders()
          let codesepPos = 0xffffffff;
          switch (test.inputs[i].comment) {
            case 'sighash/codesep#s1':
              codesepPos = 0;
              break;
            case 'sighash/codesep#s2a':
              codesepPos = 3;
              break;
            case 'sighash/codesep#s2b':
              codesepPos = 6;
              break;
          }

          const coin = coins[i];
          const actual = tx.signatureHash(
            i,
            coin.script,
            coin.value,
            type,
            digests.TAPROOT,
            coins,
            codesepPos
          );

          const expected = Buffer.from(test.inputs[i].sighash, 'hex');

          assert.bufferEqual(expected, actual);
        });
      }
    }
  });

  describe  ('Verify signature (schnorr)', function() {
    for (const test of tests) {
      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      for (let i = 0; i < tx.inputs.length; i++) {
        it(`${test.inputs[i].comment}`, () => {
          if (test.fail_input === i)
            this.skip();

          // Skip script spends for now
          if (test.inputs[i].script)
            this.skip();

          // Not all tests have a sighash ("alwaysvalid")
          if (test.inputs[i].sighash == null)
            this.skip();

          const sighash = Buffer.from(test.inputs[i].sighash, 'hex');
          const sig = tx.inputs[i].witness.items[0];

          // Get pubkey from prevout scriptPubKey (witness program)
          const key = tx.inputs[i].prevout.toKey();
          const utxo = UTXOs[key.toString('hex')];
          const script = Script.fromJSON(utxo.scriptPubKey);
          const program = script.getProgram();
          const pubkey = program.data;

          assert(Schnorr.verify(sighash, sig.slice(0, 64), pubkey));
        });
      }
    }
  });

  describe('Verify Taproot commitment', function() {
    for (const test of tests) {
      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      for (let i = 0; i < tx.inputs.length; i++) {
        it(`${test.inputs[i].comment}`, () => {
          if (test.fail_input === i)
            this.skip();

          // Only testing script spends
          if (!test.inputs[i].script)
            this.skip();

          // Get pubkey from prevout scriptPubKey (witness program)
          const key = tx.inputs[i].prevout.toKey();
          const utxo = UTXOs[key.toString('hex')];
          const script = Script.fromJSON(utxo.scriptPubKey);

          const witness = tx.inputs[i].witness;

          assert(Script.verifyTaprootCommitment(witness, script));
        });
      }
    }
  });

  describe('Verify Taproot transactions', function() {
    // Flags for mempool inclusion
    const standardFlags = flags.STANDARD_VERIFY_FLAGS;

    // Flags for block inclusion after Taproot activation,
    // inlcuding all previous deployments.
    const mandatoryFlags = flags.MANDATORY_VERIFY_FLAGS
      | flags.VERIFY_P2SH
      | flags.VERIFY_DERSIG
      | flags.VERIFY_CHECKLOCKTIMEVERIFY
      | flags.VERIFY_CHECKSEQUENCEVERIFY
      | flags.VERIFY_WITNESS
      | flags.VERIFY_NULLDUMMY
      | flags.VERIFY_TAPROOT;

    for (const test of tests) {
      const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

      // Expected mempool inclusion verification result
      const standard = test.standard;

      // Expected block inclusion verification result
      let mandatory = true;
      if (test.fail_input < tx.inputs.length)
        mandatory = false;

      // Generate test name
      let name = mandatory ? 'mand+ / ' : 'mand- / ';
      name += standard ? 'std+' : 'std-';
      for (let i = 0; i < tx.inputs.length; i++)
        name +=  ' ' + test.inputs[i].comment;

      // Add coins for each input
      const view = new CoinView();
      let script;
      for (let i = 0; i < tx.inputs.length; i++) {
        script = test.inputs[i].script;

        const key = tx.inputs[i].prevout.toKey();
        const utxo = UTXOs[key.toString('hex')];
        const coin = Coin.fromKey(key);
        coin.value = utxo.value;
        coin.script = Script.fromJSON(utxo.scriptPubKey);

        view.addCoin(coin);
      }

      it(name, () => {
        // Skip script spends for now
        if (script)
          this.skip();

        // Verify standardness (mempool)
        const isStandard =
          tx.checkStandard()[0]
          && tx.verify(view, standardFlags)
          && tx.hasStandardInputs(view)
          && tx.hasStandardWitness(view);
        assert.strictEqual(standard, isStandard);

        // Verify mandatoryness (block)
        assert.strictEqual(mandatory, tx.verify(view, mandatoryFlags));
      });
    };
  });
});
