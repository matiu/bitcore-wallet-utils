'use strict';

var _ = require('lodash');
var Uuid = require('uuid');
var chai = require('chai');
var sinon = require('sinon');
var should = chai.should();
var Bitcore = require('bitcore');
var WalletUtils = require('../lib/walletutils');

var aText = 'hola';
var aPubKey = '03bec86ad4a8a91fe7c11ec06af27246ec55094db3d86098b7d8b2f12afe47627f';
var aPrivKey = '09458c090a69a38368975fb68115df2f4b0ab7d1bc463fc60c67aa1730641d6c';
var aSignature = '3045022100d6186930e4cd9984e3168e15535e2297988555838ad10126d6c20d4ac0e74eb502201095a6319ea0a0de1f1e5fb50f7bf10b8069de10e0083e23dbbf8de9b8e02785';

var otherPubKey = '02555a2d45e309c00cc8c5090b6ec533c6880ab2d3bc970b3943def989b3373f16';

var helpers = {};

helpers.toSatoshi = function(btc) {
  if (_.isArray(btc)) {
    return _.map(btc, helpers.toSatoshi);
  } else {
    return helpers.strip(btc * 1e8);
  }
};

helpers.strip = function(number) {
  return (parseFloat(number.toPrecision(12)));
}

// Amounts in satoshis
helpers.generateUtxos = function(publicKeyRing, path, requiredSignatures, amounts) {
  var amounts = [].concat(amounts);
  var utxos = _.map(amounts, function(amount, i) {

    var address = WalletUtils.deriveAddress(publicKeyRing, path, requiredSignatures, 'testnet');

    var obj = {
      txid: Bitcore.crypto.Hash.sha256(new Buffer(i)).toString('hex'),
      vout: 100,
      satoshis: helpers.toSatoshi(amount),
      scriptPubKey: Bitcore.Script.buildMultisigOut(address.publicKeys, requiredSignatures).toScriptHashOut().toBuffer().toString('hex'),
      address: address.address,
      path: path,
      publicKeys: address.publicKeys
    };
    return obj;
  });
  return utxos;
};

describe('WalletUtils', function() {

  describe('#hashMessage', function() {
    it('should create a hash', function() {
      var res = WalletUtils.hashMessage(aText);
      res.toString('hex').should.equal('4102b8a140ec642feaa1c645345f714bc7132d4fd2f7f6202db8db305a96172f');
    });
  });

  describe('#signMessage', function() {
    it('should sign a message', function() {
      var sig = WalletUtils.signMessage(aText, aPrivKey);
      should.exist(sig);
      sig.should.equal(aSignature);
    });
    it('should fail to sign with wrong args', function() {
      (function() {
        WalletUtils.signMessage(aText, aPubKey);
      }).should.throw('Number');
    });
  });

  describe('#verifyMessage', function() {
    it('should fail to verify a malformed signature', function() {
      var res = WalletUtils.verifyMessage(aText, 'badsignature', otherPubKey);
      should.exist(res);
      res.should.equal(false);
    });
    it('should fail to verify a null signature', function() {
      var res = WalletUtils.verifyMessage(aText, null, otherPubKey);
      should.exist(res);
      res.should.equal(false);
    });
    it('should fail to verify with wrong pubkey', function() {
      var res = WalletUtils.verifyMessage(aText, aSignature, otherPubKey);
      should.exist(res);
      res.should.equal(false);
    });
    it('should verify', function() {
      var res = WalletUtils.verifyMessage(aText, aSignature, aPubKey);
      should.exist(res);
      res.should.equal(true);
    });
  });

  describe('#deriveXPrivFromMaster', function() {
    it('should derive BIP45 livenet', function() {
      var xpriv = WalletUtils.deriveXPrivFromMaster('xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', 'BIP45', 'livenet').toString();
      xpriv.should.equal('xprv9vDaAbbvT8LHKr8v5A2JeFJrnbQk6ZrMDGWuiv2vZgSyugeV4RE7Z9QjBNYsdafdhwEGb6Y48DRrXFVKvYRAub9ExzcmJHt6Js6ybJCSssm');
    });
    it('should derive BIP45 testnet', function() {
      var xpriv = WalletUtils.deriveXPrivFromMaster('tprv8ZgxMBicQKsPfPX8avSJXY1tZYJJESNg8vR88i8rJFkQJm6HgPPtDEmD36NLVSJWV5ieejVCK62NdggXmfMEHog598PxvXuLEsWgE6tKdwz', 'BIP45', 'testnet').toString();
      xpriv.should.equal('tprv8dS9thiyn4EeSuw92hNyNbksGd5tA2zhjdfLVtVpKjEkZ5X8CAsKZGCzYSnCG4utn5AdKoHMZgwmNuNLcNE5eK6XsMfBbDWQyx8EHy1ro3F');
    });
    it('should derive BIP44 livenet', function() {
      var xpriv = WalletUtils.deriveXPrivFromMaster('xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', 'BIP44', 'livenet').toString();
      xpriv.should.equal('xprv9xud2WztGSSBPDPDL9RQ3rG3vucRA4BmEnfAdP76bTqtkGCK8VzWjevLw9LsdqwH1PEWiwcjymf1T2FLp12XjwjuCRvcSBJvxDgv1BDTbWY');
    });
    it('should derive BIP44 testnet', function() {
      var xpriv = WalletUtils.deriveXPrivFromMaster('tprv8ZgxMBicQKsPfPX8avSJXY1tZYJJESNg8vR88i8rJFkQJm6HgPPtDEmD36NLVSJWV5ieejVCK62NdggXmfMEHog598PxvXuLEsWgE6tKdwz', 'BIP44', 'testnet').toString();
      xpriv.should.equal('tprv8gBu8N7JbHZs7MsW4kgE8LAYMhGJES9JP6DHsj2gw9Tc5PrF5Grr9ynAZkH1LyWsxjaAyCuEMFKTKhzdSaykpqzUnmEhpLsxfujWHA66N93');
    });
  });

  describe('#signMessage #verifyMessage round trip', function() {
    it('should sign and verify', function() {
      var aLongerText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
      var sig = WalletUtils.signMessage(aLongerText, aPrivKey);
      WalletUtils.verifyMessage(aLongerText, sig, aPubKey).should.equal(true);
    });
  });

  describe('#encryptMessage #decryptMessage round trip', function() {
    it('should encrypt and decrypt', function() {
      var pwd = "ezDRS2NRchMJLf1IWtjL5A==";
      var ct = WalletUtils.encryptMessage('hello world', pwd);
      var msg = WalletUtils.decryptMessage(ct, pwd);
      msg.should.equal('hello world');
    });
  });

  describe('#toSecret #fromSecret round trip', function() {
    it('should create secret and parse secret', function() {
      var i = 0;
      while (i++ < 100) {
        var walletId = Uuid.v4();
        var walletPrivKey = new Bitcore.PrivateKey();
        var network = i % 2 == 0 ? 'testnet' : 'livenet';
        var secret = WalletUtils.toSecret(walletId, walletPrivKey, network);
        var result = WalletUtils.fromSecret(secret);
        result.walletId.should.equal(walletId);
        result.walletPrivKey.toString().should.equal(walletPrivKey.toString());
        result.network.should.equal(network);
      };
    });
    it('should fail on invalid secret', function() {
      (function() {
        WalletUtils.fromSecret('invalidSecret');
      }).should.throw('Invalid secret');
    });

    it('should create secret and parse secret from string ', function() {
      var walletId = Uuid.v4();
      var walletPrivKey = new Bitcore.PrivateKey();
      var network = 'testnet';
      var secret = WalletUtils.toSecret(walletId, walletPrivKey.toString(), network);
      var result = WalletUtils.fromSecret(secret);
      result.walletId.should.equal(walletId);
      result.walletPrivKey.toString().should.equal(walletPrivKey.toString());
      result.network.should.equal(network);
    });
  });

  describe('#getProposalHash', function() {
    it('should compute hash for old style proposals', function() {
      var hash = WalletUtils.getProposalHash('msj42CCGruhRsFrGATiUuh25dtxYtnpbTx', 1234, 'the message');
      hash.should.equal('msj42CCGruhRsFrGATiUuh25dtxYtnpbTx|1234|the message|');
    });
    it('should compute hash for arbitrary proposal', function() {
      var header1 = {
        type: 'simple',
        version: '1.0',
        toAddress: 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx',
        amount: 1234,
        message: {
          one: 'one',
          two: 'two'
        },
      };

      var header2 = {
        toAddress: 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx',
        type: 'simple',
        version: '1.0',
        message: {
          two: 'two',
          one: 'one'
        },
        amount: 1234,
      };

      var hash1 = WalletUtils.getProposalHash(header1);
      var hash2 = WalletUtils.getProposalHash(header2);

      hash1.should.equal(hash2);
    });
  });

  describe('#getNetworkFromXPubKey', function() {
    it('should check correctly', function() {
      var result;

      var xPrivKeyLivenet = (new Bitcore.HDPrivateKey('livenet')).toString();
      var xPubKeyLivenet = new Bitcore.HDPublicKey(xPrivKeyLivenet).toString();
      result = WalletUtils.getNetworkFromXPubKey(xPubKeyLivenet);
      result.should.be.equal('livenet');

      var xPrivKeyTestnet = (new Bitcore.HDPrivateKey('testnet')).toString();
      var xPubKeyTestnet = new Bitcore.HDPublicKey(xPrivKeyTestnet).toString();
      result = WalletUtils.getNetworkFromXPubKey(xPubKeyTestnet);
      result.should.be.equal('testnet');

    });
    it('should fail if argument is null or undefined', function() {
      var values = [
        null,
        123,
      ];
      _.each(values, function(value) {
        var valid = true;
        try {
          WalletUtils.getNetworkFromXPubKey(value);
        } catch (e) {
          valid = false;
        }
        valid.should.be.false;
      });
    });

  });

  describe('#privateKeyToAESKey', function() {
    it('should be ok', function() {
      var privKey = new Bitcore.PrivateKey(aPrivKey).toString();
      WalletUtils.privateKeyToAESKey(privKey).should.be.equal('2HvmUYBSD0gXLea6z0n7EQ==');
    });
    it('should fail if pk has invalid values', function() {
      var values = [
        null,
        123,
        '123',
      ];
      _.each(values, function(value) {
        var valid = true;
        try {
          WalletUtils.privateKeyToAESKey(value);
        } catch (e) {
          valid = false;
        }
        valid.should.be.false;
      });
    });
  });

  describe('#buildTx', function() {
    var masterPrivateKey, derivedPrivateKey;
    beforeEach(function() {
      masterPrivateKey = 'tprv8ZgxMBicQKsPdPLE72pfSo7CvzTsWddGHdwSuMNrcerr8yQZKdaPXiRtP9Ew8ueSe9M7jS6RJsp4DiAVS2xmyxcCC9kZV6X1FMsX7EQX2R5';
      derivedPrivateKey = WalletUtils.deriveXPrivFromMaster(masterPrivateKey, 'BIP45', 'testnet');
    });
    it('should build a tx correctly', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var utxos = helpers.generateUtxos(publicKeyRing, 'm/1/0', 1, [1000, 2000]);
      var txp = {
        version: '2.0.0',
        inputs: utxos,
        toAddress: toAddress,
        amount: 1200,
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1],
        fee: 10050,
        derivationStrategy: 'BIP45',
      };
      var t = WalletUtils.buildTx(txp);
      var bitcoreError = t.getSerializationError({
        disableIsFullySigned: true,
        disableSmallFees: true,
        disableLargeFees: true,
      });

      should.not.exist(bitcoreError);
      t.getFee().should.equal(10050);
    });
    it('should build a legacy (v1.*) tx correctly', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var utxos = helpers.generateUtxos(publicKeyRing, 'm/1/0', 1, [1000, 2000]);
      var txp = {
        version: '1.0.1',
        inputs: utxos,
        toAddress: toAddress,
        amount: 1200,
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1],
        feePerKb: 40000,
        fee: 10050,
        derivationStrategy: 'BIP45',
      };
      var t = WalletUtils.buildTx(txp);
      var bitcoreError = t.getSerializationError({
        disableIsFullySigned: true,
        disableSmallFees: true,
        disableLargeFees: true,
      });

      should.not.exist(bitcoreError);
      t.getFee().should.equal(40000);
    });
    it('should protect from creating excessive fee', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var utxos = helpers.generateUtxos(publicKeyRing, 'm/1/0', 1, [1, 2]);
      var txp = {
        inputs: utxos,
        toAddress: toAddress,
        amount: 1.2,
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1],
        fee: 1.5e8,
        derivationStrategy: 'BIP45',
      };

      var x = WalletUtils.newBitcoreTransaction;

      WalletUtils.newBitcoreTransaction = function() {
        return {
          from: sinon.stub(),
          to: sinon.stub(),
          change: sinon.stub(),
          outputs: [{
            satoshis: 1000,
          }],
          fee: sinon.stub(),
        }
      };

      (function() {
        var t = WalletUtils.buildTx(txp);
      }).should.throw('Illegal State');

      WalletUtils.newBitcoreTransaction = x;
    });
    it('should build a tx with multiple outputs', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var utxos = helpers.generateUtxos(publicKeyRing, 'm/1/0', 1, [1000, 2000]);
      var txp = {
        inputs: utxos,
        type: 'multiple_outputs',
        outputs: [{
          toAddress: toAddress,
          amount: 800,
          message: 'first output'
        }, {
          toAddress: toAddress,
          amount: 900,
          message: 'second output'
        }],
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1, 2],
        fee: 10000,
        derivationStrategy: 'BIP45',
      };
      var t = WalletUtils.buildTx(txp);
      var bitcoreError = t.getSerializationError({
        disableIsFullySigned: true,
      });
      should.not.exist(bitcoreError);
    });

    it('should build a tx with provided output scripts', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var utxos = helpers.generateUtxos(publicKeyRing, 'm/1/0', 1, [0.001]);
      var txp = {
        inputs: utxos,
        type: 'external',
        outputs: [{
          "amount": 700,
          "script": "512103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff210314a96cd6f5a20826070173fe5b7e9797f21fc8ca4a55bcb2d2bde99f55dd352352ae"
        }, {
          "amount": 600,
          "script": "76a9144d5bd54809f846dc6b1a14cbdd0ac87a3c66f76688ac"
        }, {
          "amount": 0,
          "script": "6a1e43430102fa9213bc243af03857d0f9165e971153586d3915201201201210"
        }],
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1, 2, 3],
        fee: 10000,
        derivationStrategy: 'BIP45',
      };
      var t = WalletUtils.buildTx(txp);
      var bitcoreError = t.getSerializationError({
        disableIsFullySigned: true,
      });
      should.not.exist(bitcoreError);
      t.outputs.length.should.equal(4);
      t.outputs[0].script.toHex().should.equal(txp.outputs[0].script);
      t.outputs[0].satoshis.should.equal(txp.outputs[0].amount);
      t.outputs[1].script.toHex().should.equal(txp.outputs[1].script);
      t.outputs[1].satoshis.should.equal(txp.outputs[1].amount);
      t.outputs[2].script.toHex().should.equal(txp.outputs[2].script);
      t.outputs[2].satoshis.should.equal(txp.outputs[2].amount);
      var changeScript = Bitcore.Script.fromAddress(txp.changeAddress.address).toHex();
      t.outputs[3].script.toHex().should.equal(changeScript);
    });
    it('should fail if provided output has both toAddress and script', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var utxos = helpers.generateUtxos(publicKeyRing, 'm/1/0', 1, [0.001]);
      var txp = {
        inputs: utxos,
        type: 'external',
        outputs: [{
          "toAddress": "18433T2TSgajt9jWhcTBw4GoNREA6LpX3E",
          "amount": 700,
          "script": "512103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff210314a96cd6f5a20826070173fe5b7e9797f21fc8ca4a55bcb2d2bde99f55dd352352ae"
        }, {
          "amount": 600,
          "script": "76a9144d5bd54809f846dc6b1a14cbdd0ac87a3c66f76688ac"
        }, {
          "amount": 0,
          "script": "6a1e43430102fa9213bc243af03857d0f9165e971153586d3915201201201210"
        }],
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1, 2, 3],
        fee: 10000,
        derivationStrategy: 'BIP45',
      };
      (function() {
        var t = WalletUtils.buildTx(txp);
      }).should.throw('Output should have either toAddress or script specified');

      delete txp.outputs[0].toAddress;
      var t = WalletUtils.buildTx(txp);
      var bitcoreError = t.getSerializationError({
        disableIsFullySigned: true,
      });
      should.not.exist(bitcoreError);
    });
  });

  describe('#signTxp', function() {
    var masterPrivateKey, derivedPrivateKey;
    beforeEach(function() {
      masterPrivateKey = 'tprv8ZgxMBicQKsPdPLE72pfSo7CvzTsWddGHdwSuMNrcerr8yQZKdaPXiRtP9Ew8ueSe9M7jS6RJsp4DiAVS2xmyxcCC9kZV6X1FMsX7EQX2R5';
      derivedPrivateKey = WalletUtils.deriveXPrivFromMaster(masterPrivateKey, 'BIP45', 'testnet');
    });
    it('should sign correctly', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var path = 'm/1/0';
      var utxos = helpers.generateUtxos(publicKeyRing, path, 1, [1000, 2000]);
      var txp = {
        inputs: utxos,
        toAddress: toAddress,
        amount: 1200,
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1],
        fee: 10000,
        derivationStrategy: 'BIP45',
      };
      var signatures = WalletUtils.signTxp(txp, masterPrivateKey);
      signatures.length.should.be.equal(utxos.length);
    });
    it('should sign BIP44 proposal correctly', function() {
      masterPrivateKey = 'tprv8ZgxMBicQKsPdPLE72pfSo7CvzTsWddGHdwSuMNrcerr8yQZKdaPXiRtP9Ew8ueSe9M7jS6RJsp4DiAVS2xmyxcCC9kZV6X1FMsX7EQX2R5';
      derivedPrivateKey = WalletUtils.deriveXPrivFromMaster(masterPrivateKey, 'BIP44', 'testnet');

      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var path = 'm/1/0';
      var utxos = helpers.generateUtxos(publicKeyRing, path, 1, [1000, 2000]);
      var txp = {
        inputs: utxos,
        toAddress: toAddress,
        amount: 1200,
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1],
        fee: 10000,
        derivationStrategy: 'BIP44',
      };
      var signatures = WalletUtils.signTxp(txp, masterPrivateKey);
      signatures.length.should.be.equal(utxos.length);
    });
    it('should sign multiple-outputs proposal correctly', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var path = 'm/1/0';
      var utxos = helpers.generateUtxos(publicKeyRing, path, 1, [1000, 2000]);
      var txp = {
        inputs: utxos,
        type: 'multiple_outputs',
        outputs: [{
          toAddress: toAddress,
          amount: 800,
          message: 'first output'
        }, {
          toAddress: toAddress,
          amount: 900,
          message: 'second output'
        }],
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1, 2],
        fee: 10000,
        derivationStrategy: 'BIP45',
      };
      var signatures = WalletUtils.signTxp(txp, masterPrivateKey);
      signatures.length.should.be.equal(utxos.length);
    });
    it('should sign proposal with provided output scripts correctly', function() {
      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var utxos = helpers.generateUtxos(publicKeyRing, 'm/1/0', 1, [0.001]);
      var txp = {
        inputs: utxos,
        type: 'external',
        outputs: [{
          "amount": 700,
          "script": "512103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff210314a96cd6f5a20826070173fe5b7e9797f21fc8ca4a55bcb2d2bde99f55dd352352ae"
        }, {
          "amount": 600,
          "script": "76a9144d5bd54809f846dc6b1a14cbdd0ac87a3c66f76688ac"
        }, {
          "amount": 0,
          "script": "6a1e43430102fa9213bc243af03857d0f9165e971153586d3915201201201210"
        }],
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1, 2, 3],
        fee: 10000,
        derivationStrategy: 'BIP45',
      };
      var signatures = WalletUtils.signTxp(txp, masterPrivateKey);
      signatures.length.should.be.equal(utxos.length);
    });
  });

  describe('#formatAmount', function() {
    it('should successfully format amount', function() {
      var cases = [{
        args: [1, 'bit'],
        expected: '0',
      }, {
        args: [1, 'btc'],
        expected: '0.00',
      }, {
        args: [0, 'bit'],
        expected: '0',
      }, {
        args: [12345678, 'bit'],
        expected: '123,457',
      }, {
        args: [12345678, 'btc'],
        expected: '0.123457',
      }, {
        args: [12345611, 'btc'],
        expected: '0.123456',
      }, {
        args: [1234, 'btc'],
        expected: '0.000012',
      }, {
        args: [1299, 'btc'],
        expected: '0.000013',
      }, {
        args: [1234567899999, 'btc'],
        expected: '12,345.679',
      }, {
        args: [12345678, 'bit', {
          thousandsSeparator: '.'
        }],
        expected: '123.457',
      }, {
        args: [12345678, 'btc', {
          decimalSeparator: ','
        }],
        expected: '0,123457',
      }, {
        args: [1234567899999, 'btc', {
          thousandsSeparator: ' ',
          decimalSeparator: ','
        }],
        expected: '12 345,679',
      }, ];

      _.each(cases, function(testCase) {
        WalletUtils.formatAmount.apply(this, testCase.args).should.equal(testCase.expected);
      });
    });
  });
  describe('#verifyRequestPubKey', function() {
    it('should generate and check request pub key', function() {
      var reqPubKey = (new Bitcore.PrivateKey).toPublicKey();
      var xPrivKey = new Bitcore.HDPrivateKey();
      var xPubKey = new Bitcore.HDPublicKey(xPrivKey);


      var sig = WalletUtils.signRequestPubKey(reqPubKey.toString(), xPrivKey);
      var valid = WalletUtils.verifyRequestPubKey(reqPubKey.toString(), sig, xPubKey);
      valid.should.be.equal(true);
    });
    it('should fail to check a request pub key with wrong key', function() {
      var reqPubKey = '02c2c1c6e75cfc50235ff4a2eb848385c2871b8c94e285ee82eaced1dcd5dd568e';
      var xPrivKey = new Bitcore.HDPrivateKey();
      var xPubKey = new Bitcore.HDPublicKey(xPrivKey);
      var sig = WalletUtils.signRequestPubKey(reqPubKey, xPrivKey);

      var xPrivKey2 = new Bitcore.HDPrivateKey();
      var xPubKey2 = new Bitcore.HDPublicKey(xPrivKey2);
      var valid = WalletUtils.verifyRequestPubKey(reqPubKey, sig, xPubKey2);
      valid.should.be.equal(false);
    });

  });

});
