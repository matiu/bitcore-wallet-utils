'use strict';

var _ = require('lodash');
var $ = require('preconditions').singleton();
var sjcl = require('sjcl');
var Stringify = require('json-stable-stringify');

var Bitcore = require('bitcore');
var Address = Bitcore.Address;
var PrivateKey = Bitcore.PrivateKey;
var PublicKey = Bitcore.PublicKey;
var crypto = Bitcore.crypto;
var encoding = Bitcore.encoding;

function WalletUtils() {};

WalletUtils.DERIVATION_STRATEGIES = {
  BIP44: 'BIP44',
  BIP45: 'BIP45',
};
WalletUtils.PATHS = {
  BASE_ADDRESS_DERIVATION: {
    'BIP45': {
      livenet: "m/45'",
      testnet: "m/45'",
    },
    'BIP44': {
      livenet: "m/44'/0'/0'",
      testnet: "m/44'/1'/0'",
    },
  },
  REQUEST_KEY: "m/1'/0",
  TXPROPOSAL_KEY: "m/1'/1",
  REQUEST_KEY_AUTH: "m/2", // relative to BASE_
};

WalletUtils.DEFAULT_FEE_PER_KB = 10000;
WalletUtils.MIN_FEE_PER_KB = 0;
WalletUtils.MAX_FEE_PER_KB = 1000000;
WalletUtils.MAX_TX_FEE = 1 * 1e8;

/* TODO: It would be nice to be compatible with bitcoind signmessage. How
 * the hash is calculated there? */
WalletUtils.hashMessage = function(text) {
  $.checkArgument(text);
  var buf = new Buffer(text);
  var ret = crypto.Hash.sha256sha256(buf);
  ret = new Bitcore.encoding.BufferReader(ret).readReverse();
  return ret;
};


WalletUtils.signMessage = function(text, privKey) {
  $.checkArgument(text);
  var priv = new PrivateKey(privKey);
  var hash = WalletUtils.hashMessage(text);
  return crypto.ECDSA.sign(hash, priv, 'little').toString();
};


WalletUtils.verifyMessage = function(text, signature, pubKey) {
  $.checkArgument(text);
  $.checkArgument(pubKey);

  if (!signature)
    return false;

  var pub = new PublicKey(pubKey);
  var hash = WalletUtils.hashMessage(text);

  try {
    var sig = new crypto.Signature.fromString(signature);
    return crypto.ECDSA.verify(hash, sig, pub, 'little');
  } catch (e) {
    return false;
  }
};

WalletUtils.deriveAddress = function(publicKeyRing, path, m, network) {
  var publicKeys = _.map(publicKeyRing, function(item) {
    var xpub = new Bitcore.HDPublicKey(item.xPubKey);
    return xpub.derive(path).publicKey;
  });

  var bitcoreAddress = Address.createMultisig(publicKeys, m, network);

  return {
    address: bitcoreAddress.toString(),
    path: path,
    publicKeys: _.invoke(publicKeys, 'toString'),
  };
};

WalletUtils.getProposalHash = function(proposalHeader) {
  function getOldHash(toAddress, amount, message, payProUrl) {
    return [toAddress, amount, (message || ''), (payProUrl || '')].join('|');
  };

  // For backwards compatibility
  if (arguments.length > 1) {
    return getOldHash.apply(this, arguments);
  }

  return Stringify(proposalHeader);
};

WalletUtils.getCopayerHash = function(name, xPubKey, requestPubKey) {
  return [name, xPubKey, requestPubKey].join('|');
};

WalletUtils.xPubToCopayerId = function(xpub) {
  var hash = sjcl.hash.sha256.hash(xpub);
  return sjcl.codec.hex.fromBits(hash);
};

WalletUtils.toSecret = function(walletId, walletPrivKey, network) {
  if (_.isString(walletPrivKey)) {
    walletPrivKey = Bitcore.PrivateKey.fromString(walletPrivKey);
  }
  var widHex = new Buffer(walletId.replace(/-/g, ''), 'hex');
  var widBase58 = new encoding.Base58(widHex).toString();
  return _.padRight(widBase58, 22, '0') + walletPrivKey.toWIF() + (network == 'testnet' ? 'T' : 'L');
};

WalletUtils.fromSecret = function(secret) {
  $.checkArgument(secret);

  function split(str, indexes) {
    var parts = [];
    indexes.push(str.length);
    var i = 0;
    while (i < indexes.length) {
      parts.push(str.substring(i == 0 ? 0 : indexes[i - 1], indexes[i]));
      i++;
    };
    return parts;
  };

  try {
    var secretSplit = split(secret, [22, 74]);
    var widBase58 = secretSplit[0].replace(/0/g, '');
    var widHex = encoding.Base58.decode(widBase58).toString('hex');
    var walletId = split(widHex, [8, 12, 16, 20]).join('-');

    var walletPrivKey = Bitcore.PrivateKey.fromString(secretSplit[1]);
    var networkChar = secretSplit[2];

    return {
      walletId: walletId,
      walletPrivKey: walletPrivKey,
      network: networkChar == 'T' ? 'testnet' : 'livenet',
    };
  } catch (ex) {
    throw new Error('Invalid secret');
  }
};


WalletUtils.encryptMessage = function(message, encryptingKey) {
  var key = sjcl.codec.base64.toBits(encryptingKey);
  return sjcl.encrypt(key, message, {
    ks: 128,
    iter: 1,
  });
};

WalletUtils.decryptMessage = function(cyphertextJson, encryptingKey) {
  var key = sjcl.codec.base64.toBits(encryptingKey);
  return sjcl.decrypt(key, cyphertextJson);
};

WalletUtils.privateKeyToAESKey = function(privKey) {
  $.checkArgument(privKey && _.isString(privKey));
  $.checkArgument(Bitcore.PrivateKey.isValid(privKey), 'The private key received is invalid');
  var pk = Bitcore.PrivateKey.fromString(privKey);
  return Bitcore.crypto.Hash.sha256(pk.toBuffer()).slice(0, 16).toString('base64');
};

WalletUtils.newBitcoreTransaction = function() {
  return new Bitcore.Transaction();
};

WalletUtils.buildTx = function(txp) {
  var t = WalletUtils.newBitcoreTransaction();

  _.each(txp.inputs, function(i) {
    t.from(i, i.publicKeys, txp.requiredSignatures);
  });

  if (txp.toAddress && txp.amount && !txp.outputs) {
    t.to(txp.toAddress, txp.amount);
  } else if (txp.outputs) {
    _.each(txp.outputs, function(o) {
      $.checkState(!o.script != !o.toAddress, 'Output should have either toAddress or script specified');
      if (o.script) {
        t.addOutput(new Bitcore.Transaction.Output({
          script: o.script,
          satoshis: o.amount
        }));
      } else {
        t.to(o.toAddress, o.amount);
      }
    });
  }

  if (_.startsWith(txp.version, '1.')) {
    Bitcore.Transaction.FEE_SECURITY_MARGIN = 1;
    t.feePerKb(txp.feePerKb);
  } else {
    t.fee(txp.fee);
  }

  t.change(txp.changeAddress.address);

  // Shuffle outputs for improved privacy
  if (t.outputs.length > 1) {
    $.checkState(t.outputs.length == txp.outputOrder.length);
    t.sortOutputs(function(outputs) {
      return _.map(txp.outputOrder, function(i) {
        return outputs[i];
      });
    });
  }

  // Validate inputs vs outputs independently of Bitcore
  var totalInputs = _.reduce(txp.inputs, function(memo, i) {
    return +i.satoshis + memo;
  }, 0);
  var totalOutputs = _.reduce(t.outputs, function(memo, o) {
    return +o.satoshis + memo;
  }, 0);

  $.checkState(totalInputs - totalOutputs <= WalletUtils.MAX_TX_FEE);

  return t;
};

WalletUtils.deriveXPrivFromMaster = function(masterXPriv, derivationStrategy, network) {
  var path = WalletUtils.PATHS.BASE_ADDRESS_DERIVATION[derivationStrategy][network];
  return new Bitcore.HDPrivateKey(masterXPriv, network).derive(path);
};

WalletUtils.signTxp = function(txp, xPrivKey) {
  var self = this;

  $.checkArgument(txp);
  $.checkArgument(xPrivKey);
  $.checkArgument(txp.amount || (txp.outputs && txp.outputs[0].amount), 'amount is invalid');
  $.checkArgument(txp.changeAddress && txp.changeAddress.address, 'changeAddress is invalid');

  $.checkState(_.contains(_.values(WalletUtils.DERIVATION_STRATEGIES), txp.derivationStrategy));

  //Derive proper key to sign, for each input
  var privs = [];
  var derived = {};

  var network = new Bitcore.Address(txp.changeAddress.address).network.name;
  var xpriv = WalletUtils.deriveXPrivFromMaster(xPrivKey, txp.derivationStrategy, network);

  _.each(txp.inputs, function(i) {
    if (!derived[i.path]) {
      derived[i.path] = xpriv.derive(i.path).privateKey;
      privs.push(derived[i.path]);
    }
  });

  var t = WalletUtils.buildTx(txp);

  var signatures = _.map(privs, function(priv, i) {
    return t.getSignatures(priv);
  });

  signatures = _.map(_.sortBy(_.flatten(signatures), 'inputIndex'), function(s) {
    return s.signature.toDER().toString('hex');
  });

  return signatures;
};

WalletUtils.getNetworkFromXPubKey = function(xPubKey) {
  $.checkArgument(xPubKey && _.isString(xPubKey));
  return xPubKey.substr(0, 4) == 'tpub' ? 'testnet' : 'livenet';
};

var _UNITS = {
  btc: {
    toSatoshis: 100000000,
    maxDecimals: 6,
    minDecimals: 2,
  },
  bit: {
    toSatoshis: 100,
    maxDecimals: 0,
    minDecimals: 0,
  },
};

WalletUtils.formatAmount = function(satoshis, unit, opts) {
  $.shouldBeNumber(satoshis);
  $.checkArgument(_.contains(_.keys(_UNITS), unit));

  function addSeparators(nStr, thousands, decimal, minDecimals) {
    nStr = nStr.replace('.', decimal);
    var x = nStr.split(decimal);
    var x0 = x[0];
    var x1 = x[1];

    x1 = _.dropRightWhile(x1, function(n, i) {
      return n == '0' && i >= minDecimals;
    }).join('');
    var x2 = x.length > 1 ? decimal + x1 : '';

    x0 = x0.replace(/\B(?=(\d{3})+(?!\d))/g, thousands);
    return x0 + x2;
  }

  opts = opts || {};

  var u = _UNITS[unit];
  var amount = (satoshis / u.toSatoshis).toFixed(u.maxDecimals);
  return addSeparators(amount, opts.thousandsSeparator || ',', opts.decimalSeparator || '.', u.minDecimals);
};


WalletUtils.signRequestPubKey = function(requestPubKey, xPrivKey) {
  var priv = new Bitcore.HDPrivateKey(xPrivKey).derive(WalletUtils.PATHS.REQUEST_KEY_AUTH).privateKey;
  return WalletUtils.signMessage(requestPubKey, priv);
};

WalletUtils.verifyRequestPubKey = function(requestPubKey, signature, xPubKey) {
  var pub = (new Bitcore.HDPublicKey(xPubKey)).derive(WalletUtils.PATHS.REQUEST_KEY_AUTH).publicKey;
  return WalletUtils.verifyMessage(requestPubKey, signature, pub.toString());
};

module.exports = WalletUtils;
