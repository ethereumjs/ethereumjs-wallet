const BIP32 = require('bip32')({
  highestBit: 0x80000000,
  masterSecret: new Buffer('Bitcoin seed'),
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4
  }
})

const Wallet = require('./index.js')

function EthereumHDKey () {
}

/*
 * Horrible wrapping.
 */
function fromHDKey (hdkey) {
  var ret = new EthereumHDKey()
  ret._hdkey = hdkey
  return ret
}

EthereumHDKey.fromMasterSeed = function (seedBuffer) {
  return fromHDKey(BIP32.fromSeed(seedBuffer))
}

EthereumHDKey.fromExtendedKey = function (base58key) {
  return fromHDKey(BIP32.fromString(base58key))
}

EthereumHDKey.prototype.privateExtendedKey = function () {
  return this._hdkey.getSerializedPrivateKey()
}

EthereumHDKey.prototype.publicExtendedKey = function () {
  return this._hdkey.getSerializedPublicKey()
}

EthereumHDKey.prototype.derivePath = function (path) {
  return fromHDKey(this._hdkey.derive(path))
}

EthereumHDKey.prototype.deriveChild = function (index) {
  return fromHDKey(this._hdkey.derive(index))
}

EthereumHDKey.prototype.getWallet = function () {
  if (this._hdkey._privateKey) {
    return Wallet.fromPrivateKey(this._hdkey.getPrivateKey())
  } else {
    return Wallet.fromPublicKey(this._hdkey.getPublicKey(), true)
  }
}

module.exports = EthereumHDKey
