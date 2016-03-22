/*
 * The reason this exists is that BIP32 only supports compressed keys,
 * but Ethereum only uses uncompressed ones. We do not want to complicate
 * the Ethereum part with multiple types of keys. Let's keep this one
 * to work with BIP32 and convert once at export.
 */

var secp256k1 = require('secp256k1')

var HDKeyPair = function () {
  // FIXME: actually check for this

  this.compressed = true
}

HDKeyPair.fromPublicKey = function (publicKey) {
  // FIXME: reject uncompressed public key (or convert?)

  var account = new HDKeyPair()
  account.publicKey = publicKey
  return account
}

HDKeyPair.fromPrivateKey = function (privateKey) {
  if (!secp256k1.privateKeyVerify(privateKey)) {
    throw new Error('Invalid private key')
  }

  var account = new HDKeyPair()
  account.privateKey = privateKey
  return account
}

HDKeyPair.prototype.getPrivateKey = function () {
  return this.privateKey
}

HDKeyPair.prototype.getPublicKey = function (uncompressed) {
  if (!this.publicKey) {
    this.publicKey = secp256k1.publicKeyCreate(this.privateKey, true)
  }

  if (uncompressed) {
    return secp256k1.publicKeyConvert(this.publicKey, false)
  } else {
    return this.publicKey
  }
}

module.exports = HDKeyPair
