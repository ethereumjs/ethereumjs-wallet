var base58check = require('bs58check')
var createHmac = require('create-hmac')
var typeforce = require('typeforce')
var types = require('./types.js')
var ECPair = require('./hdkeypair.js')
var secp256k1 = require('secp256k1')
var ethUtil = require('ethereumjs-util')
var Wallet = require('./index.js')

var SECP256K1_N = new ethUtil.BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)

function HDNode (keyPair, chainCode) {
//  typeforce(types.tuple('HDKeyPair', types.Buffer256bit), arguments)
  typeforce(types.Buffer256bit, chainCode)

  if (!keyPair.compressed) throw new TypeError('BIP32 only allows compressed keyPairs')

  this.keyPair = keyPair
  this.chainCode = chainCode
  this.depth = 0
  this.index = 0
  this.parentFingerprint = 0x00000000
}

HDNode.HIGHEST_BIT = 0x80000000
HDNode.LENGTH = 78
HDNode.MASTER_SECRET = new Buffer('Bitcoin seed')
HDNode.VERSION_PUBLIC = 0x0488b21e
HDNode.VERSION_PRIVATE = 0x0488ade4

HDNode.fromSeedBuffer = function (seed) {
  typeforce(types.tuple(types.Buffer), arguments)

  if (seed.length < 16) throw new TypeError('Seed should be at least 128 bits')
  if (seed.length > 64) throw new TypeError('Seed should be at most 512 bits')

  var I = createHmac('sha512', HDNode.MASTER_SECRET).update(seed).digest()
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  // In case IL is 0 or >= n, the master key is invalid
  // This is handled by the ECPair constructor
  var keyPair = ECPair.fromPrivateKey(IL)

  return new HDNode(keyPair, IR)
}

HDNode.fromSeedHex = function (hex) {
  return HDNode.fromSeedBuffer(new Buffer(hex, 'hex'))
}

HDNode.fromBase58 = function (string) {
  var buffer = base58check.decode(string)
  if (buffer.length !== 78) throw new Error('Invalid buffer length')

  // 4 bytes: version bytes
  var version = buffer.readUInt32BE(0)

  if (version !== HDNode.VERSION_PRIVATE &&
    version !== HDNode.VERSION_PUBLIC) throw new Error('Invalid network')

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
  var depth = buffer[4]

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  var parentFingerprint = buffer.readUInt32BE(5)
  if (depth === 0) {
    if (parentFingerprint !== 0x00000000) throw new Error('Invalid parent fingerprint')
  }

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in MSB order. (0x00000000 if master key)
  var index = buffer.readUInt32BE(9)
  if (depth === 0 && index !== 0) throw new Error('Invalid index')

  // 32 bytes: the chain code
  var chainCode = buffer.slice(13, 45)
  var keyPair

  // 33 bytes: private key data (0x00 + k)
  if (version === HDNode.VERSION_PRIVATE) {
    if (buffer.readUInt8(45) !== 0x00) throw new Error('Invalid private key')

    keyPair = ECPair.fromPrivateKey(buffer.slice(46, 78))
  // 33 bytes: public key data (0x02 + X or 0x03 + X)
  } else {
    var publicKey = buffer.slice(45, 78)

    secp256k1.publicKeyVerify(publicKey)
    keyPair = ECPair.fromPublicKey(publicKey)

    // FIXME: implement this
    // if (!Q.compressed) throw new Error('Invalid public key')

    // Verify that the X coordinate in the public point corresponds to a point on the curve.
    // If not, the extended public key is invalid.

    // FIXME: this is done by secp256k1?
    // curve.validate(Q)
  }

  var hd = new HDNode(keyPair, chainCode)
  hd.depth = depth
  hd.index = index
  hd.parentFingerprint = parentFingerprint

  return hd
}

HDNode.prototype.getAddress = function () {
  return this.keyPair.getAddress()
}

HDNode.prototype.getIdentifier = function () {
  return ethUtil.ripemd160(ethUtil.sha256(this.keyPair.getPublicKey()))
}

HDNode.prototype.getFingerprint = function () {
  return this.getIdentifier().slice(0, 4)
}

HDNode.prototype.getPrivateKey = function () {
  return this.keyPair.getPrivateKey()
}

HDNode.prototype.getPublicKey = function () {
  return this.keyPair.getPublicKey()
}

HDNode.prototype.getWallet = function () {
  /* eslint-disable new-cap */
  if (this.isNeutered()) {
    return new Wallet.fromPublicKey(this.keyPair.getPublicKey())
  } else {
    return new Wallet.fromPrivateKey(this.keyPair.getPrivateKey())
  }
  /* eslint-ensable new-cap */
}

HDNode.prototype.neutered = function () {
  // To ensure there's no data leaking in keyPair
  var neuteredKeyPair = ECPair.fromPublicKey(this.keyPair.getPublicKey())

  var neutered = new HDNode(neuteredKeyPair, this.chainCode)
  neutered.depth = this.depth
  neutered.index = this.index
  neutered.parentFingerprint = this.parentFingerprint

  return neutered
}

HDNode.prototype.toBase58 = function () {
  // Version
  var version = (!this.isNeutered()) ? HDNode.VERSION_PRIVATE : HDNode.VERSION_PUBLIC
  var buffer = new Buffer(78)

  // 4 bytes: version bytes
  buffer.writeUInt32BE(version, 0)

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
  buffer.writeUInt8(this.depth, 4)

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  buffer.writeUInt32BE(this.parentFingerprint, 5)

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in big endian. (0x00000000 if master key)
  buffer.writeUInt32BE(this.index, 9)

  // 32 bytes: the chain code
  this.chainCode.copy(buffer, 13)

  // 33 bytes: the public key or private key data
  if (!this.isNeutered()) {
    // 0x00 + k for private keys
    buffer.writeUInt8(0, 45)
    this.keyPair.getPrivateKey().copy(buffer, 46)

  // 33 bytes: the public key
  } else {
    // X9.62 encoding for public keys
    this.keyPair.getPublicKey().copy(buffer, 45)
  }

  return base58check.encode(buffer)
}

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
HDNode.prototype.derive = function (index) {
  typeforce(types.UInt32, index)

  var isHardened = index >= HDNode.HIGHEST_BIT
  var data = new Buffer(37)

  // Hardened child
  if (isHardened) {
    if (this.isNeutered()) throw new TypeError('Could not derive hardened child key')

    // data = 0x00 || ser256(kpar) || ser32(index)
    data[0] = 0x00
    this.keyPair.getPrivateKey().copy(data, 1)
    data.writeUInt32BE(index, 33)

  // Normal child
  } else {
    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    this.keyPair.getPublicKey().copy(data, 0)
    data.writeUInt32BE(index, 33)
  }

  var I = createHmac('sha512', this.chainCode).update(data).digest()
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  var pIL = new ethUtil.BN(IL)

  // In case parse256(IL) >= n, proceed with the next value for i
  if (pIL.cmp(SECP256K1_N) >= 0) {
    return this.derive(index + 1)
  }

  // Private parent key -> private child key
  var derivedKeyPair
  if (!this.isNeutered()) {
    // ki = parse256(IL) + kpar (mod n)
    // FIXME use catch to do ki.num==0 case?
    var ki = secp256k1.privateKeyTweakAdd(this.keyPair.getPrivateKey(), IL)

    // In case ki == 0, proceed with the next value for i
    // if (new ethUtil.BN(ki).isZero()) {
    if (ki.toString('hex') === '0000000000000000000000000000000000000000000000000000000000000000') {
      return this.derive(index + 1)
    }

    derivedKeyPair = ECPair.fromPrivateKey(ki)

  // Public parent key -> public child key
  } else {
    // Ki = point(parse256(IL)) + Kpar
    //    = G*IL + Kpar
    var Ki = secp256k1.publicKeyTweakAdd(this.keyPair.getPublicKey(), IL, true)

    // In case Ki is the point at infinity, proceed with the next value for i
    // FIXME: do this with secp256k1
    // if (curve.isInfinity(Ki)) {
    //   return this.derive(index + 1)
    // }

    derivedKeyPair = ECPair.fromPublicKey(Ki)
  }

  var hd = new HDNode(derivedKeyPair, IR)
  hd.depth = this.depth + 1
  hd.index = index
  hd.parentFingerprint = this.getFingerprint().readUInt32BE(0)

  return hd
}

HDNode.prototype.deriveHardened = function (index) {
  typeforce(types.UInt31, index)

  // Only derives hardened private keys by default
  return this.derive(index + HDNode.HIGHEST_BIT)
}

// Private === not neutered
// Public === neutered
HDNode.prototype.isNeutered = function () {
  return !(this.keyPair.getPrivateKey())
}

HDNode.prototype.derivePath = function (path) {
  typeforce(types.Bip32Path, path)

  var splitPath = path.split('/')
  if (splitPath[0] === 'm') {
    if (this.parentFingerprint) {
      throw new Error('Not a master node')
    }

    splitPath = splitPath.slice(1)
  }

  return splitPath.reduce(function (prevHd, indexStr) {
    var index
    if (indexStr.slice(-1) === "'") {
      index = parseInt(indexStr.slice(0, -1), 10)
      return prevHd.deriveHardened(index)
    } else {
      index = parseInt(indexStr, 10)
      return prevHd.derive(index)
    }
  }, this)
}

HDNode.prototype.toString = HDNode.prototype.toBase58

module.exports = HDNode
