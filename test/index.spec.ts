/* tslint:disable no-invalid-this */
import * as assert from 'assert'
import { BN } from 'ethereumjs-util'
import { Wallet as ethersWallet } from 'ethers'

const zip = require('lodash.zip')

import Wallet from '../src'
import Thirdparty from '../src/thirdparty'

const n = 262144
const r = 8
const p = 1

const fixturePrivateKey = 'efca4cdd31923b50f4214af5d2ae10e7ac45a5019e9431cc195482d707485378'
const fixturePrivateKeyStr = '0x' + fixturePrivateKey
const fixturePrivateKeyBuffer = Buffer.from(fixturePrivateKey, 'hex')

const fixturePublicKey =
  '5d4392f450262b276652c1fc037606abac500f3160830ce9df53aa70d95ce7cfb8b06010b2f3691c78c65c21eb4cf3dfdbfc0745d89b664ee10435bb3a0f906c'
const fixturePublicKeyStr = '0x' + fixturePublicKey
const fixturePublicKeyBuffer = Buffer.from(fixturePublicKey, 'hex')

const fixtureWallet = Wallet.fromPrivateKey(fixturePrivateKeyBuffer)
const fixtureEthersWallet = new ethersWallet(fixtureWallet.getPrivateKeyString())

const isRunningInKarma = () => {
  return typeof (global as any).window !== 'undefined' && (global as any).window.__karma__
}

describe('.getPrivateKey()', function () {
  it('should work', function () {
    assert.strictEqual(fixtureWallet.getPrivateKey().toString('hex'), fixturePrivateKey)
  })
  it('should fail', function () {
    assert.throws(function () {
      Wallet.fromPrivateKey(Buffer.from('001122', 'hex'))
    }, /^Error: Expected private key to be an Uint8Array with length 32$/)
  })
})

describe('.getPrivateKeyString()', function () {
  it('should work', function () {
    assert.strictEqual(fixtureWallet.getPrivateKeyString(), fixturePrivateKeyStr)
  })
})

describe('.getPublicKey()', function () {
  it('should work', function () {
    assert.strictEqual(fixtureWallet.getPublicKey().toString('hex'), fixturePublicKey)
  })
})

describe('.getPublicKeyString()', function () {
  it('should work', function () {
    assert.strictEqual(fixtureWallet.getPublicKeyString(), fixturePublicKeyStr)
  })
})

describe('.getAddress()', function () {
  it('should work', function () {
    assert.strictEqual(
      fixtureWallet.getAddress().toString('hex'),
      'b14ab53e38da1c172f877dbc6d65e4a1b0474c3c'
    )
  })
})

describe('.getAddressString()', function () {
  it('should work', function () {
    assert.strictEqual(
      fixtureWallet.getAddressString(),
      '0xb14ab53e38da1c172f877dbc6d65e4a1b0474c3c'
    )
  })
})

describe('.getChecksumAddressString()', function () {
  it('should work', function () {
    assert.strictEqual(
      fixtureWallet.getChecksumAddressString(),
      '0xB14Ab53E38DA1C172f877DBC6d65e4a1B0474C3c'
    )
  })
})

describe('public key only wallet', function () {
  const pubKey = Buffer.from(fixturePublicKey, 'hex')
  it('.fromPublicKey() should work', function () {
    assert.strictEqual(
      Wallet.fromPublicKey(pubKey).getPublicKey().toString('hex'),
      fixturePublicKey
    )
  })
  it('.fromPublicKey() should not accept compressed keys in strict mode', function () {
    assert.throws(function () {
      Wallet.fromPublicKey(
        Buffer.from('030639797f6cc72aea0f3d309730844a9e67d9f1866e55845c5f7e0ab48402973d', 'hex')
      )
    }, /^Error: Invalid public key$/)
  })
  it('.fromPublicKey() should accept compressed keys in non-strict mode', function () {
    const tmp = Buffer.from(
      '030639797f6cc72aea0f3d309730844a9e67d9f1866e55845c5f7e0ab48402973d',
      'hex'
    )
    assert.strictEqual(
      Wallet.fromPublicKey(tmp, true).getPublicKey().toString('hex'),
      '0639797f6cc72aea0f3d309730844a9e67d9f1866e55845c5f7e0ab48402973defa5cb69df462bcc6d73c31e1c663c225650e80ef14a507b203f2a12aea55bc1'
    )
  })
  it('.getAddress() should work', function () {
    assert.strictEqual(
      Wallet.fromPublicKey(pubKey).getAddress().toString('hex'),
      'b14ab53e38da1c172f877dbc6d65e4a1b0474c3c'
    )
  })
  it('.getPrivateKey() should fail', function () {
    assert.throws(function () {
      Wallet.fromPublicKey(pubKey).getPrivateKey()
    }, /^Error: This is a public key only wallet$/)
  })
  // it('.toV3() should fail', function () {
  //   assert.throws(function () {
  //     Wallet.fromPublicKey(pubKey).toV3()
  //   }, /^Error: This is a public key only wallet$/)
  // })
})

describe('.fromExtendedPrivateKey()', function () {
  it('should work', function () {
    const xprv =
      'xprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY'
    assert.strictEqual(
      Wallet.fromExtendedPrivateKey(xprv).getAddressString(),
      '0xb800bf5435f67c7ee7d83c3a863269969a57c57c'
    )
  })
})

describe('.fromExtendedPublicKey()', function () {
  it('should work', function () {
    const xpub =
      'xpub661MyMwAqRbcGout4B6s29b6gGQsowyoiF6UgXBEr7eFCWYfXuZDvRxP9zEh1Kwq3TLqDQMbkbaRpSnoC28oWvjLeshoQz1StZ9YHM1EpcJ'
    assert.strictEqual(
      Wallet.fromExtendedPublicKey(xpub).getAddressString(),
      '0xb800bf5435f67c7ee7d83c3a863269969a57c57c'
    )
  })
})

describe('.generate()', function () {
  it('should generate an account', function () {
    assert.strictEqual(Wallet.generate().getPrivateKey().length, 32)
  })
  it('should generate an account compatible with ICAP Direct', function () {
    const max = new BN('088f924eeceeda7fe92e1f5b0fffffffffffffff', 16)
    const wallet = Wallet.generate(true)
    assert.strictEqual(wallet.getPrivateKey().length, 32)
    assert.strictEqual(new BN(wallet.getAddress()).lte(max), true)
  })
})

describe('.generateVanityAddress()', function () {
  it('should generate an account with 000 prefix (object)', function () {
    this.timeout(0) // never
    const wallet = Wallet.generateVanityAddress(/^000/)
    assert.strictEqual(wallet.getPrivateKey().length, 32)
    assert.strictEqual(wallet.getAddress()[0], 0)
    assert.strictEqual(wallet.getAddress()[1] >>> 4, 0)
  })
  it('should generate an account with 000 prefix (string)', function () {
    this.timeout(0) // never
    const wallet = Wallet.generateVanityAddress('^000')
    assert.strictEqual(wallet.getPrivateKey().length, 32)
    assert.strictEqual(wallet.getAddress()[0], 0)
    assert.strictEqual(wallet.getAddress()[1] >>> 4, 0)
  })
})

describe('.getV3Filename()', function () {
  it('should work', function () {
    assert.strictEqual(
      fixtureWallet.getV3Filename(1457917509265),
      'UTC--2016-03-14T01-05-09.265Z--b14ab53e38da1c172f877dbc6d65e4a1b0474c3c'
    )
  })
})

describe('.toV3()', function () {
  const pw = 'testtest'
  const salt = 'dc9e4a98886738bd8aae134a1f89aaa5a502c3fbd10e336136d4d5fe47448ad6'
  const iv = 'cecacd85e9cb89788b5aab2f93361233'
  const uuid = '7e59dc028d42d09db29aa8a0f862cc81'

  const strKdfOptions = { iv, salt, uuid }
  const buffKdfOptions = {
    salt: Buffer.from(salt, 'hex'),
    iv: Buffer.from(iv, 'hex'),
    uuid: Buffer.from(uuid, 'hex'),
  }

  // generate all possible combinations of salt, iv, uuid properties, e.g.
  // {salt: [string], iv: [buffer], uuid: [string]}
  // the number of objects is naturally a radix for selecting one of the
  // input values for a given property; example, three objects and two keys:
  // [{a: 0, b: 0},
  //  {a: 1, b: 1},
  //  {a: 2, b: 2}]
  const makePermutations = (...objs: Array<object>): Array<object> => {
    const permus = []
    const keys = Array.from(
      objs.reduce((acc: any, curr: object) => {
        Object.keys(curr).forEach((key) => {
          acc.add(key)
        })
        return acc
      }, new Set())
    )
    const radix = objs.length
    const numPermus = radix ** keys.length
    for (let permuIdx = 0; permuIdx < numPermus; permuIdx++) {
      const selectors = permuIdx
        .toString(radix)
        .padStart(keys.length, '0')
        .split('')
        .map((v) => parseInt(v, 10))
      const obj: any = {}
      zip(selectors, keys).forEach(([sel, k]: [number, string]) => {
        if ((objs as any)[sel].hasOwnProperty(k)) {
          obj[k] = (objs as any)[sel][k]
        }
      })
      permus.push(obj)
    }
    return permus
  }

  const makeEthersOptions = (opts: object) => {
    const obj: any = {}
    Object.entries(opts).forEach(([key, val]: [string, string | Buffer]) => {
      obj[key] = typeof val === 'string' ? '0x' + val : val
    })
    return obj
  }

  let permutations = makePermutations(strKdfOptions, buffKdfOptions)

  if (isRunningInKarma()) {
    // These tests take a long time in the browser due to
    // the amount of permutations so we will shorten them.
    permutations = permutations.slice(1)
  }

  it('should work with PBKDF2', async function () {
    this.timeout(0) // never
    const w =
      '{"version":3,"id":"7e59dc02-8d42-409d-b29a-a8a0f862cc81","address":"b14ab53e38da1c172f877dbc6d65e4a1b0474c3c","crypto":{"ciphertext":"01ee7f1a3c8d187ea244c92eea9e332ab0bb2b4c902d89bdd71f80dc384da1be","cipherparams":{"iv":"cecacd85e9cb89788b5aab2f93361233"},"cipher":"aes-128-ctr","kdf":"pbkdf2","kdfparams":{"dklen":32,"salt":"dc9e4a98886738bd8aae134a1f89aaa5a502c3fbd10e336136d4d5fe47448ad6","c":262144,"prf":"hmac-sha256"},"mac":"0c02cd0badfebd5e783e0cf41448f84086a96365fc3456716c33641a86ebc7cc"}}'

    await Promise.all(
      (
        permutations as Array<{
          salt: string | Buffer
          iv: string | Buffer
          uuid: string | Buffer
        }>
      ).map(async function ({ salt, iv, uuid }) {
        const encFixtureWallet = await fixtureWallet.toV3String(pw, {
          kdf: 'pbkdf2',
          c: n,
          uuid: uuid,
          salt: salt,
          iv: iv,
        })

        assert.deepStrictEqual(JSON.parse(w), JSON.parse(encFixtureWallet))
        // ethers doesn't support encrypting with PBKDF2
      })
    )
  })
  it('should work with Scrypt', async function () {
    this.timeout(0) // never
    const wStatic =
      '{"version":3,"id":"7e59dc02-8d42-409d-b29a-a8a0f862cc81","address":"b14ab53e38da1c172f877dbc6d65e4a1b0474c3c","crypto":{"ciphertext":"c52682025b1e5d5c06b816791921dbf439afe7a053abb9fac19f38a57499652c","cipherparams":{"iv":"cecacd85e9cb89788b5aab2f93361233"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"dc9e4a98886738bd8aae134a1f89aaa5a502c3fbd10e336136d4d5fe47448ad6","n":262144,"r":8,"p":1},"mac":"27b98c8676dc6619d077453b38db645a4c7c17a3e686ee5adaf53c11ac1b890e"}}'
    const wRandom = Wallet.generate()
    const wEthers = new ethersWallet(wRandom.getPrivateKeyString())

    await Promise.all(
      (
        permutations as Array<{
          salt: string | Buffer
          iv: string | Buffer
          uuid: string | Buffer
        }>
      ).map(async function ({ salt, iv, uuid }) {
        const ethersOpts = makeEthersOptions({ salt, iv, uuid })

        const encFixtureWallet = await fixtureWallet.toV3String(pw, {
          kdf: 'scrypt',
          uuid: uuid,
          salt: salt,
          iv: iv,
          n: n,
          r: r,
          p: p,
        })

        const encFixtureEthersWallet = (
          await fixtureEthersWallet.encrypt(pw, {
            scrypt: { N: n, r: r, p: p },
            salt: ethersOpts.salt,
            iv: ethersOpts.iv,
            uuid: ethersOpts.uuid,
          })
        ).toLowerCase()

        const encRandomWallet = await wRandom.toV3String(pw, {
          kdf: 'scrypt',
          uuid: uuid,
          salt: salt,
          iv: iv,
          n: n,
          r: r,
          p: p,
        })

        const encEthersWallet = (
          await wEthers.encrypt(pw, {
            scrypt: { N: n, r: r, p: p },
            salt: ethersOpts.salt,
            iv: ethersOpts.iv,
            uuid: ethersOpts.uuid,
          })
        ).toLowerCase()

        assert.deepStrictEqual(JSON.parse(wStatic), JSON.parse(encFixtureWallet))
        assert.deepStrictEqual(JSON.parse(wStatic), JSON.parse(encFixtureEthersWallet))
        assert.deepStrictEqual(JSON.parse(encRandomWallet), JSON.parse(encEthersWallet))
      })
    )
  })
  it('should work without providing options', async function () {
    this.timeout(0) // never
    const wallet = await fixtureWallet.toV3('testtest')
    assert.strictEqual(wallet['version'], 3)
  })
  it('should fail for unsupported kdf', function () {
    this.timeout(0) // never
    assert.rejects(async function () {
      await fixtureWallet.toV3('testtest', { kdf: 'superkey' })
    }, /^Error: Unsupported kdf$/)
  })
  it('should fail for bad salt', function () {
    const pw = 'test'
    const errStr =
      /^Error: Invalid salt, string must be empty or a non-zero even number of hex characters$/

    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { salt: 'f' })
    }, errStr)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { salt: 'fff' })
    }, errStr)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { salt: 'xfff' })
    }, errStr)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { salt: 'fffx' })
    }, errStr)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { salt: 'fffxff' })
    }, errStr)
    assert.rejects(async function () {
      // @ts-ignore
      await fixtureWallet.toV3(pw, { salt: {} })
    }, /^Error: Invalid salt, must be a string \(empty or a non-zero even number of hex characters\) or buffer$/)
  })
  it('should work with empty salt', async function () {
    this.timeout(0) // never
    const pw = 'test'
    let salt: any = ''
    let w = await fixtureWallet.toV3(pw, { salt: salt, kdf: 'pbkdf2' })

    assert.strictEqual(salt, w.crypto.kdfparams.salt)
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(w, pw)).getPrivateKeyString()
    )

    salt = '0x'
    w = await fixtureWallet.toV3(pw, { salt: salt, kdf: 'pbkdf2' })

    assert.strictEqual('', w.crypto.kdfparams.salt)
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(w, pw)).getPrivateKeyString()
    )

    salt = Buffer.from('', 'hex')
    w = await fixtureWallet.toV3(pw, { salt: salt, kdf: 'pbkdf2' })

    assert.strictEqual('', w.crypto.kdfparams.salt)
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(w, pw)).getPrivateKeyString()
    )

    salt = ''
    let iv = 'ffffffffffffffffffffffffffffffff'
    let uuid = 'ffffffffffffffffffffffffffffffff'
    let wStr = await fixtureWallet.toV3String(pw, {
      salt: salt,
      iv: iv,
      uuid: uuid,
      kdf: 'scrypt',
      n: n,
      r: r,
      p: p,
    })
    let wEthersStr = await new ethersWallet(fixtureWallet.getPrivateKeyString()).encrypt(pw, {
      scrypt: { N: n, r: r, p: p },
      salt: '0x' + (salt as string),
      iv: '0x' + iv,
      uuid: '0x' + uuid,
    })

    assert.strictEqual(salt, JSON.parse(wStr).crypto.kdfparams.salt)
    assert.deepStrictEqual(JSON.parse(wStr), JSON.parse(wEthersStr.toLowerCase()))
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(JSON.parse(wStr), pw)).getPrivateKeyString()
    )
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await ethersWallet.fromEncryptedJson(wEthersStr, pw)).privateKey
    )

    salt = '0x'
    iv = '0x' + iv
    uuid = '0x' + uuid
    wStr = await fixtureWallet.toV3String(pw, {
      salt: salt,
      iv: iv,
      uuid: uuid,
      kdf: 'scrypt',
      n: n,
      r: r,
      p: p,
    })
    wEthersStr = await new ethersWallet(fixtureWallet.getPrivateKeyString()).encrypt(pw, {
      scrypt: { N: n, r: r, p: p },
      salt: salt,
      iv: iv,
      uuid: uuid,
    })

    assert.strictEqual('', JSON.parse(wStr).crypto.kdfparams.salt)
    assert.deepStrictEqual(JSON.parse(wStr), JSON.parse(wEthersStr.toLowerCase()))
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(JSON.parse(wStr), pw)).getPrivateKeyString()
    )
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await ethersWallet.fromEncryptedJson(wEthersStr, pw)).privateKey
    )

    salt = Buffer.from('', 'hex')
    wStr = await fixtureWallet.toV3String(pw, {
      salt: salt,
      iv: iv,
      uuid: uuid,
      kdf: 'scrypt',
      n: n,
      r: r,
      p: p,
    })
    wEthersStr = await new ethersWallet(fixtureWallet.getPrivateKeyString()).encrypt(pw, {
      scrypt: { N: n, r: r, p: p },
      salt: salt,
      iv: iv,
      uuid: uuid,
    })

    assert.strictEqual('', JSON.parse(wStr).crypto.kdfparams.salt)
    assert.deepStrictEqual(JSON.parse(wStr), JSON.parse(wEthersStr.toLowerCase()))
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(JSON.parse(wStr), pw)).getPrivateKeyString()
    )
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await ethersWallet.fromEncryptedJson(wEthersStr, pw)).privateKey
    )
  })
  it('should fail for bad iv', function () {
    const pw = 'test'
    const errStrLength = /^Error: Invalid iv, string must be 32 hex characters$/
    const errBuffLength = /^Error: Invalid iv, buffer must be 16 bytes$/

    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: '' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: 'ff' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: 'ffffffffffffffffffffffffffffffffff' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: 'xfffffffffffffffffffffffffffffff' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: 'fffffffffffffffffffffffffffffffx' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: 'fffffffffffffffxffffffffffffffff' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: Buffer.from('', 'hex') })
    }, errBuffLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: Buffer.from('ff', 'hex') })
    }, errBuffLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { iv: Buffer.from('ffffffffffffffffffffffffffffffffff', 'hex') })
    }, errBuffLength)
    assert.rejects(async function () {
      // @ts-ignore
      await fixtureWallet.toV3(pw, { iv: {} })
    }, /^Error: Invalid iv, must be a string \(32 hex characters\) or buffer \(16 bytes\)$/)
  })
  it('should fail for bad uuid', function () {
    const pw = 'test'
    const errStrLength = /^Error: Invalid uuid, string must be 32 hex characters$/
    const errBuffLength = /^Error: Invalid uuid, buffer must be 16 bytes$/

    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { uuid: '' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { uuid: 'ff' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { uuid: 'ffffffffffffffffffffffffffffffffff' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { uuid: 'xfffffffffffffffffffffffffffffff' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { uuid: 'fffffffffffffffffffffffffffffffx' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { uuid: 'fffffffffffffffxffffffffffffffff' })
    }, errStrLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { uuid: Buffer.from('', 'hex') })
    }, errBuffLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, { uuid: Buffer.from('ff', 'hex') })
    }, errBuffLength)
    assert.rejects(async function () {
      await fixtureWallet.toV3(pw, {
        uuid: Buffer.from('ffffffffffffffffffffffffffffffffff', 'hex'),
      })
    }, errBuffLength)
    assert.rejects(async function () {
      // @ts-ignore
      await fixtureWallet.toV3(pw, { uuid: {} })
    }, /^Error: Invalid uuid, must be a string \(32 hex characters\) or buffer \(16 bytes\)$/)
  })
  it('should strip leading "0x" from salt, iv, uuid', async function () {
    this.timeout(0) // never
    const pw = 'test'
    const salt =
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    const iv = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    const uuid = 'cccccccccccccccccccccccccccccccc'
    let w = await fixtureWallet.toV3(pw, {
      salt: '0x' + salt,
      iv: '0X' + iv,
      uuid: '0x' + uuid,
      kdf: 'pbkdf2',
    })
    let w2 = await fixtureWallet.toV3(pw, {
      salt: '0x' + salt,
      iv: '0X' + iv,
      uuid: uuid,
      kdf: 'pbkdf2',
    })

    assert.strictEqual(salt, w.crypto.kdfparams.salt)
    assert.strictEqual(iv, w.crypto.cipherparams.iv)
    assert.strictEqual(w.id, w2.id)
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(w, pw)).getPrivateKeyString()
    )
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(w2, pw)).getPrivateKeyString()
    )

    w = await fixtureWallet.toV3(pw, {
      salt: '0x' + salt,
      iv: '0X' + iv,
      uuid: '0x' + uuid,
      kdf: 'scrypt',
    })
    w2 = await fixtureWallet.toV3(pw, {
      salt: '0x' + salt,
      iv: '0X' + iv,
      uuid: uuid,
      kdf: 'scrypt',
    })

    assert.strictEqual(salt, w.crypto.kdfparams.salt)
    assert.strictEqual(iv, w.crypto.cipherparams.iv)
    assert.strictEqual(w.id, w2.id)
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(w, pw)).getPrivateKeyString()
    )
    assert.strictEqual(
      fixtureWallet.getPrivateKeyString(),
      (await Wallet.fromV3(w2, pw)).getPrivateKeyString()
    )
  })
})

/*
describe('.fromV1()', function () {
  it('should work', function () {
    const sample = '{"Address":"d4584b5f6229b7be90727b0fc8c6b91bb427821f","Crypto":{"CipherText":"07533e172414bfa50e99dba4a0ce603f654ebfa1ff46277c3e0c577fdc87f6bb4e4fe16c5a94ce6ce14cfa069821ef9b","IV":"16d67ba0ce5a339ff2f07951253e6ba8","KeyHeader":{"Kdf":"scrypt","KdfParams":{"DkLen":32,"N":262144,"P":1,"R":8,"SaltLen":32},"Version":"1"},"MAC":"8ccded24da2e99a11d48cda146f9cc8213eb423e2ea0d8427f41c3be414424dd","Salt":"06870e5e6a24e183a5c807bd1c43afd86d573f7db303ff4853d135cd0fd3fe91"},"Id":"0498f19a-59db-4d54-ac95-33901b4f1870","Version":"1"}'
    const wallet = Wallet.fromV1(sample, 'foo')
    assert.strictEqual(wallet.getAddressString(), '0xd4584b5f6229b7be90727b0fc8c6b91bb427821f')
  })
})
*/

describe('.fromV3()', function () {
  it('should work with PBKDF2', async function () {
    const w =
      '{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},"ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","kdf":"pbkdf2","kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}'
    let wEthersCompat = JSON.parse(w)
    // see: https://github.com/ethers-io/ethers.js/issues/582
    wEthersCompat.address = '0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b'
    wEthersCompat = JSON.stringify(wEthersCompat)
    const pw = 'testpassword'
    const wallet = await Wallet.fromV3(w, pw)
    const wRandom = await Wallet.generate().toV3String(pw, { kdf: 'pbkdf2' })
    const walletRandom = await Wallet.fromV3(wRandom, pw)

    this.timeout(0) // never
    assert.strictEqual(wallet.getAddressString(), '0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b')
    assert.strictEqual(
      wallet.getAddressString(),
      (await ethersWallet.fromEncryptedJson(wEthersCompat, pw)).address.toLowerCase()
    )
    assert.strictEqual(
      walletRandom.getAddressString(),
      (await ethersWallet.fromEncryptedJson(wRandom, pw)).address.toLowerCase()
    )
  })
  it('should work with Scrypt', async function () {
    this.timeout(0) // never
    const sample =
      '{"address":"2f91eb73a6cd5620d7abb50889f24eea7a6a4feb","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"a2bc4f71e8445d64ceebd1247079fbd8"},"ciphertext":"6b9ab7954c9066fa1e54e04e2c527c7d78a77611d5f84fede1bd61ab13c51e3e","kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"r":1,"p":8,"salt":"caf551e2b7ec12d93007e528093697a4c68e8a50e663b2a929754a8085d9ede4"},"mac":"506cace9c5c32544d39558025cb3bf23ed94ba2626e5338c82e50726917e1a15"},"id":"1b3cad9b-fa7b-4817-9022-d5e598eb5fe3","version":3}'
    const pw = 'testtest'
    const wallet = await Wallet.fromV3(sample, pw)
    const sampleRandom = await Wallet.generate().toV3String(pw)
    const walletRandom = await Wallet.fromV3(sampleRandom, pw)

    assert.strictEqual(wallet.getAddressString(), '0x2f91eb73a6cd5620d7abb50889f24eea7a6a4feb')
    assert.strictEqual(
      wallet.getAddressString(),
      (await ethersWallet.fromEncryptedJson(sample, pw)).address.toLowerCase()
    )
    assert.strictEqual(
      walletRandom.getAddressString(),
      (await ethersWallet.fromEncryptedJson(sampleRandom, pw)).address.toLowerCase()
    )
  })
  it("should work with 'unencrypted' wallets", async function () {
    this.timeout(0) // never
    const w =
      '{"address":"a9886ac7489ecbcbd79268a79ef00d940e5fe1f2","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c542cf883299b5b0a29155091054028d"},"ciphertext":"0a83c77235840cffcfcc5afe5908f2d7f89d7d54c4a796dfe2f193e90413ee9d","kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"r":1,"p":8,"salt":"699f7bf5f6985068dfaaff9db3b06aea8fe3dd3140b3addb4e60620ee97a0316"},"mac":"613fed2605240a2ff08b8d93ccc48c5b3d5023b7088189515d70df41d65f44de"},"id":"0edf817a-ee0e-4e25-8314-1f9e88a60811","version":3}'
    const wallet = await Wallet.fromV3(w, '')
    assert.strictEqual(wallet.getAddressString(), '0xa9886ac7489ecbcbd79268a79ef00d940e5fe1f2')
  })
  it('should fail with invalid password', function () {
    const w =
      '{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},"ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","kdf":"pbkdf2","kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}'
    this.timeout(0) // never
    assert.rejects(async function () {
      await Wallet.fromV3(w, 'wrongtestpassword')
    }, /^Error: Key derivation failed - possibly wrong passphrase$/)
  })
  it('should work with (broken) mixed-case input files', async function () {
    const w =
      '{"Crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},"ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","kdf":"pbkdf2","kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}'
    this.timeout(0) // never
    const wallet = await Wallet.fromV3(w, 'testpassword', true)
    assert.strictEqual(wallet.getAddressString(), '0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b')
  })
  it("shouldn't work with (broken) mixed-case input files in strict mode", function () {
    const w =
      '{"Crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},"ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","kdf":"pbkdf2","kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}'
    this.timeout(0) // never
    assert.rejects(async function () {
      await Wallet.fromV3(w, 'testpassword')
    }) // FIXME: check for assert message(s)
  })
  it('should fail for wrong version', function () {
    const w = '{"version":2}'
    assert.rejects(async function () {
      await Wallet.fromV3(w, 'testpassword')
    }, /^Error: Not a V3 wallet$/)
  })
  it('should fail for wrong kdf', function () {
    const w = '{"crypto":{"kdf":"superkey"},"version":3}'
    assert.rejects(async function () {
      await Wallet.fromV3(w, 'testpassword')
    }, /^Error: Unsupported key derivation scheme$/)
  })
  it('should fail for wrong prf in pbkdf2', function () {
    const w = '{"crypto":{"kdf":"pbkdf2","kdfparams":{"prf":"invalid"}},"version":3}'
    assert.rejects(async function () {
      await Wallet.fromV3(w, 'testpassword')
    }, /^Error: Unsupported parameters to PBKDF2$/)
  })
})

describe('.fromEthSale()', function () {
  // Generated using https://github.com/ethereum/pyethsaletool/ [4afd19ad60cee8d09b645555180bc3a7c8a25b67]
  it('should work with short password (8 characters)', function () {
    const json =
      '{"encseed": "81ffdfaf2736310ce87df268b53169783e8420b98f3405fb9364b96ac0feebfb62f4cf31e0d25f1ded61f083514dd98c3ce1a14a24d7618fd513b6d97044725c7d2e08a7d9c2061f2c8a05af01f06755c252f04cab20fee2a4778130440a9344", "ethaddr": "22f8c5dd4a0a9d59d580667868df2da9592ab292", "email": "hello@ethereum.org", "btcaddr": "1DHW32MFwHxU2nk2SLAQq55eqFotT9jWcq"}'
    const wallet = Wallet.fromEthSale(json, 'testtest')
    assert.strictEqual(wallet.getAddressString(), '0x22f8c5dd4a0a9d59d580667868df2da9592ab292')
  })
  it('should work with long password (19 characters)', function () {
    const json =
      '{"encseed": "0c7e462bd67c6840ed2fa291090b2f46511b798d34492e146d6de148abbccba45d8fcfc06bea2e5b9d6c5d17b51a9a046c1054a032f24d96a56614a14dcd02e3539685d7f09b93180067160f3a9db648ccca610fc2f983fc65bf973304cbf5b6", "ethaddr": "c90b232231c83b462723f473b35cb8b1db868108", "email": "thisisalongpassword@test.com", "btcaddr": "1Cy2fN2ov5BrMkzgrzE34YadCH2yLMNkTE"}'
    const wallet = Wallet.fromEthSale(json, 'thisisalongpassword')
    assert.strictEqual(wallet.getAddressString(), '0xc90b232231c83b462723f473b35cb8b1db868108')
  })
  // From https://github.com/ryepdx/pyethrecover/blob/master/test_wallets/ico.json
  it("should work with pyethrecover's wallet", function () {
    const json =
      '{"encseed": "8b4001bf61a10760d8e0876fb791e4ebeb85962f565c71697c789c23d1ade4d1285d80b2383ae5fc419ecf5319317cd94200b65df0cc50d659cbbc4365fc08e8", "ethaddr": "83b6371ba6bd9a47f82a7c4920835ef4be08f47b", "bkp": "9f566775e56486f69413c59f7ef923bc", "btcaddr": "1Nzg5v6uRCAa6Fk3CUU5qahWxEDZdZ1pBm"}'
    const wallet = Wallet.fromEthSale(json, 'password123')
    assert.strictEqual(wallet.getAddressString(), '0x83b6371ba6bd9a47f82a7c4920835ef4be08f47b')
  })
})

describe('.fromEtherWallet()', function () {
  // it('should work with unencrypted input', function () {
  //   const etherWalletUnencrypted = '{"address":"0x9d6abd11d36cc20d4836c25967f1d9efe6b1a27c","encrypted":true,"locked":false,"hash":"b7a6621e8b125a17234d3e5c35522696a84134d98d07eab2479d020a8613c4bd","private":"a2c6222146ca2269086351fda9f8d2dfc8a50331e8a05f0f400c13653a521862","public":"2ed129b50b1a4dbbc53346bf711df6893265ad0c700fd11431b0bc3a66bd383a87b10ad835804a6cbe092e0375a0cc3524acf06b1ec7bb978bf25d2d6c35d120"}'
  //   const wallet = Thirdparty.fromEtherWallet(etherWalletUnencrypted)
  //   assert.strictEqual(wallet.getAddressString(), '0x9d6abd11d36cc20d4836c25967f1d9efe6b1a27c')
  // })
  it('should work with encrypted input', function () {
    const etherWalletEncrypted =
      '{"address":"0x9d6abd11d36cc20d4836c25967f1d9efe6b1a27c","encrypted":true,"locked":true,"hash":"b7a6621e8b125a17234d3e5c35522696a84134d98d07eab2479d020a8613c4bd","private":"U2FsdGVkX1/hGPYlTZYGhzdwvtkoZfkeII4Ga4pSd/Ak373ORnwZE4nf/FFZZFcDTSH1X1+AmewadrW7dqvwr76QMYQVlihpPaFV307hWgKckkG0Mf/X4gJIQQbDPiKdcff9","public":"U2FsdGVkX1/awUDAekZQbEiXx2ct4ugXwgBllY0Hz+IwYkHiEhhxH+obu7AF7PCU2Vq5c0lpCzBUSvk2EvFyt46bw1OYIijw0iOr7fWMJEkz3bfN5mt9pYJIiPzN0gxM8u4mrmqLPUG2SkoZhWz4NOlqRUHZq7Ep6aWKz7KlEpzP9IrvDYwGubci4h+9wsspqtY1BdUJUN59EaWZSuOw1g=="}'
    const wallet = Thirdparty.fromEtherWallet(etherWalletEncrypted, 'testtest')
    assert.strictEqual(wallet.getAddressString(), '0x9d6abd11d36cc20d4836c25967f1d9efe6b1a27c')
  })
})

describe('.fromEtherCamp()', function () {
  it('should work with seed text', function () {
    const wallet = Thirdparty.fromEtherCamp('ethercamp123')
    assert.strictEqual(wallet.getAddressString(), '0x182b6ca390224c455f11b6337d74119305014ed4')
  })
})

describe('.fromKryptoKit()', function () {
  // it('should work with basic input (d-type)', function () {
  //   const wallet = Thirdparty.fromKryptoKit('dBWfH8QZSGbg1sAYHLBhqE5R8VGAoM7')
  //   assert.strictEqual(wallet.getAddressString(), '0x3611981ad2d6fc1d7579d6ce4c6bc37e272c369c')
  // })
  it('should work with encrypted input (q-type)', async function () {
    const wallet = await Thirdparty.fromKryptoKit(
      'qhah1VeT0RgTvff1UKrUrxtFViiQuki16dd353d59888c25',
      'testtest'
    )
    this.timeout(0) // never
    assert.strictEqual(wallet.getAddressString(), '0x3c753e27834db67329d1ec1fab67970ec1e27112')
  })
})

describe('.fromQuorumWallet()', function () {
  it('should work', function () {
    const wallet = Thirdparty.fromQuorumWallet('testtesttest', 'ethereumjs-wallet')
    assert.strictEqual(wallet.getAddressString(), '0x1b86ccc22e8f137f204a41a23033541242a48815')
  })
})

describe('raw new Wallet() init', function () {
  it('should fail when both priv and pub key provided', function () {
    assert.throws(function () {
      new Wallet(fixturePrivateKeyBuffer, fixturePublicKeyBuffer)
    }, /^Error: Cannot supply both a private and a public key to the constructor$/)
  })
})
