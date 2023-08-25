import { HDKey } from 'ethereum-cryptography/hdkey'
import { mnemonicToSeedSync } from 'ethereum-cryptography/bip39'
import Wallet from './index'

export default class EthereumHDKey {
  /**
   * Creates an instance based on a seed.
   */
  public static fromMasterSeed(seedBuffer: Buffer): EthereumHDKey {
    return new EthereumHDKey(HDKey.fromMasterSeed(seedBuffer))
  }

  /**
   * Creates an instance based on BIP39 mnemonic phrases
   */
  public static fromMnemonic(mnemonic: string, passphrase?: string) {
    return EthereumHDKey.fromMasterSeed(Buffer.from(mnemonicToSeedSync(mnemonic, passphrase)))
  }

  /**
   * Create an instance based on a BIP32 extended private or public key.
   */
  public static fromExtendedKey(base58Key: string): EthereumHDKey {
    return new EthereumHDKey(HDKey.fromExtendedKey(base58Key))
  }

  constructor(private readonly _hdkey: HDKey) {}

  /**
   * Returns a BIP32 extended private key (xprv)
   */
  public privateExtendedKey(): string {
    if (!this._hdkey.privateExtendedKey) {
      throw new Error('This is a public key only wallet')
    }
    return this._hdkey.privateExtendedKey
  }

  /**
   * Return a BIP32 extended public key (xpub)
   */
  public publicExtendedKey(): string {
    return this._hdkey.publicExtendedKey
  }

  /**
   * Derives a node based on a path (e.g. m/44'/0'/0/1)
   */
  public derivePath(path: string): EthereumHDKey {
    return new EthereumHDKey(this._hdkey.derive(path))
  }

  /**
   * Derive a node based on a child index
   */
  public deriveChild(index: number): EthereumHDKey {
    return new EthereumHDKey(this._hdkey.deriveChild(index))
  }

  /**
   * Return a `Wallet` instance as seen above
   */
  public getWallet(): Wallet {
    if (this._hdkey.privateKey) {
      return Wallet.fromPrivateKey(Buffer.from(this._hdkey.privateKey))
    }
    if (!this._hdkey.publicKey) throw new Error('No hdkey')
    return Wallet.fromPublicKey(Buffer.from(this._hdkey.publicKey), true)
  }
}
