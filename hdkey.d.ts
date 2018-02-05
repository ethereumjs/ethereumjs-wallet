import { Buffer } from 'buffer';
import { IPublicKeyOnlyWallet, IFullWallet } from './';

export interface IHDNodePublic {
  /**
   * @description return a BIP32 extended public key (xpub)
   */
  publicExtendedKey(): string;

  /**
   * @description derive a node based on a path (e.g. m/44'/0'/0/1)
   */
  derivePath(path: string): IHDNodePublic;

  /**
   * @description derive a node based on a child index
   */
  deriveChild(index): IHDNodePublic;

  /**
   * @description return a Wallet instance
   */
  getWallet(): IPublicKeyOnlyWallet;
}

/**
 *
 *
 * @interface IHDNodePrivate
 */
export interface IHDNodePrivate {
  /**
   * @description return a BIP32 extended private key (xprv)
   */
  privateExtendedKey(): string;

  /**
   * @description return a BIP32 extended public key (xpub)
   */
  publicExtendedKey(): string;

  /**
   * @description derive a node based on a path (e.g. m/44'/0'/0/1)
   */
  derivePath(path: string): IHDNodePrivate | IHDNodePublic;

  /**
   * @description derive a node based on a child index
   */
  deriveChild(index): IHDNodePrivate | IHDNodePublic;

  /**
   * @description return a Wallet instance
   */
  getWallet(): IFullWallet;
}

/**
 * @description create an instance based on a seed
 */
export function fromMasterSeed(seed: Buffer): IHDNodePrivate;

/**
 * @description create an instance based on a BIP32 extended private or public key
 */
export function fromExtendedKey(key: string): IHDNodePrivate | IHDNodePublic;
