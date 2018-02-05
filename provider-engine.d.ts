import { IPublicKeyOnlyWallet, IFullWallet } from './';

export interface WalletSubprovider {
  constructor(wallet: IPublicKeyOnlyWallet | IFullWallet, opts?: object);
}
