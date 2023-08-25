[ethereumjs-wallet](../README.md) > [EthereumHDKey](../classes/ethereumhdkey.md)

# Class: EthereumHDKey

## Hierarchy

**EthereumHDKey**

## Index

### Constructors

- [constructor](ethereumhdkey.md#constructor)

### Properties

- [\_hdkey](ethereumhdkey.md#_hdkey)

### Methods

- [deriveChild](ethereumhdkey.md#derivechild)
- [derivePath](ethereumhdkey.md#derivepath)
- [getWallet](ethereumhdkey.md#getwallet)
- [privateExtendedKey](ethereumhdkey.md#privateextendedkey)
- [publicExtendedKey](ethereumhdkey.md#publicextendedkey)
- [fromExtendedKey](ethereumhdkey.md#fromextendedkey)
- [fromMasterSeed](ethereumhdkey.md#frommasterseed)
- [fromMnemonic](ethereumhdkey.md#frommnemonic)

---

## Constructors

<a id="constructor"></a>

### constructor

⊕ **new EthereumHDKey**(\_hdkey: _`any`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:27](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L27)_

**Parameters:**

| Name               | Type  |
| ------------------ | ----- |
| `Optional` \_hdkey | `any` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

## Properties

<a id="_hdkey"></a>

### ` <Private>``<Optional> ` \_hdkey

**● \_hdkey**: _`any`_

_Defined in [hdkey.ts:27](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L27)_

---

## Methods

<a id="derivechild"></a>

### deriveChild

▸ **deriveChild**(index: _`number`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:56](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L56)_

**Parameters:**

| Name  | Type     |
| ----- | -------- |
| index | `number` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

<a id="derivepath"></a>

### derivePath

▸ **derivePath**(path: _`string`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:49](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L49)_

**Parameters:**

| Name | Type     |
| ---- | -------- |
| path | `string` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

<a id="getwallet"></a>

### getWallet

▸ **getWallet**(): [Wallet](wallet.md)

_Defined in [hdkey.ts:63](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L63)_

**Returns:** [Wallet](wallet.md)

---

<a id="privateextendedkey"></a>

### privateExtendedKey

▸ **privateExtendedKey**(): `Buffer`

_Defined in [hdkey.ts:32](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L32)_

**Returns:** `Buffer`

---

<a id="publicextendedkey"></a>

### publicExtendedKey

▸ **publicExtendedKey**(): `Buffer`

_Defined in [hdkey.ts:42](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L42)_

**Returns:** `Buffer`

---

<a id="fromextendedkey"></a>

### `<Static>` fromExtendedKey

▸ **fromExtendedKey**(base58Key: _`string`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:23](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L23)_

**Parameters:**

| Name      | Type     |
| --------- | -------- |
| base58Key | `string` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

<a id="frommasterseed"></a>

### `<Static>` fromMasterSeed

▸ **fromMasterSeed**(seedBuffer: _`Buffer`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:9](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L9)_

**Parameters:**

| Name       | Type     |
| ---------- | -------- |
| seedBuffer | `Buffer` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

<a id="frommnemonic"></a>

### `<Static>` fromMnemonic

▸ **fromMnemonic**(mnemonic: _`string`_, passphrase: _`string`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:16](https://github.com/ethereumjs/ethereumjs-wallet/blob/7b6ac09/src/hdkey.ts#L16)_

**Parameters:**

| Name       | Type     |
| ---------- | -------- |
| mnemonic | `string` |
| `Optional` passphrase | `string` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---
