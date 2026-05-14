# tcx-wasm

[English](README.md) | 简体中文

TokenCore 的 WebAssembly 版本，面向浏览器侧的多链密钥管理、账户派生、
交易签名、消息签名、PSBT 签名，以及 Nostr 风格的消息加密和事件签名 API。

公开 npm 包名为 `@consenlabs/tcx-wasm`。

## 安装

```bash
npm install @consenlabs/tcx-wasm
```

该包通过 `wasm-pack --target web` 生成，应用需要先初始化 wasm 模块，再调用导出的函数。

```ts
import init, {
  create_keystore,
  derive_accounts,
  sign_tx,
} from "@consenlabs/tcx-wasm";

await init();

const keystoreJson = create_keystore(JSON.stringify({
  password: "correct horse battery staple",
  mnemonic: "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
  network: "MAINNET",
}));

const accounts = JSON.parse(derive_accounts(JSON.stringify({
  keystoreJson,
  key: "correct horse battery staple",
  derivations: [
    {
      chain: "ETHEREUM",
      derivationPath: "m/44'/60'/0'/0/0",
      chainId: "1",
      network: "MAINNET",
    },
  ],
})));
```

## 本地开发

在仓库根目录执行：

```bash
make build-wasm
make dev-wasm
```

`make build-wasm` 会构建 `token-core/tcx-wasm`，并把生成的包复制到
`examples/wasm/src/pkg`。`make dev-wasm` 会启动浏览器集成示例，地址为
`http://localhost:3000`。

构建 npm 包产物：

```bash
make build-npm
```

## API 约定

除 `cache_keystore` 和 `clear_cached_keystore` 外，所有导出函数都接收 JSON
字符串并返回 JSON 字符串。JavaScript 字段使用 `camelCase`，Rust 侧通过
`serde(rename_all = "camelCase")` 进行映射。

大多数 API 都支持：

- `keystoreJson`：已经缓存 keystore 时可以省略。
- `key`：必填的解锁密钥。对原生 HD keystore 来说是密码；对 Passkey envelope
  来说是 32 字节十六进制 PRF key。
- `prfKey`：为已有 Passkey 调用方保留的兼容别名。

可以使用 `cache_keystore(keystoreJson)` 避免每次调用都传入 keystore JSON，
使用 `clear_cached_keystore()` 清除缓存的 keystore 和消息密钥。

## 创建 Keystore

`create_keystore(paramJson)` 会基于以下其中一种解锁模式创建 keystore：

- `password`：创建原生 TokenCore HD keystore。
- `prfKey`：创建由 32 字节十六进制 WebAuthn PRF key 加密的 Passkey envelope。
  该模式还需要提供 `userId`、`credentialId` 和 `rpId`。

助记词来源支持：

- `mnemonic`：导入已有助记词。
- `entropy`：基于调用方提供的十六进制熵生成助记词。
- 同时省略 `mnemonic` 和 `entropy`：在 wasm 内部随机生成助记词。

```ts
const passkeyKeystore = create_keystore(JSON.stringify({
  prfKey: "0000000000000000000000000000000000000000000000000000000000000001",
  userId: "user-1",
  credentialId: "credential-1",
  rpId: "example.com",
  mnemonic: "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
  network: "MAINNET",
}));

const passwordKeystore = create_keystore(JSON.stringify({
  password: "correct horse battery staple",
  entropy: "00000000000000000000000000000000",
  network: "TESTNET",
}));
```

使用 `export_mnemonic(paramJson)` 解密并导出助记词：

```ts
const { mnemonic } = JSON.parse(export_mnemonic(JSON.stringify({
  keystoreJson: passwordKeystore,
  key: "correct horse battery staple",
})));
```

## 支持的链

`derive_accounts` 支持以下 `chain` 值：

| Chain | 曲线 | 默认派生路径 |
| --- | --- | --- |
| `ETHEREUM` | secp256k1 | `m/44'/60'/0'/0/0` |
| `TRON` | secp256k1 | `m/44'/195'/0'/0/0` |
| `BITCOIN` | secp256k1 | 取决于 `segWit` |
| `BITCOINCASH` | secp256k1 | `m/44'/145'/0'/0/0` |
| `LITECOIN` | secp256k1 | `m/44'/2'/0'/0/0` |
| `DOGECOIN` | secp256k1 | `m/44'/3'/0'/0/0` |
| `OMNI` | secp256k1 | `m/44'/0'/0'/0/0` |
| `COSMOS` | secp256k1 | `m/44'/118'/0'/0/0` |
| `EOS` | secp256k1 | `m/44'/194'/0'/0/0` |
| `TEZOS` | ed25519 | `m/44'/1729'/0'/0'` |
| `TON` | ed25519 | `m/44'/607'/0'` |
| `NERVOS` | secp256k1 | `m/44'/309'/0'/0/0` |
| `POLKADOT` | sr25519 | `//imToken//polkadot/0` |
| `KUSAMA` | sr25519 | `//imToken//kusama/0` |

对 `BITCOIN`、`LITECOIN` 和 `DOGECOIN`，`segWit` 用于选择地址类型：

| `segWit` | BTC 路径 | 地址类型 |
| --- | --- | --- |
| `NONE` | `m/44'/0'/0'/0/0` | P2PKH |
| `P2WPKH` | `m/49'/0'/0'/0/0` | P2SH-P2WPKH |
| `VERSION_0` | `m/84'/0'/0'/0/0` | Native SegWit |
| `VERSION_1` | `m/86'/0'/0'/0/0` | Taproot |

`ETHEREUM2` 和 `FILECOIN` 未包含在当前 wasm 构建中，因为它们的 BLS 依赖与
`wasm32-unknown-unknown` 不兼容。

## 签名 API

### `sign_tx(paramJson)`

签名单笔交易。支持的交易类型包括：

- Ethereum legacy 和 EIP-1559 交易。
- TRON raw transaction。
- BTC/BCH/LTC/DOGE UTXO 交易。
- OMNI 交易。
- COSMOS、EOS、TEZOS、TON、NERVOS、POLKADOT 和 KUSAMA raw transaction。

```ts
const result = JSON.parse(sign_tx(JSON.stringify({
  keystoreJson,
  key: "correct horse battery staple",
  chain: "ETHEREUM",
  derivationPath: "m/44'/60'/0'/0/0",
  input: {
    nonce: "0",
    gasPrice: "20000000000",
    gasLimit: "21000",
    to: "0x3535353535353535353535353535353535353535",
    value: "1000000000000000000",
    chainId: "1",
  },
})));
// { signature: "0x...", txHash: "0x..." }
```

可以使用 `sign_txs(paramJson)` 在一次 keystore 解锁后批量签名多笔交易。

### `sign_message(paramJson)`

消息签名支持：

- `ETHEREUM`：`PersonalSign` 或 `EcSign`。
- `TRON`：TRON message signing。
- `BITCOIN`、`BITCOINCASH`、`LITECOIN` 和 `DOGECOIN`：BIP-322 风格的消息签名。
- `EOS`：EOS message signing。

#### ETH Typed Data / EIP-712 注意事项

`sign_message` 不接收结构化 Typed Data，也不会执行 EIP-712 的
`hashDomain` / `hashStruct` 流程。`ETHEREUM` 使用
`signatureType: "EcSign"` 时，`tcx-wasm` 会先将 `input.message` 转成字节，
然后再做一次 `keccak256` 并签名。

不要把 `viem.hashTypedData(...)` 等 SDK helper 的返回值直接传给
`sign_message`。`viem.hashTypedData(...)` 已经执行了 `hashDomain` 和
`hashStruct`，返回的是最终 EIP-712 digest；再传给 `sign_message` 会被
`tcx-wasm` 再 hash 一次，生成的签名无法通过常规 EIP-712 校验。

AI / Vibe Coding 防误用规则：

```ts
// 避免：这会对 EIP-712 digest 重复 hash。
const digest = hashTypedData({ domain, types, primaryType, message });
sign_message(JSON.stringify({
  chain: "ETHEREUM",
  input: { message: digest, signatureType: "EcSign" },
}));
```

如果需要兼容 EIP-712 的 Typed Data 签名，请使用或新增专用的 Typed Data
签名 API：只执行一次 `hashDomain` / `hashStruct`，并且对最终 digest 直接签名，
不要再次 hash。

### `sign_psbt(paramJson)` 和 `sign_psbts(paramJson)`

签名单个或多个 BTC 系 PSBT。`derivationPath` 可以是账户级路径；传入完整地址路径时，
API 会规范化到账户路径。

```ts
const signed = JSON.parse(sign_psbt(JSON.stringify({
  keystoreJson,
  key: "correct horse battery staple",
  chain: "BITCOIN",
  derivationPath: "m/86'/1'/0'",
  input: {
    psbt: "70736274ff01...",
    autoFinalize: true,
  },
})));
// { psbt: "hex..." }
```

## Message API

Message API 会从钱包助记词派生 Nostr key，缓存到 wasm 内存中，然后用于
NIP-44 加解密和 Schnorr 事件签名。

调用 `encrypt_message`、`decrypt_message` 或 `sign_message_event` 之前，需要先调用
`derive_message_key_pair`。

```ts
const { pubkey } = JSON.parse(derive_message_key_pair(JSON.stringify({
  keystoreJson,
  key: "correct horse battery staple",
  derivationPath: "m/44'/1237'/0'/0/0",
})));

const encrypted = JSON.parse(encrypt_message(JSON.stringify({
  serverPubkey: "d39eadac9f88ea1a77b034e8586191ed5435f44b01dea8f214f45fd7bd0b8e0f",
  plaintext: "secret message",
})));

const signedEvent = JSON.parse(sign_message_event(JSON.stringify({
  event: {
    createdAt: Math.floor(Date.now() / 1000),
    kind: 1,
    tags: [],
    content: "Hello Nostr!",
  },
})));
```

当 `sign_message_event` 传入 `recipientPubkey` 时，API 会返回 NIP-59 gift-wrapped
event，也就是 `kind: 1059` 的事件。

## 浏览器示例

参考 [`examples/wasm`](../../examples/wasm)。该 Next.js 浏览器集成示例覆盖
keystore 创建、账户派生、交易签名、消息签名、PSBT 签名和 Message API。
