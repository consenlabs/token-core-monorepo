# tcx-wasm

[English](README.md) | [简体中文](README.zh-CN.md)

WebAssembly build of TokenCore for browser-side multi-chain key management,
account derivation, transaction signing, message signing, PSBT signing, and
Nostr-style message encryption/signing APIs.

The public npm package is `@consenlabs/tcx-wasm`.

## Installation

```bash
npm install @consenlabs/tcx-wasm
```

The package is generated with `wasm-pack --target web`, so applications should
initialize the wasm module before calling exported functions.

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

## Local Development

From the repository root:

```bash
make build-wasm
make dev-wasm
```

`make build-wasm` builds `token-core/tcx-wasm` and copies the generated package
into `examples/wasm/src/pkg`. `make dev-wasm` starts the browser integration app
at `http://localhost:3000`.

To build the npm package artifacts:

```bash
make build-npm
```

## API Conventions

All exported functions accept JSON strings and return JSON strings, except
`cache_keystore` and `clear_cached_keystore`. JavaScript fields use
`camelCase`; Rust maps them with `serde(rename_all = "camelCase")`.

Most APIs accept:

- `keystoreJson`: optional when a keystore has already been cached.
- `key`: required unlock secret. For native HD keystores this is the password;
  for Passkey envelopes this is the 32-byte hex PRF key.
- `prfKey`: legacy alias accepted for existing Passkey callers.

Use `cache_keystore(keystoreJson)` to avoid passing the keystore JSON on every
call, and `clear_cached_keystore()` to clear cached keystore and message keys.

## Keystore Creation

`create_keystore(paramJson)` creates a keystore from exactly one unlock mode:

- `password`: creates a native TokenCore HD keystore.
- `prfKey`: creates a Passkey envelope encrypted by a 32-byte hex WebAuthn PRF
  key. This mode also requires `userId`, `credentialId`, and `rpId`.

Mnemonic source supports:

- `mnemonic`: import an existing mnemonic.
- `entropy`: create a mnemonic from caller-provided hex entropy.
- omitted `mnemonic` and `entropy`: create a random mnemonic in wasm.

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

Use `export_mnemonic(paramJson)` to decrypt and export the mnemonic:

```ts
const { mnemonic } = JSON.parse(export_mnemonic(JSON.stringify({
  keystoreJson: passwordKeystore,
  key: "correct horse battery staple",
})));
```

## Supported Chains

`derive_accounts` supports these chain values:

| Chain | Curve | Default derivation path |
| --- | --- | --- |
| `ETHEREUM` | secp256k1 | `m/44'/60'/0'/0/0` |
| `TRON` | secp256k1 | `m/44'/195'/0'/0/0` |
| `BITCOIN` | secp256k1 | depends on `segWit` |
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

For `BITCOIN`, `LITECOIN`, and `DOGECOIN`, `segWit` selects the address type:

| `segWit` | BTC path | Address type |
| --- | --- | --- |
| `NONE` | `m/44'/0'/0'/0/0` | P2PKH |
| `P2WPKH` | `m/49'/0'/0'/0/0` | P2SH-P2WPKH |
| `VERSION_0` | `m/84'/0'/0'/0/0` | Native SegWit |
| `VERSION_1` | `m/86'/0'/0'/0/0` | Taproot |

`ETHEREUM2` and `FILECOIN` are not included in this wasm build because their
BLS dependencies are incompatible with `wasm32-unknown-unknown`.

## Signing APIs

### `sign_tx(paramJson)`

Signs one transaction. Supported transaction families include:

- Ethereum legacy and EIP-1559 transactions.
- TRON raw transactions.
- BTC/BCH/LTC/DOGE UTXO transactions.
- OMNI transactions.
- COSMOS, EOS, TEZOS, TON, NERVOS, POLKADOT, and KUSAMA raw transactions.

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

Use `sign_txs(paramJson)` to batch-sign multiple transactions with a single
keystore unlock.

### `sign_message(paramJson)`

Signs messages for:

- `ETHEREUM`: `PersonalSign` or `EcSign`.
- `TRON`: TRON message signing.
- `BITCOIN`, `BITCOINCASH`, `LITECOIN`, and `DOGECOIN`: BIP-322 style message
  signing.
- `EOS`: EOS message signing.

#### ETH Typed Data / EIP-712 warning

`sign_message` does not accept structured Typed Data and does not run the
EIP-712 `hashDomain` / `hashStruct` flow. For `ETHEREUM` with
`signatureType: "EcSign"`, `tcx-wasm` converts `input.message` to bytes and
then applies `keccak256` before signing.

Do not pass the result of SDK helpers such as `viem.hashTypedData(...)` into
`sign_message`. `viem.hashTypedData(...)` already returns the final EIP-712
digest after `hashDomain` and `hashStruct`; passing that digest to
`sign_message` makes `tcx-wasm` hash the digest again and produces a signature
that will not match normal EIP-712 verification.

AI / Vibe Coding guardrail:

```ts
// Avoid: this double-hashes the EIP-712 digest.
const digest = hashTypedData({ domain, types, primaryType, message });
sign_message(JSON.stringify({
  chain: "ETHEREUM",
  input: { message: digest, signatureType: "EcSign" },
}));
```

If you need EIP-712-compatible Typed Data signatures, use or add a dedicated
Typed Data signing API that performs `hashDomain` / `hashStruct` exactly once
and signs the resulting digest without hashing it again.

### `sign_psbt(paramJson)` and `sign_psbts(paramJson)`

Signs one or more BTC-family PSBTs. `derivationPath` may be an account-level
path; full address paths are accepted and normalized to the account path.

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

The Message API derives a Nostr key from the wallet mnemonic, caches it in wasm
memory, and then uses it for NIP-44 encryption/decryption and Schnorr event
signing.

Call `derive_message_key_pair` before `encrypt_message`, `decrypt_message`, or
`sign_message_event`.

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

When `recipientPubkey` is provided to `sign_message_event`, the API returns a
NIP-59 gift-wrapped event (`kind: 1059`).

## Browser Example

See [`examples/wasm`](../../examples/wasm) for a Next.js browser integration
app that exercises keystore creation, account derivation, transaction signing,
message signing, PSBT signing, and the Message API.
