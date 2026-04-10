# tcx-wasm Browser Example

Next.js web app for testing the `tcx-wasm` crate in the browser, covering keystore creation, account derivation, ETH / TRON transaction & message signing, and Message API (NIP-44 encryption + Schnorr/Nostr event signing) via WebAssembly.

## Prerequisites

- [Rust nightly](https://rustup.rs/) (see `rust-toolchain.toml` at repo root)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [LLVM with wasm32 support](https://formulae.brew.sh/formula/llvm) (`brew install llvm`)
- Node.js >= 18

## Quick Start

```bash
# From repo root
make build-wasm        # compile WASM and copy to public/
make dev-wasm          # build + start Next.js dev server
```

Then open [http://localhost:3000](http://localhost:3000) and click **Run Tests**.

## Manual Steps

```bash
# 1. Build the WASM package
npm run build:wasm

# 2. Start the dev server
npm run dev
```

## API Reference

All functions accept / return JSON strings (unless noted). Field names use **camelCase** on the JS side and are automatically mapped to Rust `snake_case` via `serde(rename_all = "camelCase")`.

---

### `cache_keystore(keystore_json: string): void`

Caches a keystore JSON string in WASM thread-local storage. Subsequent calls to `derive_accounts`, `sign_tx`, `sign_message`, etc. can omit the `keystoreJson` field.

```ts
cache_keystore(keystoreJson);
```

---

### `clear_cached_keystore(): void`

Clears the cached keystore and any cached message secret key.

```ts
clear_cached_keystore();
```

---

### `create_keystore(param_json: string): string`

Creates a new passkey-protected keystore. Supports three modes:
- **Import** — provide `mnemonic`
- **Entropy** — provide `entropy` (hex)
- **Random** — omit both (uses Web Crypto internally)

```ts
// Import existing mnemonic
const ks = create_keystore(JSON.stringify({
  prfKey: "0000...0001",         // 32-byte hex PRF key from WebAuthn
  userId: "user-1",
  credentialId: "cred-1",
  rpId: "example.com",
  mnemonic: "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
  network: "MAINNET",           // optional: "MAINNET" | "TESTNET"
}));

// Generate from entropy
const ks2 = create_keystore(JSON.stringify({
  prfKey: "0000...0001",
  userId: "user-2",
  credentialId: "cred-2",
  rpId: "example.com",
  entropy: "a1b2c3d4e5f6...",   // 16-byte hex
}));

// Fully random
const ks3 = create_keystore(JSON.stringify({
  prfKey: "0000...0001",
  userId: "user-3",
  credentialId: "cred-3",
  rpId: "example.com",
}));
```

**Output:**

```json
{
  "userId": "user-1",
  "credentialId": "cred-1",
  "rpId": "example.com",
  "encryptedMnemonic": "hex...",
  "mnemonicIv": "hex...",
  "createdAt": 1712600000,
  "identity": {
    "identifier": "im...",
    "ipfsId": "Qm...",
    "encKey": "hex...",
    "encAuthKey": { ... }
  }
}
```

---

### `derive_accounts(param_json: string): string`

Derives one or more accounts from the keystore. Supports **ETHEREUM** and **TRON** chains.

```ts
const accounts = JSON.parse(derive_accounts(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  prfKey: "0000...0001",
  derivations: [
    {
      chain: "ETHEREUM",
      derivationPath: "m/44'/60'/0'/0/0",
      chainId: "1",
      network: "MAINNET",
    },
    {
      chain: "TRON",
      derivationPath: "m/44'/195'/0'/0/0",
      network: "MAINNET",
    },
  ],
})));
```

**Output:** `AccountResponse[]`

```json
[
  {
    "address": "0x...",
    "chain": "ETHEREUM",
    "derivationPath": "m/44'/60'/0'/0/0",
    "extPubKey": "xpub...",
    "publicKey": "hex..."
  },
  {
    "address": "T...",
    "chain": "TRON",
    "derivationPath": "m/44'/195'/0'/0/0",
    "extPubKey": "xpub...",
    "publicKey": "hex..."
  }
]
```

---

### `sign_tx(param_json: string): string`

Signs a transaction. Supports ETH legacy (EIP-155), EIP-1559, and TRON.

#### ETH Legacy Transaction

```ts
const result = JSON.parse(sign_tx(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  prfKey: "0000...0001",
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
// => { signature: "0x...", txHash: "0x..." }
```

#### ETH EIP-1559 Transaction

```ts
const result = JSON.parse(sign_tx(JSON.stringify({
  keystoreJson: ks,
  prfKey: "0000...0001",
  derivationPath: "m/44'/60'/0'/0/0",
  input: {
    nonce: "1",
    gasLimit: "21000",
    to: "0x3535353535353535353535353535353535353535",
    value: "1000000000000000000",
    chainId: "1",
    txType: "02",
    maxFeePerGas: "30000000000",
    maxPriorityFeePerGas: "1000000000",
    accessList: [],
  },
})));
// => { signature: "0x...", txHash: "0x..." }
```

#### TRON Transaction

```ts
const result = JSON.parse(sign_tx(JSON.stringify({
  keystoreJson: ks,
  prfKey: "0000...0001",
  chain: "TRON",
  input: {
    rawData: "0a0208312208b02efdc02638b61e40f083c3a7c92d5a65...",
  },
})));
// => { signatures: ["hex..."] }
```

---

### `sign_txs(param_json: string): string`

Batch-signs multiple transactions with a single keystore unlock. Only decrypts the mnemonic once, which is more efficient than calling `sign_tx` repeatedly.

```ts
const results = JSON.parse(sign_txs(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  prfKey: "0000...0001",
  txs: [
    {
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
    },
    {
      chain: "TRON",
      input: {
        rawData: "0a0208312208b02efdc02638b61e40f083c3a7c92d5a65...",
      },
    },
  ],
})));
// => [
//   { signature: "0x...", txHash: "0x..." },   // ETH result
//   { signatures: ["hex..."] },                 // TRON result
// ]
```

**Input:** `{ keystoreJson?, prfKey, txs: [{ chain?, derivationPath?, input }] }`

**Output:** `Array` — each element matches the corresponding `sign_tx` output for the given chain.

---

### `sign_message(param_json: string): string`

Signs a message. Supports ETH PersonalSign / EcSign and TRON message signing.

#### ETH PersonalSign

```ts
const result = JSON.parse(sign_message(JSON.stringify({
  keystoreJson: ks,
  prfKey: "0000...0001",
  chain: "ETHEREUM",
  derivationPath: "m/44'/60'/0'/0/0",
  input: {
    message: "Hello from tcx-wasm!",
    signatureType: "PersonalSign",    // or "EcSign"
  },
})));
// => { signature: "0x..." }
```

#### TRON Message

```ts
const result = JSON.parse(sign_message(JSON.stringify({
  keystoreJson: ks,
  prfKey: "0000...0001",
  chain: "TRON",
  input: {
    value: "Hello from tcx-wasm!",
    header: "TRON",                   // optional, default "TRON"
    version: 2,                       // optional, default 1
  },
})));
// => { signature: "0x..." }
```

---

### `derive_message_key_pair(param_json: string): string`

Derives a NIP-44 key pair from the keystore mnemonic at the Nostr BIP-44 path (`m/44'/1237'/0'/0/0` by default). Returns the x-only public key and caches the secret key in WASM memory for subsequent `encrypt_message` / `decrypt_message` calls.

```ts
const keyPair = JSON.parse(derive_message_key_pair(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  prfKey: "0000...0001",
  // derivationPath: "m/44'/1237'/0'/0/0",  // optional, this is the default
})));
// => { pubkey: "64-char hex (x-only 32-byte)" }
```

---

### `sign_message_event(param_json: string): string`

Signs a Nostr event (NIP-01) with Schnorr/BIP-340. **Must call `derive_message_key_pair` first** — uses the cached secret key.

When `recipientPubkey` is provided, performs **NIP-59 Gift Wrapping** (seal + wrap) and returns a `kind: 1059` gift-wrapped event instead of the plain signed event.

```ts
// Basic signing (no seal/wrap)
const signedEvent = JSON.parse(sign_message_event(JSON.stringify({
  event: {
    createdAt: Math.floor(Date.now() / 1000),
    kind: 1,
    tags: [],
    content: "Hello Nostr!",
  },
})));

// With NIP-59 seal + wrap
const wrappedEvent = JSON.parse(sign_message_event(JSON.stringify({
  recipientPubkey: "64-char hex recipient x-only pubkey",
  event: {
    createdAt: Math.floor(Date.now() / 1000),
    kind: 1,
    tags: [],
    content: "Private message",
  },
})));
// => kind: 1059, pubkey is ephemeral, tags: [["p", recipientPubkey]]
```

**Output (basic):**

```json
{
  "id": "64-char hex event id",
  "pubkey": "64-char hex x-only pubkey",
  "createdAt": 1712600000,
  "kind": 1,
  "tags": [],
  "content": "Hello Nostr!",
  "sig": "128-char hex Schnorr signature"
}
```

**Output (seal + wrap):**

```json
{
  "id": "64-char hex event id",
  "pubkey": "64-char hex ephemeral pubkey",
  "createdAt": 1712599000,
  "kind": 1059,
  "tags": [["p", "64-char hex recipient pubkey"]],
  "content": "base64 NIP-44 encrypted seal",
  "sig": "128-char hex Schnorr signature"
}
```

---

### `encrypt_message(param_json: string): string`

Encrypts plaintext using NIP-44 v2 with the cached secret key and a caller-supplied server public key. **Must call `derive_message_key_pair` first** to populate the cached key.

```ts
const encrypted = JSON.parse(encrypt_message(JSON.stringify({
  serverPubkey: "d39eadac9f88ea1a77b034e8586191ed5435f44b01dea8f214f45fd7bd0b8e0f",
  plaintext: "secret message",
})));
// => { encryptedContent: "base64 NIP-44 payload" }
```

---

### `decrypt_message(param_json: string): string`

Decrypts a NIP-44 v2 payload back to plaintext. Uses the same cached secret key + caller-supplied server public key.

```ts
const decrypted = JSON.parse(decrypt_message(JSON.stringify({
  serverPubkey: "d39eadac9f88ea1a77b034e8586191ed5435f44b01dea8f214f45fd7bd0b8e0f",
  encryptedContent: encrypted.encryptedContent,
})));
// => { plaintext: "secret message" }
```

---

## What It Tests

| # | Test Case | API | Description |
|---|-----------|-----|-------------|
| 1 | Init WASM | — | Load and initialize the WASM module |
| 2 | Create Keystore (import) | `create_keystore` | Import a known mnemonic, verify identity fields |
| 3 | Create Keystore (new via entropy) | `create_keystore` | Create from caller-supplied entropy (TESTNET) |
| 4 | Create Keystore (random) | `create_keystore` | Create with WASM-internal random entropy |
| 5 | Derive Accounts (ETH + TRON) | `derive_accounts` | Derive ETH + TRON addresses in one call |
| 6 | Sign Legacy TX (EIP-155) | `sign_tx` | Sign a legacy ETH transaction |
| 7 | Sign EIP-1559 TX | `sign_tx` | Sign a type-2 EIP-1559 transaction |
| 8 | Sign TRON TX | `sign_tx` | Sign a TRON transaction |
| 9 | Sign Batch TXs (ETH + TRON) | `sign_txs` | Batch-sign ETH + TRON in one call |
| 10 | Sign ETH Message (PersonalSign) | `sign_message` | Sign ETH personal message |
| 11 | Sign TRON Message | `sign_message` | Sign TRON message (v2) |
| 12 | Cache Keystore + Derive | `cache_keystore` / `derive_accounts` / `clear_cached_keystore` | Cache keystore, derive without explicit JSON |
| 13 | derive_message_key_pair | `derive_message_key_pair` | Derive and cache NIP-44 key pair |
| 14 | encrypt_message | `encrypt_message` | Encrypt plaintext with NIP-44 v2 |
| 15 | decrypt_message | `decrypt_message` | Decrypt and verify roundtrip |
| 16 | sign_message_event | `sign_message_event` | Sign Nostr event with Schnorr/BIP-340 |
| 17 | sign_message_event (seal+wrap) | `sign_message_event` | NIP-59 Gift Wrapping: seal + wrap with recipientPubkey |
| 18 | sign + encrypt/decrypt roundtrip | All Message APIs | Full roundtrip: encrypt → sign event → decrypt |
