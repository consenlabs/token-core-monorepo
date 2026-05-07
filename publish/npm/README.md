# tcx-wasm Browser Example

Next.js web app for testing the `tcx-wasm` crate in the browser, covering keystore creation, account derivation, ETH / TRON / BTC transaction, message & PSBT signing, and Message API (NIP-44 encryption + Schnorr/Nostr event signing) via WebAssembly.

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

After creation, APIs use a single `key` string. If the keystore JSON has a native `crypto` object, `key` is treated as a password and the KDF parameters from `crypto` are used. If the keystore JSON is the Passkey envelope, `key` is treated as the 32-byte hex PRF key. Legacy `prfKey` remains accepted as an alias for existing Passkey callers.

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

Creates a new keystore. Creation requires exactly one of:
- `prfKey` — 32-byte hex PRF key from WebAuthn; returns the existing Passkey envelope.
- `password` — plain password; returns native HD keystore JSON with `crypto.kdf = "pbkdf2"`.

Mnemonic source supports three modes:
- **Import** — provide `mnemonic`
- **Entropy** — provide `entropy` (hex)
- **Random** — omit both (uses Web Crypto internally)

```ts
// Import existing mnemonic
const ks = create_keystore(JSON.stringify({
  prfKey: "0000...0001",      // 32-byte hex PRF key from WebAuthn
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

// Password mode
const passwordKs = create_keystore(JSON.stringify({
  password: "correct horse battery staple",
  mnemonic: "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
  network: "MAINNET",
}));
```

**Passkey PRF output:**

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

**Password output:** native HD keystore JSON with `version: 12000`, `crypto.kdf: "pbkdf2"`, `crypto.kdfparams.c: 600000`, and MAC/cipher params stored under `crypto`.

---

### `export_mnemonic(param_json: string): string`

Exports (decrypts) the mnemonic. Post-creation APIs use `key`; for native `crypto` keystore JSON it is a password, and for the Passkey envelope it is the PRF key. Legacy `prfKey` is still accepted as an alias for Passkey callers.

```ts
const result = JSON.parse(export_mnemonic(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  key: "0000...0001",
})));
// => { mnemonic: "inject kidney empty canal ..." }
```

**Output:**

```json
{
  "mnemonic": "inject kidney empty canal shadow pact comfort wife crush horse wife sketch"
}
```

---

### `derive_accounts(param_json: string): string`

Derives one or more accounts from the keystore. Supports **ETHEREUM**, **TRON** and **BITCOIN**.

For `BITCOIN`, `segWit` selects the address type:

| `segWit`    | Default BIP path        | Address prefix (MAINNET) |
|-------------|-------------------------|--------------------------|
| `NONE`      | `m/44'/0'/0'/0/0`       | `1...` (P2PKH)           |
| `P2WPKH`    | `m/49'/0'/0'/0/0`       | `3...` (P2SH-P2WPKH)     |
| `VERSION_0` | `m/84'/0'/0'/0/0`       | `bc1q...` (Native SegWit)|
| `VERSION_1` | `m/86'/0'/0'/0/0`       | `bc1p...` (Taproot)      |

```ts
const accounts = JSON.parse(derive_accounts(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  key: "0000...0001",
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
    {
      chain: "BITCOIN",
      derivationPath: "m/84'/0'/0'/0/0",
      network: "MAINNET",
      segWit: "VERSION_0",
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
  },
  {
    "address": "bc1q...",
    "chain": "BITCOIN",
    "derivationPath": "m/84'/0'/0'/0/0",
    "extPubKey": "xpub...",
    "publicKey": "hex..."
  }
]
```

---

### `sign_tx(param_json: string): string`

Signs a transaction. Supports ETH legacy (EIP-155), EIP-1559, TRON, and BITCOIN (UTXO-based).

#### ETH Legacy Transaction

```ts
const result = JSON.parse(sign_tx(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  key: "0000...0001",
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
  key: "0000...0001",
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
  key: "0000...0001",
  chain: "TRON",
  input: {
    rawData: "0a0208312208b02efdc02638b61e40f083c3a7c92d5a65...",
  },
})));
// => { signatures: ["hex..."] }
```

#### BITCOIN Transaction (UTXO)

```ts
const result = JSON.parse(sign_tx(JSON.stringify({
  keystoreJson: ks,
  key: "0000...0001",
  chain: "BITCOIN",
  network: "TESTNET",                 // "MAINNET" | "TESTNET"
  segWit: "VERSION_0",                // "NONE" | "P2WPKH" | "VERSION_0" | "VERSION_1"
  derivationPath: "m/84'/1'/0'/0/0",  // full address-level path
  input: {
    inputs: [
      {
        txHash: "cebc5c2b4f5533428ad0cca94e9bfefa6410a270ed1d7116e2ee8592494c66bd",
        vout: 1,
        amount: 100000,               // satoshis
        address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95",
        derivedPath: "m/84'/1'/0'/0/0",
      },
    ],
    to: "tb1p3ax2dfecfag2rlsqewje84dgxj6gp3jkj2nk4e3q9cwwgm93cgesa0zwj4",
    amount: 50000,
    fee: 20000,
    changeAddressIndex: 53,           // optional
    opReturn: undefined,              // optional hex
  },
})));
// => { rawTx: "hex...", txHash: "hex...", wtxHash: "hex..." }
```

---

### `sign_txs(param_json: string): string`

Batch-signs multiple transactions with a single keystore unlock. Only decrypts the mnemonic once, which is more efficient than calling `sign_tx` repeatedly.

```ts
const results = JSON.parse(sign_txs(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  key: "0000...0001",
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

**Input:** `{ keystoreJson?, key, txs: [{ chain?, derivationPath?, input }] }`

**Output:** `Array` — each element matches the corresponding `sign_tx` output for the given chain.

---

### `sign_message(param_json: string): string`

Signs a message. Supports ETH PersonalSign / EcSign, TRON message, and BTC BIP-322 signing.

#### ETH PersonalSign

```ts
const result = JSON.parse(sign_message(JSON.stringify({
  keystoreJson: ks,
  key: "0000...0001",
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
  key: "0000...0001",
  chain: "TRON",
  input: {
    value: "Hello from tcx-wasm!",
    header: "TRON",                   // optional, default "TRON"
    version: 2,                       // optional, default 1
  },
})));
// => { signature: "0x..." }
```

#### BITCOIN Message (BIP-322)

```ts
const result = JSON.parse(sign_message(JSON.stringify({
  keystoreJson: ks,
  key: "0000...0001",
  chain: "BITCOIN",
  network: "MAINNET",                 // "MAINNET" | "TESTNET"
  segWit: "VERSION_0",                // same enum as derive_accounts
  derivationPath: "m/84'/0'/0'",      // account-level; a full /0/0 path is accepted and auto-trimmed
  input: { message: "hello world" },
})));
// => { signature: "hex..." }
```

---

### `sign_psbt(param_json: string): string`

Signs a single BITCOIN PSBT (Partially Signed Bitcoin Transaction) and optionally finalizes it.

```ts
const result = JSON.parse(sign_psbt(JSON.stringify({
  keystoreJson: ks,
  key: "0000...0001",
  chain: "BITCOIN",                   // optional, default "BITCOIN"
  derivationPath: "m/86'/1'/0'",      // account-level; full /0/0 path also accepted
  input: {
    psbt: "70736274ff01...",          // hex-encoded PSBT
    autoFinalize: true,
  },
})));
// => { psbt: "hex..." }
```

---

### `sign_psbts(param_json: string): string`

Batch-signs multiple PSBTs with a single keystore unlock.

```ts
const result = JSON.parse(sign_psbts(JSON.stringify({
  keystoreJson: ks,
  key: "0000...0001",
  chain: "BITCOIN",
  derivationPath: "m/86'/1'/0'",
  input: {
    psbts: ["70736274ff01...", "70736274ff01..."],
    autoFinalize: true,
  },
})));
// => { psbts: ["hex...", "hex..."] }
```

---

### `derive_message_key_pair(param_json: string): string`

Derives a NIP-44 key pair from the keystore mnemonic at the Nostr BIP-44 path (`m/44'/1237'/0'/0/0` by default). Returns the x-only public key and caches the secret key in WASM memory for subsequent `encrypt_message` / `decrypt_message` calls.

```ts
const keyPair = JSON.parse(derive_message_key_pair(JSON.stringify({
  keystoreJson: ks,              // optional if cached
  key: "0000...0001",
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
| 5 | Create Password Keystore | `create_keystore` | Create native HD keystore with PBKDF2 600000 rounds |
| 6 | Export Mnemonic | `export_mnemonic` | Decrypt and export mnemonic with `key` |
| 7 | Export Mnemonic (legacy prfKey) | `export_mnemonic` | Verify legacy `prfKey` alias still works |
| 8 | Password Export + Wrong Password | `export_mnemonic` | Export with password and reject a wrong password |
| 9 | Derive Accounts (ETH + TRON) | `derive_accounts` | Derive ETH + TRON addresses in one call |
| 10 | Password Derive Accounts | `derive_accounts` | Derive the same ETH + TRON addresses from password keystore |
| 11 | Sign Legacy TX (EIP-155) | `sign_tx` | Sign a legacy ETH transaction |
| 12 | Password Sign Legacy TX | `sign_tx` | Sign the same ETH transaction from password keystore |
| 13 | Sign EIP-1559 TX | `sign_tx` | Sign a type-2 EIP-1559 transaction |
| 14 | Sign TRON TX | `sign_tx` | Sign a TRON transaction |
| 15 | Sign Batch TXs (ETH + TRON) | `sign_txs` | Batch-sign ETH + TRON in one call |
| 16 | Sign ETH Message (PersonalSign) | `sign_message` | Sign ETH personal message |
| 17 | Sign TRON Message | `sign_message` | Sign TRON message (v2) |
| 18 | Derive BTC Accounts (4 types) | `derive_accounts` | Derive P2PKH / P2SH-P2WPKH / Native SegWit / Taproot addresses |
| 19 | Sign BTC TX (P2WPKH TESTNET) | `sign_tx` | Sign a native-SegWit testnet transaction |
| 20 | Sign BTC Message (BIP-322) | `sign_message` | Sign a BIP-322 message with Native SegWit |
| 21 | Sign PSBT (Taproot TESTNET) | `sign_psbt` | Sign and auto-finalize a Taproot PSBT |
| 22 | Sign PSBTs (batch) | `sign_psbts` | Batch-sign PSBTs with one keystore unlock |
| 23 | Cache Keystore + Derive | `cache_keystore` / `derive_accounts` / `clear_cached_keystore` | Cache keystore, derive without explicit JSON |
| 24 | derive_message_key_pair | `derive_message_key_pair` | Derive and cache NIP-44 key pair |
| 25 | encrypt_message | `encrypt_message` | Encrypt plaintext with NIP-44 v2 |
| 26 | decrypt_message | `decrypt_message` | Decrypt and verify roundtrip |
| 27 | sign_message_event | `sign_message_event` | Sign Nostr event with Schnorr/BIP-340 |
| 28 | sign_message_event (seal+wrap) | `sign_message_event` | NIP-59 Gift Wrapping: seal + wrap with recipientPubkey |
| 29 | sign + encrypt/decrypt roundtrip | All Message APIs | Full roundtrip: encrypt, sign event, decrypt |
