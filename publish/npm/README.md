# @consenlabs/tcx-wasm

WebAssembly build of [TokenCore](https://github.com/consenlabs/token-core-monorepo) — multi-chain key management and transaction signing, compiled to WASM for browser environments.

## Supported Chains

- **Ethereum** — EIP-155 legacy & EIP-1559 transactions
- **TRON**

## Installation

```bash
npm install @consenlabs/tcx-wasm
```

## Quick Start

```ts
import init, {
  create_keystore,
  derive_accounts,
  sign_tx,
  cache_keystore,
  clear_cached_keystore,
} from "@consenlabs/tcx-wasm";

// 1. Initialize the WASM module (call once)
await init();

// 2. Create a keystore with passkey PRF key
const keystoreJson = create_keystore(
  JSON.stringify({
    prfKey: "<hex-encoded-32-byte-prf-key>",
    userId: "user-id",
    credentialId: "credential-id",
    rpId: "example.com",
    mnemonic: "your twelve word mnemonic ...",
    // OR provide entropy to generate a new mnemonic:
    // entropy: "<hex-encoded-16-byte-entropy>",
  })
);

// 3. Derive accounts (batch — single keystore unlock)
const accounts = JSON.parse(
  derive_accounts(
    JSON.stringify({
      keystoreJson,
      prfKey: "<prf-key>",
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
    })
  )
);
console.log(accounts[0].address); // ETH
console.log(accounts[1].address); // TRON

// 4. Sign a transaction
const result = JSON.parse(
  sign_tx(
    JSON.stringify({
      keystoreJson,
      prfKey: "<prf-key>",
      chain: "ETHEREUM",
      derivationPath: "m/44'/60'/0'/0/0",
      input: {
        nonce: "0",
        gasPrice: "20000000000",
        gasLimit: "21000",
        to: "0x...",
        value: "1000000000000000000",
        chainId: "1",
      },
    })
  )
);
console.log(result.signature, result.txHash);
```

## WASM Loading

The package is built with `wasm-pack --target web`. You need to call `init()` before using any functions.

### With Vite / Next.js

Most modern bundlers support WASM out of the box. Just `import` and call `init()`:

```ts
import init from "@consenlabs/tcx-wasm";
await init();
```

If you need to serve the `.wasm` file from a specific path (e.g. a CDN or `/public`), pass the URL:

```ts
await init("/path/to/tcx_wasm_bg.wasm");
```

## API Reference

### `create_keystore(paramJson: string): string`

Creates an encrypted keystore JSON. Accepts a mnemonic or entropy for new wallet generation.

### `derive_accounts(paramJson: string): string`

Derives one or more blockchain accounts from the keystore in a single call. The keystore is decrypted and unlocked once, then each entry in the `derivations` array produces an account. Returns a JSON array of `{ chain, address, derivationPath, extPubKey, publicKey }`.

### `sign_tx(paramJson: string): string`

Signs a transaction and returns the signature. Supports EIP-155 legacy TX, EIP-1559 TX, and TRON TX.

### `cache_keystore(keystoreJson: string): void`

Caches a keystore JSON in thread-local storage so subsequent calls to `derive_accounts` / `sign_tx` don't require passing it explicitly.

### `clear_cached_keystore(): void`

Clears the cached keystore.

## License

Apache-2.0
