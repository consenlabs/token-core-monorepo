# TokenCoreX

`token-core` contains the software wallet side of this workspace. It provides
keystore management, account derivation, chain-specific address generation,
transaction/message signing, migration helpers, Protobuf request/response
types, and a C ABI for mobile clients.

The external API boundary is the `tcx` crate:

- C ABI entrypoint: `call_tcx_api(hex_str)`
- Request format: hex-encoded Protobuf `TcxAction`
- Error boundary: API-facing errors are compatibility-sensitive and should not
  leak lower-level dependency messages without an explicit compatibility review.

## Crate Map

| Crate or path | Purpose |
| ------------- | ------- |
| [`tcx`](./tcx) | TokenCoreX API wrapper and C ABI |
| [`tcx-proto`](./tcx-proto) | Protobuf-generated API types |
| [`tcx-common`](./tcx-common) | Shared hex, hash, random, and utility helpers |
| [`tcx-constants`](./tcx-constants) | Chain, network, and curve constants |
| [`tcx-primitive`](./tcx-primitive) | Keys, BIP32, BLS, Ed25519, Sr25519, Secp256k1, paths |
| [`tcx-crypto`](./tcx-crypto) | Encryption, decryption, KDF, and keystore crypto |
| [`tcx-keystore`](./tcx-keystore) | HD/private keystore, identity, account derivation, signing traits |
| [`tcx-migration`](./tcx-migration) | Legacy keystore migration and scanning |
| `tcx-btc-kin`, `tcx-eth`, `tcx-tron`, `tcx-ckb`, `tcx-atom`, `tcx-eos`, `tcx-substrate`, `tcx-filecoin`, `tcx-tezos`, `tcx-ton`, `tcx-eth2` | Chain-specific address and signing implementations |
| [`tcx-wasm`](./tcx-wasm) | Focused WebAssembly binding surface |
| [`test-data`](./test-data) | Fixtures for migration, scanning, and password-reset tests |

## Build

From the repository root:

```bash
make build-tcx
```

To compile the TokenCoreX C ABI crate directly:

```bash
cargo build -p tcx
```

For WebAssembly:

```bash
make test-wasm
make build-wasm
```

See the workspace build guide at [`../doc/BUILD.md`](../doc/BUILD.md).

## Test

```bash
# Run token-core unit, integration, and doc tests
make test-tcx

# Compile all workspace test targets before running narrower test sets
cargo test --workspace --no-run
```

`make test-tcx` sets `KDF_ROUNDS=1` to shorten keystore tests. This is a test
speed setting only.

Migration tests can be slow and may print "has been running for over 60
seconds"; that message does not necessarily mean the test is stuck.

## WebAssembly

`tcx-wasm` is the web-facing subset for browser/passkey-oriented flows. The
browser example lives in [`../examples/wasm`](../examples/wasm/README.md).

```bash
make build-wasm
make dev-wasm
```

The full mobile C ABI surface and the wasm surface are intentionally different.
Do not assume a function is exposed in wasm because it exists in `tcx`.

## Documentation

- [`tcx-docs/BUILD.md`](./tcx-docs/BUILD.md): historical TokenCoreX build notes.
- [`tcx-docs/API.zh.md`](./tcx-docs/API.zh.md): TokenCoreX API notes.
- [`tcx-docs/KEYS.zh.md`](./tcx-docs/KEYS.zh.md): key abstraction design.
- [`tcx-docs/KDF.zh.md`](./tcx-docs/KDF.zh.md): keystore KDF strategy.
- [`tcx-docs/TECH.zh.md`](./tcx-docs/TECH.zh.md): architecture notes.
- [`tcx-docs/INTEGRATION.md`](./tcx-docs/INTEGRATION.md): adding chain support.
- [`tcx-docs/FAQ.md`](./tcx-docs/FAQ.md): TokenCoreX FAQ.
- [`../doc/TEST.md`](../doc/TEST.md): current workspace test policy.
- [`../doc/COMPATIBILITY.md`](../doc/COMPATIBILITY.md): current compatibility matrix.

## Security

For vulnerability reports, follow the root policy in [`../SECURITY.md`](../SECURITY.md).

## License

Apache License, Version 2.0. See [`../LICENSE`](../LICENSE).
