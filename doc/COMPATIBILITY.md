# Compatibility Matrix

This matrix summarizes the supported build and consumption surfaces for the
current repository state.

## Toolchain and Host

| Area | Current support |
| ---- | --------------- |
| Rust toolchain | `nightly-2026-04-06`, pinned by `rust-toolchain.toml` |
| Cargo resolver | Workspace resolver v2 |
| Primary CI host | `macos-14` for Rust, mobile, and wasm jobs |
| Linux CI host | `ubuntu-latest` for `cargo-deny` advisories, licenses, and sources |
| macOS deployment target for host tests | `10.12`, set by Makefile test env and rustc wrapper |
| iOS deployment target for release workflow | `14.0` |
| Android compile/target SDK in publishing project | `30` |
| Android minimum SDK in publishing project | `19` |
| Android NDK used by release workflow | `25.2.9519653` |

## Package Surfaces

| Surface | Path | API boundary | Build output |
| ------- | ---- | ------------ | ------------ |
| TokenCoreX mobile core | `token-core/tcx` | C ABI `call_tcx_api`, hex-encoded Protobuf `TcxAction` | `libtcx` static/dynamic libraries, iOS `TokenCoreX.xcframework`, Android native libs inside AAR |
| imKeyCore mobile core | `imkey-core/ikc` | C ABI `call_imkey_api`, hex-encoded Protobuf `ImkeyAction` | `libconnector` static/dynamic libraries, iOS `imKeyCoreX.xcframework`, Android native libs inside AAR |
| tcx-wasm | `token-core/tcx-wasm` | `wasm-bindgen` JSON string API | `tcx_wasm_bg.wasm`, JS glue, TypeScript declarations |
| Android AAR | `publish/android` | Maven package `io.github.consenlabs.android:token-core` | `tokencore-release.aar` |
| Browser example | `examples/wasm` | Next.js app consuming generated wasm files | Local dev app on `localhost:3000` |

## Test Boundary

| Test path | Requires hardware | Requires network | Command |
| --------- | ----------------- | ---------------- | ------- |
| TokenCoreX host tests | No | No by default | `make test-tcx` |
| imKeyCore host-safe tests | No | No; skips external TSM post test | `make test-ikc` |
| Workspace compile and host-safe tests | No | No by default | `make test-workspace` |
| imKey hardware tests | Yes | Depends on device/app flow | `make test-hardware` |
| tcx-wasm compile checks | No | No | `make test-wasm` |

## Compatibility-Sensitive Behavior

Review existing tests and historical assertions before changing:

- Address string formats.
- Transaction hashes, witness hashes, serialized transactions, and signatures.
- Derivation path parsing, especially account paths that must start with `m`.
- Keystore encryption/decryption and KDF behavior.
- Protobuf field names, enum values, and C ABI request/response shapes.
- API-facing error strings returned by `call_tcx_api` and `call_imkey_api`.
- imKey APDU command encoding and response parsing.
- Android Maven coordinates and iOS framework names.
- `tcx-wasm` JSON field names and TypeScript declarations.

## Known Compatibility Notes

- Dogecoin `VERSION_1` bech32 compatibility in `tcx-btc-kin` depends on
  preserving historical empty-HRP behavior.
- Invalid base58 addresses should map to business-level `invalid_address`
  errors instead of dependency error text.
- Invalid sr25519 private keys should map to API-facing `invalid_private_key`.
- imKey derivation paths must validate both hierarchy and BIP32 formatting.
- USDT transaction amount checks must avoid `u64` underflow and return
  `imkey_amount_less_than_minimum` for insufficient funds.

These notes are compatibility boundaries, not a full substitute for tests.
