# Token Core Monorepo

Token Core Monorepo is the Rust workspace behind imToken software wallet
core libraries and imKey hardware wallet core libraries. It keeps the
software-wallet, hardware-wallet, WebAssembly, mobile SDK, and release
packaging code on one pinned Rust toolchain and one dependency graph.

Chinese documentation: [`README.zh.md`](./README.zh.md).

Use this repository when you need to build or inspect:

- `token-core`: software wallet keystore, account derivation, address
  generation, transaction/message signing, migration, Protobuf API, and C ABI.
- `imkey-core`: imKey hardware wallet APDU transport, device management,
  address derivation, and signing command wrappers.
- `token-core/tcx-wasm`: browser/WebAssembly entrypoint for a focused
  TokenCoreX surface.
- `publish`: Android Maven Central packaging and release support files.

## Repository Map

| Path | Purpose | Main consumer |
| ---- | ------- | ------------- |
| [`token-core`](./token-core/README.md) | Software wallet core crates and C ABI entrypoint `call_tcx_api` | iOS, Android, React Native, Rust tests |
| [`imkey-core`](./imkey-core/README.md) | Hardware wallet core crates and C ABI entrypoint `call_imkey_api` | iOS, Android, hardware integration |
| [`token-core/tcx-wasm`](./token-core/tcx-wasm) | WebAssembly bindings for browser/passkey-oriented flows | Web apps, [`examples/wasm`](./examples/wasm/README.md) |
| [`publish/android`](./publish/android/README.md) | Android AAR and Maven Central publishing project | Release automation |
| [`doc`](./doc) | Workspace build, test, release, support, and compatibility docs | External contributors and maintainers |

## Requirements

- Rust toolchain pinned by [`rust-toolchain.toml`](./rust-toolchain.toml):
  `nightly-2026-04-06`
- macOS is the primary host for the current CI and mobile release workflows.
- `protobuf` is required for Protobuf code generation.
- `wasm32-unknown-unknown`, `wasm-pack`, and LLVM with wasm32 support are
  required only for `tcx-wasm` builds.
- Android SDK/NDK and Xcode are required only for mobile release artifacts.

For detailed setup, see [`doc/BUILD.md`](./doc/BUILD.md).

## Quick Start

```bash
git clone https://github.com/consenlabs/token-core-monorepo.git
cd token-core-monorepo

cargo build
make test-tcx
make test-ikc
```

`make test-tcx` and `make test-ikc` set `KDF_ROUNDS=1` to keep keystore-related
tests practical for local and CI runs. This does not describe production KDF
settings.

## Common Commands

```bash
# Compile all workspace crates
cargo build

# Compile all workspace test targets without running them
cargo test --workspace --no-run

# Run software-wallet tests, excluding imKey wallet crates
make test-tcx

# Run imKey host-safe tests that do not require a physical device
make test-ikc

# Run the full host-safe workspace verification
make test-workspace

# Run hardware tests with a connected and authorized imKey device
make test-hardware

# Verify native and wasm32 compilation for tcx-wasm
make test-wasm

# Build and run the browser wasm example
make dev-wasm
```

For test scope and hardware boundaries, see [`doc/TEST.md`](./doc/TEST.md).

## Release Surfaces

| Surface | Version source | Artifact |
| ------- | -------------- | -------- |
| Android | [`VERSION`](./VERSION) plus release commit | Maven Central AAR `io.github.consenlabs.android:token-core` |
| iOS | [`VERSION`](./VERSION) plus release commit | GitHub Release tag `v<VERSION>` with TokenCoreX and imKeyCoreX XCFramework zips |
| WebAssembly | [`token-core/tcx-wasm/Cargo.toml`](./token-core/tcx-wasm/Cargo.toml) and generated npm package metadata | `publish/npm` package files built by `make build-npm` |

Release policy and version/tag conventions are documented in
[`doc/RELEASE.md`](./doc/RELEASE.md). User-facing changes should be recorded in
[`CHANGELOG.md`](./CHANGELOG.md).

## Documentation

- [`doc/BUILD.md`](./doc/BUILD.md): local, wasm, Android, and iOS build setup.
- [`doc/TEST.md`](./doc/TEST.md): host-safe, workspace, wasm, and hardware tests.
- [`doc/RELEASE.md`](./doc/RELEASE.md): versioning, tags, artifacts, and release checks.
- [`doc/COMPATIBILITY.md`](./doc/COMPATIBILITY.md): supported toolchains and artifact matrix.
- [`SECURITY.md`](./SECURITY.md): vulnerability reporting policy.
- [`SUPPORT.md`](./SUPPORT.md): supported questions and maintenance boundaries.
- [`token-core/tcx-docs`](./token-core/tcx-docs): TokenCoreX API and design notes.
- [`imkey-core/ikc-docs`](./imkey-core/ikc-docs): imKeyCore API and design notes.

## Security

Do not open public issues for suspected vulnerabilities. Follow
[`SECURITY.md`](./SECURITY.md) and report security issues to `sec@token.im`.

## License

This repository is licensed under the Apache License, Version 2.0. See
[`LICENSE`](./LICENSE).
