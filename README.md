# TokenCore Monorepo

This repository is a Rust workspace for the core wallet libraries used by
imToken and imKey. It combines TokenCore and imKeyCore in one workspace so the
projects can share a pinned Rust toolchain and dependency versions.

For the Chinese README, see [README.zh.md](./README.zh.md).

## Workspace

- `token-core/` contains TokenCore crates for wallet keystores, cryptography,
  chain-specific signing, protobuf interfaces, migration logic, and WASM
  bindings.
- `imkey-core/` contains imKeyCore crates for hardware-wallet transport,
  device APIs, protobuf interfaces, and chain-specific signing.
- `publish/` contains package publishing outputs and instructions, including
  NPM and Android package workflows.
- `script/` contains local mobile build scripts for Android and iOS.
- `doc/` contains architecture notes and security reports.
- `examples/wasm/` contains the browser WASM example for `tcx-wasm`.

## Requirements

- Rust toolchain is pinned in [rust-toolchain.toml](./rust-toolchain.toml).
  `rustup` will install and select it automatically when running Cargo commands
  in this repository.
- Install standard Rust components when needed:

```bash
rustup component add rustfmt clippy
```

- WASM and package workflows require extra tools such as `wasm-pack`, LLVM
  tools, `wasm-opt`, Node.js, and npm, depending on the target command.
- Android and iOS packaging require the corresponding platform SDKs and Rust
  targets.

## Quick Start

```bash
git clone git@github.com:consenlabs/token-core-monorepo.git
cd token-core-monorepo

cargo build
cargo test
```

Use fewer KDF rounds for faster local test runs:

```bash
KDF_ROUNDS=1 cargo test
```

## Common Commands

```bash
# Build the whole workspace
cargo build

# Run the whole test suite
cargo test

# Build TokenCore crates
make build-tcx

# Build the protobuf crate
make build-tcx-proto

# Check TokenCore crates
make check-tcx

# Run TokenCore-focused tests
make test-tcx

# Run imKeyCore-focused tests
make test-ikc

# Format and verify formatting
cargo fmt --all
cargo fmt -- --check

# Run clippy with warnings treated as errors
cargo clippy --all-targets --all-features -- -D warnings
```

## WASM and NPM

```bash
# Build the browser WASM package and start the example app
make dev-wasm

# Build the optimized NPM package into publish/npm/
make build-npm

# Publish the NPM package
make publish-npm
```

When changing `#[wasm_bindgen]` exports in `token-core/tcx-wasm/src/lib.rs` or
`types.rs`, update `examples/wasm/` and [examples/wasm/README.md](./examples/wasm/README.md)
at the same time.

## Packages

- [token-core](./token-core/README.md)
- [imkey-core](./imkey-core/README.md)
- [publish](./publish/README.md)
- [WASM example](./examples/wasm/README.md)

## Security

Never commit secrets, private keys, mnemonic phrases, or keystores. Treat
signing, key management, serialization, and migration changes as
security-sensitive.

Security report:

- [imKey Security Report (CN)](./doc/imKeySecurityReport.pdf)

## License

```text
Copyright 2023 imToken PTE. LTD.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
