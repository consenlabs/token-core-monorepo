# Token Core Monorepo

<p align="center">
  <a href="https://10.token.im/">
    <img alt="imToken 10th Anniversary" src="https://img.shields.io/badge/IMTOKEN-10th%20Anniversary-2168db?style=for-the-badge&amp;labelColor=2168db&amp;color=2168db">
  </a>
</p>



<p align="center">
  🎉
  <a href="https://10.token.im/">imToken 10th Anniversary invites you to AI co-create: your wallet, under your control</a>
  <br>
  🛠️
  <a href="https://github.com/consenlabs/token-core-monorepo/tree/tenth-anniversary/token-core/tcx-wasm">Build your wallet with tcx-wasm</a>
</p>

<p align="center">
  🌐
  <a href="./README.zh.md">中文 README</a>
</p>

This repository is a Rust workspace for imToken and imKey wallet core libraries. It keeps `token-core` and `imkey-core` on one Rust toolchain and one dependency graph, so their generated libraries can be integrated into mobile clients without Rust version conflicts.

## Components

- `token-core`: wallet keystore management, blockchain signing, and C-compatible APIs for mobile clients.
- `imkey-core`: imKey hardware wallet communication, device management, and secure signing without exposing private keys to the mobile client.
- `publish`: Android packaging and publishing configuration.
- `script`: local and CI build scripts for Android and iOS artifacts.

## Getting Started

```bash
git clone git@github.com:consenlabs/token-core-monorepo.git
cd token-core-monorepo
cargo build
cargo test
```

This workspace uses the Rust toolchain pinned in [rust-toolchain.toml](./rust-toolchain.toml).

## Common Commands

```bash
# Build token-core only
make build-tcx

# Run token-core tests
make test-tcx

# Run imkey-core tests
make test-ikc
```

`make test-tcx` and `make test-ikc` set `KDF_ROUNDS=1` to keep test execution fast.

## Packages

- [`token-core`](./token-core/README.md): TokenCoreX wallet core.
- [`tcx-wasm`](https://github.com/consenlabs/token-core-monorepo/tree/tenth-anniversary/token-core/tcx-wasm): TokenCoreX WebAssembly package.
- [`imkey-core`](./imkey-core/README.md): imKey wallet core.
- [`publish`](./publish/README.md): publishing entrypoint.
- [`publish/android`](./publish/android/README.md): Android publishing guide.

## Security Report

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
