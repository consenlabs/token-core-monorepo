# TokenCore Monorepo

<p align="center">
  <a href="https://10.token.im/">
    <img alt="imToken 十周年" src="https://img.shields.io/badge/IMTOKEN-%E5%8D%81%E5%91%A8%E5%B9%B4-2168db?style=for-the-badge&amp;labelColor=2168db&amp;color=2168db">
  </a>
</p>

<p align="center">
  <a href="https://10.token.im/">imToken 十周年邀请你参与 AI 共创：你的钱包，由你掌控</a>
  <br>
  <a href="https://github.com/consenlabs/token-core-monorepo/tree/tenth-anniversary/token-core/tcx-wasm">使用 tcx-wasm 构建你的钱包</a>
</p>

[English](./README.md)

本仓库是 imToken 与 imKey 钱包核心库的 Rust workspace。它将 `token-core` 与 `imkey-core` 统一到同一个 Rust 工具链和依赖图中，避免由不同 Rust 版本编译出的库文件在移动端集成时产生冲突。

## 组件

- `token-core`：提供钱包 keystore 管理、区块链签名能力，以及面向移动端的 C 兼容接口。
- `imkey-core`：提供 imKey 硬件钱包通信、设备管理和安全签名能力，签名过程不会向移动端暴露私钥。
- `publish`：Android 包构建与发布配置。
- `script`：Android 与 iOS 制品的本地和 CI 构建脚本。

## 快速开始

```bash
git clone git@github.com:consenlabs/token-core-monorepo.git
cd token-core-monorepo
cargo build
cargo test
```

本 workspace 使用 [rust-toolchain.toml](./rust-toolchain.toml) 中锁定的 Rust 工具链。

## 常用命令

```bash
# 仅构建 token-core
make build-tcx

# 运行 token-core 测试
make test-tcx

# 运行 imkey-core 测试
make test-ikc
```

`make test-tcx` 和 `make test-ikc` 会设置 `KDF_ROUNDS=1`，以缩短测试执行时间。

## 包说明

- [`token-core`](./token-core/README.md)：TokenCoreX 钱包核心。
- [`tcx-wasm`](https://github.com/consenlabs/token-core-monorepo/tree/tenth-anniversary/token-core/tcx-wasm)：TokenCoreX WebAssembly 包。
- [`imkey-core`](./imkey-core/README.md)：imKey 钱包核心。
- [`publish`](./publish/README.md)：发布入口说明。
- [`publish/android`](./publish/android/README.md)：Android 发布指南。

## 安全报告

- [imKey 安全报告（中文）](./doc/imKeySecurityReport.pdf)

## 许可证

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
