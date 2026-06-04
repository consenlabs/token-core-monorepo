# Token Core Monorepo

Token Core Monorepo 是 imToken 软件钱包核心库与 imKey 硬件钱包核心库所在的
Rust workspace。仓库统一管理软件钱包、硬件钱包、WebAssembly、移动端 SDK 和
发布打包代码的 Rust toolchain 与依赖图。

English documentation: [`README.md`](./README.md)。

本仓库主要面向以下场景：

- `token-core`：软件钱包 keystore、账户派生、地址生成、交易/消息签名、迁移、
  Protobuf API 与 C ABI。
- `imkey-core`：imKey 硬件钱包 APDU 通信、设备管理、地址派生和签名命令封装。
- `token-core/tcx-wasm`：面向浏览器/WebAssembly 的 TokenCoreX 子集入口。
- `publish`：Android Maven Central 发布所需的打包与发布工程。

## 仓库边界

| 路径 | 作用 | 主要消费者 |
| ---- | ---- | ---------- |
| [`token-core`](./token-core/README.md) | 软件钱包核心 crate 与 C ABI 入口 `call_tcx_api` | iOS、Android、React Native、Rust 测试 |
| [`imkey-core`](./imkey-core/README.md) | 硬件钱包核心 crate 与 C ABI 入口 `call_imkey_api` | iOS、Android、硬件集成 |
| [`token-core/tcx-wasm`](./token-core/tcx-wasm) | 浏览器和 passkey 方向的 WebAssembly 绑定 | Web 应用、[`examples/wasm`](./examples/wasm/README.md) |
| [`publish/android`](./publish/android/README.md) | Android AAR 与 Maven Central 发布工程 | 发布自动化 |
| [`doc`](./doc) | workspace 构建、测试、发布、支持和兼容性文档 | 外部贡献者与维护者 |

## 环境要求

- Rust toolchain 固定在 [`rust-toolchain.toml`](./rust-toolchain.toml)：
  `nightly-2026-04-06`。
- 当前 CI 与移动端发布流程以 macOS 为主要 host。
- Protobuf 代码生成需要安装 `protobuf`。
- 只有构建 `tcx-wasm` 时才需要 `wasm32-unknown-unknown`、`wasm-pack` 和带
  wasm32 支持的 LLVM。
- 只有构建移动端发布产物时才需要 Android SDK/NDK 或 Xcode。

详细环境说明见 [`doc/BUILD.md`](./doc/BUILD.md)。

## 快速开始

```bash
git clone https://github.com/consenlabs/token-core-monorepo.git
cd token-core-monorepo

cargo build
make test-tcx
make test-ikc
```

`make test-tcx` 和 `make test-ikc` 会设置 `KDF_ROUNDS=1`，用于缩短
keystore 相关测试耗时。该设置不代表生产 KDF 配置。

## 常用命令

```bash
# 编译全部 workspace crate
cargo build

# 只编译全部测试目标，不执行测试
cargo test --workspace --no-run

# 运行软件钱包测试，排除 imKey wallet crate
make test-tcx

# 运行不依赖真实设备的 imKey host-safe 测试
make test-ikc

# 运行完整 host-safe workspace 验证
make test-workspace

# 连接并授权真实 imKey 设备后运行硬件测试
make test-hardware

# 验证 tcx-wasm 的 native 与 wasm32 编译
make test-wasm

# 构建并启动浏览器 wasm 示例
make dev-wasm
```

测试范围和硬件边界见 [`doc/TEST.md`](./doc/TEST.md)。

## 发布面

| 发布面 | 版本来源 | 产物 |
| ------ | -------- | ---- |
| Android | [`VERSION`](./VERSION) 与发布提交 | Maven Central AAR `io.github.consenlabs.android:token-core` |
| iOS | [`VERSION`](./VERSION) 与发布提交 | GitHub Release tag `v<VERSION>`，包含 TokenCoreX 与 imKeyCoreX XCFramework zip |
| WebAssembly | [`token-core/tcx-wasm/Cargo.toml`](./token-core/tcx-wasm/Cargo.toml) 与生成的 npm package metadata | `make build-npm` 生成的 `publish/npm` 文件 |

版本、tag 与产物关系见 [`doc/RELEASE.md`](./doc/RELEASE.md)。面向用户的变化应记录在
[`CHANGELOG.md`](./CHANGELOG.md)。

## 文档入口

- [`doc/BUILD.md`](./doc/BUILD.md)：本地、wasm、Android、iOS 构建环境。
- [`doc/TEST.md`](./doc/TEST.md)：host-safe、workspace、wasm 与硬件测试。
- [`doc/RELEASE.md`](./doc/RELEASE.md)：版本号、tag、产物和发布检查。
- [`doc/COMPATIBILITY.md`](./doc/COMPATIBILITY.md)：toolchain 与产物兼容矩阵。
- [`SECURITY.md`](./SECURITY.md)：安全漏洞报告政策。
- [`SUPPORT.md`](./SUPPORT.md)：支持范围与维护边界。
- [`token-core/tcx-docs`](./token-core/tcx-docs)：TokenCoreX API 与设计说明。
- [`imkey-core/ikc-docs`](./imkey-core/ikc-docs)：imKeyCore API 与设计说明。

## 安全

疑似安全漏洞不要提交公开 issue。请按 [`SECURITY.md`](./SECURITY.md) 说明发送到
`sec@token.im`。

## 许可证

本仓库使用 Apache License, Version 2.0，见 [`LICENSE`](./LICENSE)。
