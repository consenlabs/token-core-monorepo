# AGENTS.md

本文件记录当前仓库的结构和协作约定，供后续自动化 agent 或维护者快速接手。

## 项目概览

`token-core-monorepo` 是 imToken / imKey 钱包核心库的 Rust monorepo。根目录是一个 Cargo workspace，统一管理 `token-core` 和 `imkey-core` 的 Rust toolchain、依赖图、测试和移动端打包产物。

核心目标：

- `token-core`：软件钱包核心能力，包括 keystore、助记词/私钥导入导出、多链地址派生、交易/消息签名、迁移、C ABI/Protobuf API。
- `imkey-core`：imKey 硬件钱包核心能力，包括 HID/APDU 通信、设备管理、多链地址/签名命令封装、移动端 SDK 桥接。
- `publish` / `script`：Android/iOS 产物构建和发布脚本。
- `vendor`：本仓库 patch 的第三方依赖源码，目前通过 `[patch.crates-io]` 使用 `vendor/crypto-common-0.1.7`。

## Toolchain 与构建环境

- Rust toolchain 固定在 `rust-toolchain.toml`：`nightly-2026-04-06`。
- 根 workspace 使用 Cargo resolver v2。
- `.cargo/config.toml` 设置：
  - `rustc-wrapper = "scripts/rustc-wrapper.sh"`
  - `--check-cfg=cfg(tarpaulin)`
- `scripts/rustc-wrapper.sh` 会设置 macOS deployment target，以适配当前 Rust 最低支持的 macOS 版本。
- `Makefile` 中 `test-tcx` / `test-ikc` 显式设置 `MACOSX_DEPLOYMENT_TARGET=10.12` 和 `KDF_ROUNDS=1`。

`MACOSX_DEPLOYMENT_TARGET` 只影响 macOS 构建产物的最低系统版本声明和链接环境，不应改变钱包算法、地址、签名或 keystore 业务逻辑。

## Workspace 结构

根 `Cargo.toml` 的主要成员分组：

### token-core

- `token-core/tcx`：TokenCoreX 对外 API wrapper，C ABI 入口是 `call_tcx_api`，内部通过 Protobuf `TcxAction` 分发到 handler。
- `token-core/tcx-proto`：TokenCoreX Protobuf 类型生成。
- `token-core/tcx-common`：通用工具、hex/hash/rand 等。
- `token-core/tcx-constants`：链、网络、曲线等常量定义。
- `token-core/tcx-primitive`：底层密钥、BIP32、BLS、Ed25519、Sr25519、Secp256k1、派生路径等。
- `token-core/tcx-crypto`：加解密、KDF、keystore crypto。
- `token-core/tcx-keystore`：HD/private keystore、身份、签名接口、账户派生。
- `token-core/tcx-migration`：旧 keystore 迁移、扫描、升级。
- `token-core/tcx-btc-kin`、`tcx-eth`、`tcx-tron`、`tcx-ckb`、`tcx-atom`、`tcx-eos`、`tcx-substrate`、`tcx-filecoin`、`tcx-tezos`、`tcx-ton`、`tcx-eth2`：链级地址和签名实现。
- `token-core/tcx-libs`：本地维护/集成的底层库，例如 `ed25519-dalek-bip32`、`tonlib-core`。
- `token-core/test-data`：迁移、扫描、重置密码等测试 fixture，测试会读写这些数据的临时副本。

### imkey-core

- `imkey-core/ikc`：imKey 对外 API wrapper，C ABI 入口是 `call_imkey_api`，内部通过 Protobuf `ImkeyAction` 分发。
- `imkey-core/ikc-proto`：imKey Protobuf 类型生成。
- `imkey-core/ikc-common`：APDU 构造、路径校验、hex/hash/crypto 公共工具、TSM HTTPS client。
- `imkey-core/ikc-transport`：HID 设备连接和 APDU 发送；`hid_connect` 会访问真实 imKey 设备。
- `imkey-core/ikc-device`：设备管理、绑定、激活、COS/app 管理、证书检查。
- `imkey-core/ikc-wallet/coin-*`：各链硬件钱包地址和签名命令封装。
- `imkey-core/mobile-sdk`、`ikc-examples`、`blelibrary`：移动 SDK 和示例工程。

## 对外 API 边界

### TokenCoreX

入口文件：`token-core/tcx/src/lib.rs`

- `call_tcx_api(hex_str)`：C ABI 入口，入参是 hex 编码后的 Protobuf action。
- 通过 `landingpad` 捕获错误，并把错误保存在 `LAST_ERROR`。
- 对外错误字符串是兼容性边界，不要随意让底层依赖错误文本泄漏到 API 层。

### imKeyCore

入口文件：`imkey-core/ikc/src/lib.rs`

- `call_imkey_api(hex_str)`：C ABI 入口，入参是 hex 编码后的 Protobuf action。
- `get_apdu` / `set_apdu` / `get_apdu_return` / `set_apdu_return` / `set_callback` 用于 APDU 桥接。
- 硬件相关测试和功能通常会经过 `ikc-transport` 的 `hid_connect` 或 callback APDU 通道。

## 常用命令

```bash
# 编译全部 workspace
cargo build

# TokenCoreX 测试，不包含 imkey-core/coin-* 测试
make test-tcx

# imkey-core 测试；注意：包含需要真实 imKey 设备的测试
make test-ikc

# 编译检查
cargo check --workspace

# 只编译测试目标，不实际执行
cargo test --workspace --no-run

# 格式化
cargo fmt

# 检查补丁空白问题
git diff --check
```

## 测试注意事项

### token-core

`make test-tcx` 当前用于验证软件钱包侧功能，命令实际执行：

```bash
MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 cargo test --workspace --exclude 'ikc*' --exclude 'coin*'
```

该目标会运行 `token-core` 相关单测、集成测试和 doc-test。迁移测试耗时较长，出现 “has been running for over 60 seconds” 不一定是卡死。

### imkey-core

`make test-ikc` 会执行 imkey 侧 workspace 测试，但其中很多测试需要真实 imKey 设备或 APDU 通道，例如：

- 调用 `bind_test()`
- 调用 `hid_connect(...)`
- 通过 `send_apdu(...)` 与设备交互
- 地址展示、xpub 获取、硬件签名、设备管理、绑定、COS/app 管理测试

没有连接设备时，完整 `make test-ikc` 可能失败，这是测试环境问题，不一定是代码回归。

不需要连接设备的本地测试可通过 `cargo test --workspace --exclude 'tcx*' -- --skip ...` 过滤硬件测试执行。当前已验证过本地集合，另外 `https::test::post_test` 依赖外部 TSM 网络接口，也应与纯本地测试分开看待。

### KDF_ROUNDS

测试命令设置 `KDF_ROUNDS=1`，用于缩短 keystore 加密/解密相关测试耗时。不要把该环境变量理解为生产默认配置。

## 依赖和升级注意事项

- 依赖版本应在 `Cargo.toml` 中固定到完整版本号，例如 `=1.0.11`，避免只写大版本。
- 依赖升级记录维护在 `dependency-upgrade-list.md`。
- 根 `Cargo.toml` 通过 `[patch.crates-io]` 指向 `vendor/crypto-common-0.1.7`，不要误删该 patch。
- 升级底层加密、地址、BIP32、bech32、bitcoin、substrate 相关库时，要特别关注：
  - 地址字符串兼容性。
  - 错误码兼容性。
  - derivation path 解析宽松度变化。
  - 签名 hash、txid/wtxid、序列化输出变化。
  - Protobuf/C ABI 对外错误字符串。

## 最近已知兼容性修复点

这些点是依赖升级后容易再次踩到的兼容性边界：

- `token-core/tcx-btc-kin/src/address.rs`
  - Dogecoin `VERSION_1` 地址存在空 HRP 的历史兼容输出，需要使用 `bech32::Hrp::parse_unchecked` 保持旧行为。
  - base58 解码失败应映射为业务错误 `invalid_address`，不要泄漏依赖库内部错误文本。
- `token-core/tcx-primitive/src/derive.rs`
  - account path 必须以 `m` 开头，缺少 `m/` 的相对路径不能被当成合法 account path。
- `token-core/tcx/src/handler.rs`
  - 无效 sr25519 私钥在 API 边界应返回 `invalid_private_key`，不要暴露底层 `invalid_sr25519_key`。
- `imkey-core/ikc-common/src/path.rs`
  - path 校验要同时检查层级和 BIP32 格式；末尾 `/` 保持兼容，但 `m/44a'/...` 应拒绝。
- `imkey-core/ikc-wallet/coin-bitcoin/src/usdt_transaction.rs`
  - 金额扣减要避免 `u64` 下溢；资金不足应返回 `imkey_amount_less_than_minimum`，不要 panic。

## 代码修改约定

- 优先遵循现有 crate 的局部风格，不做无关重构。
- 修改对外 API、错误码、地址/签名输出前，先找现有测试和历史兼容断言。
- 对 `token-core/test-data` 和 `imkey-core/test-data` 保持谨慎，除非测试预期确实变化，否则不要更新 fixture。
- 设备相关测试不要当作普通 CI 本地测试直接修成跳过；需要明确区分“代码回归”和“没有真实设备”。
- 对依赖升级引发的 deprecation/warning，优先迁移到新 API，但必须保持行为和错误码兼容。
- 修改后至少运行相关 crate 的目标测试；涉及共享行为时运行 workspace 级测试。

## 文档入口

- 根 README：`README.md` / `README.zh.md`
- TokenCoreX 文档：`token-core/tcx-docs/`
- imKeyCore 文档：`imkey-core/ikc-docs/`
- 发布文档：`publish/README.md`、`publish/android/README.md`
- 依赖升级记录：`dependency-upgrade-list.md`

