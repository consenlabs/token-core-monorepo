## Why

imToken 需要在 Web App 场景下提供客户端侧的密钥管理和签名能力。当前 `token-core`（移动端 C ABI）和 `imkey-core`（硬件钱包 APDU）均面向原生平台，无法在浏览器环境运行。

Web App 需要在浏览器中完成以下核心功能：
1. **钱包 seed 生成** — 需要安全的随机数源
2. **BIP44 密钥派生** — 从 seed 派生出各链的密钥对
3. **secp256k1 签名** — 对交易或消息进行 ECDSA 签名
4. **FIDO 设备交互** — 通过 WebAuthn API 进行 FIDO 设备注册，以及利用 PRF 扩展生成对称密钥

这些能力需要通过 Rust 编译为 **WebAssembly (WASM)** 供前端 JavaScript 调用，复用 Rust 生态的密码学实现，确保安全性和跨平台一致性。

第一阶段的核心目标是 **验证 WASM 编译的可行性**：配置所有必要的依赖库，定义接口原型，确保整条工具链（Rust → WASM → JS 调用）打通。

## What Changes

- **新增 `web-core/` 模块**：在 monorepo 中新增顶层目录 `web-core/`，对标 `token-core/` 和 `imkey-core/` 的组织方式，但输出目标为 `wasm32-unknown-unknown`，通过 `wasm-bindgen` 暴露接口
- **新增 seed 生成接口**：利用浏览器 WebCrypto API（`crypto.getRandomValues()`）作为随机数源，生成 BIP39 助记词和 seed
- **新增 BIP44 密钥派生接口**：从 seed 派生指定路径（如 `m/44'/60'/0'/0/0`）的密钥对，返回公钥和（加密的）私钥
- **新增 secp256k1 签名接口**：接收私钥和待签名数据，返回 ECDSA 签名结果
- **新增 FIDO 注册接口**：通过 WebAuthn API 调用 `navigator.credentials.create()`，完成 FIDO 设备注册
- **新增 FIDO PRF 密钥派生接口**：通过 WebAuthn PRF 扩展（`hmac-secret`），基于 salt 生成确定性的对称密钥
- **集成 WASM 构建工具链**：配置 `wasm-bindgen`、`wasm-pack`、构建脚本，确保可编译为 WASM 并生成 JS/TS 绑定

## Capabilities

### New Capabilities

- `wasm-seed-generation`: 在 WASM 环境中通过 WebCrypto 安全随机数源生成 BIP39 助记词和 seed
- `wasm-bip44-derivation`: 在 WASM 环境中从 seed 进行 BIP44 路径密钥派生，返回公钥
- `wasm-secp256k1-signing`: 在 WASM 环境中进行 secp256k1 ECDSA 签名
- `wasm-fido-register`: 在 WASM 环境中通过 WebAuthn API 进行 FIDO 设备注册
- `wasm-fido-prf-key`: 在 WASM 环境中通过 WebAuthn PRF 扩展生成对称密钥
- `wasm-build-pipeline`: WASM 构建工具链配置（Cargo、wasm-bindgen、wasm-pack）和可行性验证

### Modified Capabilities

（无。web-core 为全新模块，不修改现有 token-core 或 imkey-core 的功能。）

## Impact

- **Cargo workspace**：根目录 `Cargo.toml` 需新增 `web-core/` 的 crate 到 `[workspace].members`
- **依赖选型变化**：web-core 无法使用 C 依赖的 crate（如 `secp256k1-sys`），需替换为纯 Rust 实现：
  - `secp256k1` → `k256`（RustCrypto，纯 Rust，WASM 兼容）
  - `bitcoin` crate 的 BIP32 模块 → 独立的 `bip32` crate（纯 Rust）
  - `tiny-bip39` 1.0 → `tiny-bip39` 2.0（有 wasm-bindgen 支持）
  - `getrandom` 需启用 `js` feature 以使用 `crypto.getRandomValues()`
- **新增依赖**：`wasm-bindgen`、`wasm-bindgen-futures`、`web-sys`、`js-sys`、`serde-wasm-bindgen`
- **构建工具链**：需安装 `wasm32-unknown-unknown` target、`wasm-bindgen-cli`、可选 `wasm-opt`
- **CI/CD**：后续需新增 WASM 构建和测试的 CI workflow（不在第一阶段范围内）
- **与 token-core / imkey-core 的关系**：web-core 为独立模块，不依赖也不被现有模块依赖；未来可能抽取共享的纯 Rust 密码学层
