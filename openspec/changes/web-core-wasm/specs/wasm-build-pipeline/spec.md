## ADDED Requirements

### Requirement: WASM 编译可行性
web-core crate SHALL 能够成功编译到 `wasm32-unknown-unknown` 目标，所有依赖 SHALL 为纯 Rust 实现，不依赖任何 C/系统库。

#### Scenario: cargo check 通过
- **WHEN** 执行 `cargo check --target wasm32-unknown-unknown -p web-core`
- **THEN** 编译成功，无错误（warning 可接受）

#### Scenario: wasm-pack build 通过
- **WHEN** 在 `web-core/` 目录执行 `wasm-pack build --target web`
- **THEN** 生成 `pkg/` 目录，包含 `web_core_bg.wasm`、`web_core.js`、`web_core.d.ts` 文件

### Requirement: JS 绑定可用
生成的 JS 绑定 SHALL 可在浏览器环境中正常导入和调用。

#### Scenario: 导入 WASM 模块
- **WHEN** 在浏览器 JS 中执行 `import init, { generate_mnemonic } from './pkg/web_core.js'`
- **THEN** 模块加载成功，`generate_mnemonic` 函数可调用

#### Scenario: 所有导出函数可见
- **WHEN** 加载 WASM 模块后检查导出的函数列表
- **THEN** SHALL 包含以下函数：`generate_mnemonic`、`mnemonic_to_seed`、`derive_key`、`derive_public_key`、`secp256k1_sign`、`secp256k1_verify`、`fido_register`、`fido_derive_prf_key`

### Requirement: Cargo workspace 集成
web-core SHALL 作为 workspace member 加入根 `Cargo.toml`，且不影响其他 crate 的原生目标编译。

#### Scenario: 原生目标编译不受影响
- **WHEN** 执行 `cargo check`（默认 host target）
- **THEN** web-core 可能因 wasm-bindgen 等依赖报 warning 或被跳过，但 token-core 和 imkey-core 的所有 crate 编译不受影响

#### Scenario: 独立编译 web-core
- **WHEN** 执行 `cargo check --target wasm32-unknown-unknown -p web-core`
- **THEN** 仅编译 web-core 及其依赖，不涉及 token-core 或 imkey-core 的 crate
