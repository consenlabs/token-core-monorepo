## 1. 项目脚手架与构建环境

- [x] 1.1 创建 `web-core/` 目录结构：`Cargo.toml`、`src/lib.rs`、`src/wallet.rs`、`src/fido.rs`
- [x] 1.2 配置 `Cargo.toml`：设置 `crate-type = ["cdylib", "rlib"]`，添加所有依赖（k256、bip32、tiny-bip39 2.0、getrandom with js、wasm-bindgen、web-sys、js-sys、serde-wasm-bindgen 等）
- [x] 1.3 将 `web-core` 添加到根 `Cargo.toml` 的 `[workspace].members`
- [x] 1.4 安装 WASM 编译目标：`rustup target add wasm32-unknown-unknown`
- [x] 1.5 安装 wasm-pack：`cargo install wasm-pack`
- [x] 1.6 验证 `cargo check --target wasm32-unknown-unknown -p web-core` 编译通过
- [x] 1.7 验证 `wasm-pack build --target web` 生成 `pkg/` 目录（含 .wasm、.js、.d.ts）

## 2. Seed 生成接口（wasm-seed-generation）

- [x] 2.1 在 `src/wallet.rs` 中实现 `generate_mnemonic(word_count: u32) -> Result<String, JsError>`，使用 tiny-bip39 生成助记词
- [x] 2.2 在 `src/wallet.rs` 中实现 `mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<String, JsError>`，返回 hex 编码的 64 字节 seed
- [x] 2.3 添加 `#[wasm_bindgen]` 导出宏
- [x] 2.4 编写 wasm-bindgen-test 测试：使用 BIP39 标准测试向量验证助记词和 seed 生成的正确性

## 3. BIP44 密钥派生接口（wasm-bip44-derivation）

- [x] 3.1 在 `src/wallet.rs` 中实现 `derive_key(seed_hex: &str, path: &str) -> Result<JsValue, JsError>`，使用 bip32 crate 从 seed 派生密钥对，返回包含 public_key 和 private_key 的 JS 对象
- [x] 3.2 在 `src/wallet.rs` 中实现 `derive_public_key(seed_hex: &str, path: &str) -> Result<String, JsError>`，仅返回压缩公钥 hex
- [x] 3.3 添加 `#[wasm_bindgen]` 导出宏
- [x] 3.4 编写测试：使用已知 seed 和路径验证派生结果与 BIP44 参考实现一致

## 4. secp256k1 签名接口（wasm-secp256k1-signing）

- [x] 4.1 在 `src/wallet.rs` 中实现 `secp256k1_sign(private_key_hex: &str, message_hash_hex: &str) -> Result<JsValue, JsError>`，使用 k256 生成 ECDSA 可恢复签名，返回 { r, s, v } 对象
- [x] 4.2 在 `src/wallet.rs` 中实现 `secp256k1_verify(public_key_hex: &str, message_hash_hex: &str, signature_hex: &str) -> Result<bool, JsError>`
- [x] 4.3 添加 `#[wasm_bindgen]` 导出宏
- [x] 4.4 编写测试：使用 RFC 6979 测试向量验证签名正确性
- [x] 4.5 验证签名 normalize_s（low-S）行为

## 5. FIDO 注册接口（wasm-fido-register）

- [x] 5.1 在 `src/fido.rs` 中实现 `fido_register(options: JsValue) -> Result<JsValue, JsError>` 异步函数，通过 web-sys 调用 `navigator.credentials.create()`
- [x] 5.2 在 `publicKeyCredentialCreationOptions.extensions` 中自动包含 `prf: {}` 扩展声明
- [x] 5.3 解析 `AuthenticatorAttestationResponse`，提取 credential_id、public_key、attestation_object
- [x] 5.4 从 `getClientExtensionResults()` 读取 PRF 支持状态，包含在返回结果中
- [x] 5.5 处理错误场景：用户取消、WebAuthn 不支持、超时等
- [x] 5.6 添加 `#[wasm_bindgen]` 导出宏

## 6. FIDO PRF 密钥派生接口（wasm-fido-prf-key）

- [x] 6.1 在 `src/fido.rs` 中实现 `fido_derive_prf_key(options: JsValue) -> Result<JsValue, JsError>` 异步函数，通过 web-sys 调用 `navigator.credentials.get()` 并传入 PRF 扩展参数
- [x] 6.2 构造 PRF 扩展参数：`extensions: { prf: { eval: { first: <salt_buffer> } } }`，使用 js_sys::Object + js_sys::Reflect
- [x] 6.3 从 `getClientExtensionResults().prf.results.first` 提取 32 字节对称密钥
- [x] 6.4 处理错误场景：设备不支持 PRF、用户取消、凭证不可用等
- [x] 6.5 添加 `#[wasm_bindgen]` 导出宏

## 7. 集成验证

- [x] 7.1 执行 `cargo check --target wasm32-unknown-unknown -p web-core` 确认编译无错误
- [x] 7.2 执行 `wasm-pack build --target web` 确认生成完整的 JS/TS 绑定包
- [x] 7.3 检查生成的 `.d.ts` 文件，确认所有 8 个导出函数（generate_mnemonic、mnemonic_to_seed、derive_key、derive_public_key、secp256k1_sign、secp256k1_verify、fido_register、fido_derive_prf_key）均可见
- [x] 7.4 执行 `cargo tree -i getrandom -p web-core` 审计 getrandom 依赖路径，确认 js feature 已对所有路径生效
- [x] 7.5 验证 `cargo check`（默认 host target）不影响 token-core 和 imkey-core 的编译
- [x] 7.6 编写一个最小化的 HTML 测试页面，导入 WASM 模块并调用 `generate_mnemonic(12)` 验证端到端可用性
