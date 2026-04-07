## Context

`token-core-monorepo` 通过 `token-core/`（移动端 C ABI）和 `imkey-core/`（硬件钱包 APDU）向原生平台提供密钥管理和签名能力。两者均编译为 `staticlib`/`cdylib`，通过 protobuf 编码的 C FFI 接口与上层通信。

现需新增 `web-core/` 模块，目标平台为浏览器（`wasm32-unknown-unknown`），通过 `wasm-bindgen` 将 Rust 函数导出为 JavaScript 可调用的接口。

关键约束：
- WASM 环境没有系统随机数源、文件系统、网络 socket 和线程
- 不能使用任何 C 依赖的 crate（`secp256k1-sys`、`ring`、`openssl-sys` 等）
- WebAuthn/FIDO API 只能通过浏览器 JS API 访问，需要 `wasm-bindgen` + `web-sys` 桥接
- 项目当前 Rust 工具链为 nightly，web-core 的依赖需兼容该工具链

## Goals / Non-Goals

**Goals：**
- 建立 `web-core/` 模块的项目结构和 WASM 构建流水线
- 定义 seed 生成、BIP44 派生、secp256k1 签名三个核心钱包接口
- 定义 FIDO 注册和 PRF 对称密钥生成两个 WebAuthn 接口
- 配置所有必要的纯 Rust 依赖，验证 WASM 编译可行性
- 确保通过 `wasm-pack build` 可生成完整的 JS/TS 绑定包

**Non-Goals：**
- 不实现完整的钱包业务逻辑（如 keystore 管理、多链支持）
- 不实现 UI 或前端集成层
- 不实现 CI/CD 自动化（第一阶段手动验证）
- 不与 token-core / imkey-core 共享 crate（未来优化方向）
- 不涉及私钥的持久化存储方案
- 不处理 WASM 二进制体积优化（后续阶段）

## Decisions

### 决策 1：密码学库选型 — 全部使用 RustCrypto 纯 Rust 实现

**选择**：
| 功能 | 现有 token-core 依赖 | web-core 替代方案 |
|------|---------------------|-------------------|
| secp256k1 签名 | `secp256k1` (C-based, `secp256k1-sys`) | `k256` (RustCrypto, 纯 Rust) |
| BIP32 派生 | `bitcoin` crate 的 bip32 模块 | `bip32` crate (RustCrypto, 纯 Rust) |
| BIP39 助记词 | `tiny-bip39` 1.0 | `tiny-bip39` 2.0（有 wasm-bindgen 支持）|
| 哈希 | `sha2`, `bitcoin_hashes` | `sha2` (RustCrypto) |

**理由**：`secp256k1-sys` 依赖 C 编译器（`cc` crate），在 `wasm32-unknown-unknown` 目标下编译复杂且脆弱。`k256` 是 RustCrypto 项目维护的纯 Rust secp256k1 实现，支持 ECDSA 签名/验证、公钥恢复、`no_std`，编译到 WASM 无障碍。

**否决的方案**：使用 `secp256k1` + emscripten 交叉编译。否决原因：构建配置复杂、CI 难维护、每次需要 clang WASM backend。

### 决策 2：随机数源 — getrandom + js feature

**选择**：使用 `getrandom` crate 的 `js` feature（0.2.x）或 `wasm_js` feature（0.3.x），在 WASM 中自动调用浏览器的 `crypto.getRandomValues()`。

**实现方式**：
```toml
getrandom = { version = "0.2", features = ["js"] }
```

**理由**：`getrandom` 是 Rust 生态的标准随机数源抽象。`rand` crate 和其他密码学 crate 均通过 `getrandom` 获取随机数。启用 `js` feature 后，它会通过 `wasm-bindgen` 调用浏览器 `crypto.getRandomValues()`，这是浏览器环境唯一的密码学安全随机数源。

**需确认事项**：如果项目中同时存在 `getrandom` 0.2.x 和 0.3.x（通过不同的 transitive dependency），需要确保两者都启用了相应的 JS feature。可通过 `cargo tree -i getrandom` 审计。

### 决策 3：WASM 接口暴露方式 — wasm-bindgen + serde-wasm-bindgen

**选择**：使用 `#[wasm_bindgen]` 宏导出 Rust 函数。复杂数据结构通过 `serde-wasm-bindgen` 在 Rust struct 和 JS `JsValue` 之间转换。

**接口设计原则**：
- 简单参数（字符串、字节数组）直接通过 `wasm-bindgen` 类型传递
- 复杂输入/输出使用 `serde::Serialize` + `serde-wasm-bindgen::to_value()` 转换为 JS 对象
- 异步操作（FIDO）使用 `wasm-bindgen-futures` + `async fn` 导出为 JS `Promise`
- 返回结果统一为 `Result<JsValue, JsError>` 格式

**否决的方案**：protobuf 编码（与 token-core 一致）。否决原因：Web 环境下 JS 对象和 JSON 是更自然的数据交换格式，protobuf 增加了不必要的序列化/反序列化复杂度和二进制体积。

### 决策 4：WebAuthn/FIDO 接口 — 直接使用 web-sys 绑定

**选择**：通过 `web-sys` + `js-sys` 直接调用浏览器的 `navigator.credentials.create()` 和 `navigator.credentials.get()` API，手动构造 PRF 扩展参数。

**理由**：目前不存在成熟的 Rust WebAuthn 客户端 crate 支持 PRF 扩展。`web-sys` 提供了与浏览器 API 的类型安全绑定。PRF 扩展属于较新的 W3C 规范特性，需要通过 `js_sys::Object` + `js_sys::Reflect` 手动构造扩展参数对象。

**PRF 扩展的实现方式**：
- FIDO 注册时：在 `publicKeyCredentialCreationOptions.extensions` 中设置 `prf: {}` 以声明 PRF 能力
- PRF 密钥派生时：在 `publicKeyCredentialRequestOptions.extensions` 中设置 `prf: { eval: { first: <salt> } }`，从响应的 `getClientExtensionResults().prf.results.first` 获取派生密钥

**需确认事项**：
1. `web-sys` 是否已包含 `PublicKeyCredentialCreationOptions` 等 WebAuthn 类型的完整绑定？部分较新的 API 可能需要通过 `js_sys` 动态构造
2. PRF 扩展的 `extensions` 输入和 `getClientExtensionResults()` 输出可能没有强类型绑定，需要通过 `JsValue` 动态访问

### 决策 5：项目结构 — 单 crate 起步

**选择**：第一阶段 `web-core/` 仅包含一个 crate（`web-core`），所有功能在同一个 crate 内实现。

```
web-core/
├── Cargo.toml          # crate-type = ["cdylib", "rlib"]
├── src/
│   ├── lib.rs          # wasm-bindgen exports
│   ├── wallet.rs       # seed 生成、BIP44 派生、签名
│   └── fido.rs         # FIDO 注册、PRF 密钥派生
└── tests/
    └── web.rs          # wasm-bindgen-test
```

**理由**：第一阶段核心目标是验证 WASM 可行性，不需要过早拆分 crate。WASM 的 cdylib 入口天然是单 crate。后续可按需拆分为 `web-core-crypto`、`web-core-fido` 等子 crate。

**否决的方案**：一开始就复刻 token-core 的多 crate 结构。否决原因：增加维护成本且第一阶段没有复用需求。

### 决策 6：构建方式 — wasm-pack 为主

**选择**：使用 `wasm-pack build --target web` 作为主构建命令，输出包含 `.wasm`、`.js`、`.d.ts` 绑定文件的 `pkg/` 目录。

**理由**：虽然 `wasm-pack` 的维护有所减弱，但它仍然是 one-command 构建的最简单方案，尤其适合第一阶段验证。它自动调用 `wasm-bindgen`、生成 package.json、处理 WASM 优化。

**备选方案**（如 wasm-pack 遇到问题可切换）：
```bash
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/web_core.wasm --out-dir pkg --target web
wasm-opt pkg/web_core_bg.wasm -O3 -o pkg/web_core_bg.wasm
```

## Risks / Trade-offs

**[k256 与 secp256k1 签名结果不一致]** → k256 和 bitcoin/secp256k1 虽然实现同一椭圆曲线，但 DER 编码、normalize_s 等细节可能导致签名字节不同。缓解措施：使用已知测试向量（如 BIP-340、RFC 6979）验证两者输出一致性。

**[getrandom transitive dependency 未启用 js feature]** → 任何间接依赖 `getrandom` 但未启用 `js` feature 的 crate 会导致 WASM 编译失败（`compile_error!`）。缓解措施：构建后运行 `cargo tree -i getrandom` 审计所有引用路径，在 `web-core/Cargo.toml` 中通过 `[target.'cfg(target_arch = "wasm32")'.dependencies]` 显式启用。

**[WebAuthn PRF 扩展的浏览器兼容性]** → PRF 扩展是较新的 W3C 规范特性，并非所有浏览器/平台都支持。已知支持：Chrome/Edge（Windows/Linux/Android）、macOS Safari 18+。iOS Safari 支持有限。缓解措施：接口层需处理 PRF 不可用的情况，返回明确错误；前端在调用前检测浏览器支持度。

**[web-sys 对 WebAuthn 的绑定不完整]** → `web-sys` 的 WebAuthn 类型绑定可能不包含 PRF 扩展等较新字段。缓解措施：PRF 扩展参数通过 `js_sys::Object` + `js_sys::Reflect` 动态构造，不依赖 web-sys 的强类型绑定。

**[WASM 二进制体积]** → 引入 `k256`、`bip32`、`tiny-bip39`（含词表）、`web-sys` 等依赖可能导致 WASM 二进制较大。缓措施：第一阶段不优化体积；后续可通过 `wasm-opt -Oz`、feature flag 裁剪词表、tree shaking 等手段缩减。

**[单一 WASM 线程模型]** → WASM 默认单线程运行，密码学计算（如 scrypt KDF）可能阻塞 UI。缓解措施：第一阶段接受同步阻塞；后续可使用 Web Worker 隔离计算密集型操作。

## 已确认事项

### 1. tiny-bip39 2.0 WASM 兼容性 — ✅ 已确认可用

`tiny-bip39` 2.0.0 明确支持 WASM 环境：
- `Cargo.toml` 中直接依赖 `wasm-bindgen`，dev-dependencies 中包含 `wasm-bindgen-test`
- 作为纯 Rust 实现，可直接编译到 `wasm32-unknown-unknown`
- 与项目当前 nightly 工具链兼容（无 nightly-only feature 依赖）

### 2. web-sys WebAuthn 类型覆盖度 — ✅ 核心类型已覆盖，PRF 需手动构造

`web-sys` 基于浏览器 WebIDL 自动生成绑定，已包含 WebAuthn 核心类型：
- `PublicKeyCredential`、`PublicKeyCredentialCreationOptions`、`PublicKeyCredentialRequestOptions`
- `AuthenticatorAttestationResponse`、`AuthenticatorAssertionResponse`
- `CredentialsContainer`、`Credential`

**使用方式**：每个类型需通过同名 feature flag 显式启用，例如：
```toml
web-sys = { version = "0.3", features = [
    "PublicKeyCredential",
    "PublicKeyCredentialCreationOptions",
    "PublicKeyCredentialRequestOptions",
    "AuthenticatorAttestationResponse",
    "AuthenticatorAssertionResponse",
    "CredentialsContainer",
    "Credential",
    "Navigator",
    "Window",
] }
```

**PRF 扩展**：`web-sys` 的强类型绑定**不包含** PRF 扩展的 `extensions` 输入/输出字段（PRF 是较新的 W3C 规范扩展）。需通过 `js_sys::Object` + `js_sys::Reflect` 动态构造 PRF 参数和读取 PRF 结果，这在决策 4 中已确定。

### 3. PRF 扩展输出格式 — ✅ 已确认

根据 W3C WebAuthn 规范和 Yubico 开发者文档确认：

**注册阶段**（`create()`）：
```javascript
getClientExtensionResults().prf
// → { enabled: true }      // 设备支持 PRF
// → { enabled: false }     // 设备不支持 PRF
```

**认证阶段**（`get()`）：
```javascript
getClientExtensionResults().prf.results.first
// → ArrayBuffer (32 字节)   // PRF 输出
```

- **数据类型**：`ArrayBuffer`
- **长度**：标准输出为 **32 字节**（256 位），由 CTAP2 hmac-secret 扩展产生
- **确定性**：相同的 credential + rpId + salt 组合始终产生相同输出
- **最佳实践**：原始 32 字节输出应作为 IKM（Input Keying Material），推荐通过 HKDF 派生最终加密密钥，而非直接使用

### 4. Cargo workspace 兼容性 — ⚠️ 有约束，需注意

**结论**：可以共存，但需遵循以下规则：

- `cargo check --target wasm32-unknown-unknown -p web-core` **可以正常工作**，仅编译 web-core 及其依赖，不影响其他 crate
- **不能**在 workspace 根目录执行不带 `-p` 的 `cargo check` 或 `cargo build`，因为 Cargo 会尝试用同一 target 编译所有 workspace member，导致 `wasm-bindgen` 等 web-core 依赖在 native target 下报错
- **推荐做法**：
  1. 始终使用 `-p` 指定包名：`cargo check -p web-core --target wasm32-unknown-unknown`
  2. 原有 `cargo check`（无 `--target`）仅编译 native crate，web-core 中 `wasm-bindgen` 等依赖会产生 warning 但不会导致 token-core/imkey-core 编译失败
  3. 可使用 Makefile 或 `cargo-make` 定义分离的构建命令
  4. `resolver = "2"` 已配置，feature 解析不会跨 target 污染

### 5. k256 ECDSA 可恢复签名 API — ✅ 已确认支持

k256 v0.13.x 提供完整的可恢复签名能力：

**签名 API**：
```rust
use k256::ecdsa::{SigningKey, Signature, RecoveryId};
use sha2::Sha256;  // 或 sha3::Keccak256

let signing_key = SigningKey::from_bytes(&private_key_bytes)?;
let (signature, recid) = signing_key.sign_digest_recoverable(digest)?;
// signature: Signature (64 字节, r + s)
// recid: RecoveryId (值为 0 或 1)
```

**公钥恢复 API**：
```rust
use k256::ecdsa::VerifyingKey;

let recovered_key = VerifyingKey::recover_from_digest(digest, &signature, recid)?;
```

**与 secp256k1 crate 的对应关系**：
| 概念 | `secp256k1` crate | `k256` crate |
|------|-------------------|--------------|
| 私钥 | `SecretKey` | `SigningKey` |
| 公钥 | `PublicKey` | `VerifyingKey` |
| 签名 | `Signature` | `Signature` |
| 恢复 ID | `RecoveryId::from_i32(v)` | `RecoveryId::try_from(v as u8)` |
| 可恢复签名 | `sign_ecdsa_recoverable()` | `sign_digest_recoverable(digest)` |
| 公钥恢复 | `recover_ecdsa()` | `VerifyingKey::recover_from_digest()` |

**注意**：k256 的 `sign_digest_recoverable` 需要传入 `Digest` 对象（而非预计算的 hash 字节）。如果已有 32 字节 hash，需使用 `hazmat::SignPrimitive` trait 的 `try_sign_prehashed` 方法。BIP-137 场景下（已有双 SHA256 hash），应使用 prehash 签名路径。
