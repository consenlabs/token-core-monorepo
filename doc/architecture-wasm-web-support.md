# TokenCore WebAssembly 架构文档

## 背景

TokenCore 最初作为移动端（iOS / Android）的跨链密钥管理与交易签名库，通过 Rust → C FFI 编译为原生库供移动应用调用。`feat/keyless` 分支的目标是将同一套核心代码编译为 WebAssembly，使其能够在浏览器环境中运行，支持 Web 端钱包场景（如 Passkey 无密码钱包）。

本文档描述为实现这一目标所做的架构变更。

---

## 架构总览

### 变更前

```
┌─────────────────────────────────────────────────────┐
│                  Mobile Applications                │
│                 (iOS / Android)                      │
└──────────────────────┬──────────────────────────────┘
                       │ C FFI (protobuf)
┌──────────────────────▼──────────────────────────────┐
│  tcx (FFI handler)                                  │
│  ├── tcx-keystore  (HD / PrivateKey keystore)       │
│  ├── tcx-crypto    (AES-128, PBKDF2, scrypt)        │
│  ├── tcx-primitive (secp256k1, ed25519, sr25519,    │
│  │                  bls12-381, bip32, bip39)         │
│  ├── tcx-eth / tcx-tron / tcx-btc-kin / ...         │
│  └── tcx-substrate / tcx-ton / ...                  │
└─────────────────────────────────────────────────────┘
```

### 变更后

```
┌──────────────────────┐       ┌──────────────────────┐
│  Mobile Applications │       │   Web Applications   │
│  (iOS / Android)     │       │   (Browser)          │
└──────────┬───────────┘       └──────────┬───────────┘
           │ C FFI (protobuf)             │ wasm-bindgen (JSON)
┌──────────▼───────────┐       ┌──────────▼───────────┐
│  tcx (FFI handler)   │       │  tcx-wasm            │
│  全量链支持          │       │  ETH + TRON          │
│  password-based      │       │  passkey PRF-based   │
└──────────┬───────────┘       └──────────┬───────────┘
           │                              │
┌──────────▼──────────────────────────────▼───────────┐
│  共享核心层                                         │
│  ├── tcx-keystore  (feature: substrate-crypto)      │
│  ├── tcx-crypto    (新增 AES-256-CTR)               │
│  ├── tcx-primitive (feature: substrate-crypto)      │
│  ├── tcx-eth / tcx-tron                             │
│  └── tcx-constants / tcx-common                     │
└─────────────────────────────────────────────────────┘
```

新增的 `tcx-wasm` crate 是面向 Web 端的入口层，与移动端的 `tcx` crate 并列。两者共享底层核心 crate，但通过 feature flag 和条件编译适配各自的目标平台。

---

## 核心变更

### 1. 新增 `tcx-wasm` Crate

**路径**: `token-core/tcx-wasm/`

作为 Web 端的入口模块，通过 `wasm-bindgen` 暴露以下 API：

| 函数 | 功能 |
|------|------|
| `create_keystore(param_json)` | 创建 Passkey Keystore（支持导入助记词或由 entropy 生成新助记词） |
| `derive_accounts(param_json)` | 从 keystore 批量派生区块链账户（地址、公钥、扩展公钥），一次解锁派生多个账户 |
| `sign_tx(param_json)` | 交易签名（ETH Legacy/EIP-1559, TRON） |
| `cache_keystore(json)` | 缓存 keystore JSON 到 thread-local storage |
| `clear_cached_keystore()` | 清除缓存的 keystore |

**依赖关系**：

```
tcx-wasm
├── tcx-keystore  (default-features = false)
├── tcx-primitive (default-features = false)
├── tcx-eth       (default-features = false)
├── tcx-tron      (default-features = false)
├── tcx-crypto
├── tcx-constants
├── tcx-common
├── wasm-bindgen
├── js-sys
└── getrandom    (features = ["js"])
```

关键设计决策：
- **JSON-in / JSON-out 接口**：所有参数和返回值均为 JSON 字符串，通过 `serde_json` 在 Rust 侧序列化/反序列化。选择 JSON 而非 protobuf 是因为 Web 端使用 JSON 更自然，且避免引入 protobuf WASM 依赖。
- **`default-features = false`**：禁用 `substrate-crypto` feature，排除 BLS / SR25519 / sp-core 等无法编译到 WASM 的依赖。
- **`getrandom` + `js` feature**：在 WASM 环境中通过 `crypto.getRandomValues()` 提供随机数源。

### 2. Feature Flag 体系：`substrate-crypto`

为解决 `blst`、`sp-core`、`schnorrkel` 等原生 C 依赖无法编译到 `wasm32-unknown-unknown` 的问题，引入了条件编译机制。

**`tcx-primitive`**:

```toml
[features]
default = ["substrate-crypto"]
substrate-crypto = ["dep:blst", "dep:sp-core", "dep:schnorrkel"]
```

当 `substrate-crypto` 被禁用时，通过 `#[path]` 属性加载 stub 实现：

```rust
#[cfg(feature = "substrate-crypto")]
mod bls;
#[cfg(not(feature = "substrate-crypto"))]
#[path = "bls_stub.rs"]
mod bls;
```

Stub 文件实现了相同的 trait 接口，但所有方法返回错误，确保类型系统满足而不引入不可编译的依赖。涉及的 stub 文件：

| 文件 | 替代 | 说明 |
|------|------|------|
| `bls_stub.rs` | `bls.rs` | BLS12-381 签名（Filecoin/ETH2） |
| `ed25519_stub.rs` | `ed25519.rs` | Ed25519 签名（保留基本类型定义，WASM 下不可签名） |
| `sr25519_stub.rs` | `sr25519.rs` | SR25519 签名（Substrate 生态） |

**级联传播**：`tcx-keystore`、`tcx-eth`、`tcx-tron` 也新增了同名 feature，向上透传：

```toml
# tcx-eth/Cargo.toml
[features]
default = ["substrate-crypto"]
substrate-crypto = ["tcx-keystore/substrate-crypto", "tcx-primitive/substrate-crypto"]
```

### 3. Passkey Keystore 格式

Web 端采用新的 keystore 格式 `PasskeyKeystore`，与移动端的 `Store` 格式不同：

```rust
pub struct PasskeyKeystore {
    pub user_id: String,          // WebAuthn user ID
    pub credential_id: String,    // WebAuthn credential ID
    pub rp_id: String,            // Relying Party ID
    pub encrypted_mnemonic: String, // AES-256-CTR 加密的助记词
    pub mnemonic_iv: String,      // 加密 IV
    pub created_at: i64,          // 创建时间戳
    pub identity: Identity,       // 复用现有 Identity 结构
}
```

与移动端 keystore 的主要区别：

| 特性 | 移动端 (Store) | Web 端 (PasskeyKeystore) |
|------|---------------|------------------------|
| 密钥保护 | 密码 → PBKDF2/scrypt → AES-128-CTR | Passkey PRF → AES-256-CTR |
| 加密对象 | 完整 keystore (crypto 字段) | 仅助记词 |
| 身份绑定 | 设备文件系统 | WebAuthn credential |
| 解锁方式 | password / derived_key | PRF key (32字节) |

### 4. 新增 AES-256-CTR 加密

**路径**: `token-core/tcx-crypto/src/aes.rs`

新增 `ctr256` 模块，使用 AES-256 密钥（32 字节）配合 CTR 模式加密。原有的 `ctr` 模块为 AES-128。

这是 Passkey PRF 场景所需的：WebAuthn PRF 扩展直接产出 32 字节密钥，无需再经过 KDF 派生，因此使用 AES-256-CTR 直接加密助记词。

### 5. `from_mnemonic_unlocked` 方法

**路径**: `token-core/tcx-keystore/src/keystore/hd.rs`

新增 `HdKeystore::from_mnemonic_unlocked` 方法，创建一个不经过密码加密、直接处于解锁状态的 `HdKeystore`。这在 WASM 场景下是必要的：

- 每次操作（派生地址、签名）时，前端传入 PRF key → 解密助记词 → 构建临时 unlocked keystore → 执行操作 → 销毁
- 不需要完整的 `Crypto`（PBKDF2/scrypt）流程，因为密钥保护由 Passkey PRF 在浏览器层完成

同步新增 `Identity::from_seed_with_raw_key`，允许直接传入原始密钥（而非 `Unlocker`）来创建 Identity。

### 6. WASM 平台兼容性修复

**`metadata_default_time`** 条件编译：

```rust
#[cfg(not(target_arch = "wasm32"))]
fn metadata_default_time() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH)...
}

#[cfg(target_arch = "wasm32")]
fn metadata_default_time() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}
```

WASM 环境不支持 `std::time::SystemTime`，改用 `js_sys::Date::now()`。

**`let-else` 语法调整** (`tcx-btc-kin/src/signer.rs`, `tcx/src/handler.rs`, `tcx/src/migration.rs`)：
将 `if let ... && ...` 合并表达式拆分为嵌套 `if`，兼容新版 nightly 编译器的语法要求。

### 7. 工具链升级

```toml
# rust-toolchain.toml
[toolchain]
channel = "nightly-2026-04-06"   # 从 nightly-2023-06-15 升级
```

升级原因：旧版 nightly 的 WASM target 支持不完整，新版修复了多个 wasm32 编译问题。

---

## 构建与发布

### Makefile 新增目标

| 命令 | 功能 |
|------|------|
| `make build-wasm` | 编译 WASM（debug profile），输出到 `examples/wasm/src/pkg/` |
| `make build-wasm-opt` | 编译优化 WASM（LTO + `Oz` + wasm-opt），最小化体积 |
| `make dev-wasm` | 编译 + 启动 Next.js 开发服务器 |
| `make build-npm` | 构建 NPM 发布包到 `publish/npm/` |
| `make publish-npm` | 发布到 npmjs.com（`@consenlabs/tcx-wasm`） |

构建依赖：
- `wasm-pack` — Rust → WASM 编译与 JS binding 生成
- `llvm` (via Homebrew) — 提供兼容的 `clang` / `llvm-ar`，解决某些 C 依赖的交叉编译
- `wasm-opt` (可选) — binaryen 的 WASM 优化器，进一步压缩产物体积

### NPM 包结构

```
publish/npm/
├── package.json           # @consenlabs/tcx-wasm
├── README.md              # 使用文档
├── tcx_wasm_bg.wasm       # WASM 二进制（构建时生成）
├── tcx_wasm.js            # JS glue code（构建时生成）
├── tcx_wasm.d.ts          # TypeScript 类型定义（构建时生成）
└── tcx_wasm_bg.wasm.d.ts  # WASM 类型定义（构建时生成）
```

### 示例应用

```
examples/wasm/                # Next.js 16 + Turbopack
├── src/
│   ├── app/page.tsx          # 集成测试页面
│   └── lib/wasm.ts           # WASM 加载封装
└── public/
    └── tcx_wasm_bg.wasm      # WASM 二进制（构建时拷贝）
```

示例应用包含完整的集成测试用例：
1. Keystore 创建（导入助记词 / 新生成）
2. ETH / TRON 账户派生
3. ETH Legacy TX / EIP-1559 TX / TRON TX 签名
4. Keystore 缓存机制验证

---

## 安全考量

1. **助记词内存驻留最小化**：每次操作解密助记词 → 构建临时 keystore → 操作完成后 `keystore.lock()` 清除内存中的明文。
2. **PRF key 不存储**：PRF key 由 WebAuthn PRF 扩展在用户认证时实时派生，不在 JS 侧持久化。Keystore JSON 中仅存储加密后的助记词。
3. **Stub 实现安全**：禁用 substrate-crypto 后的 stub 实现不会静默返回错误结果，而是显式返回 `Error`，确保不会在不支持的曲线上意外执行签名。
4. **WASM 沙箱隔离**：WASM 运行在浏览器沙箱中，无法访问文件系统和网络，密钥材料仅存在于 WASM 线性内存中。

---

## 未来扩展方向

- 增加更多链的 WASM 支持（BTC、TON 等），需评估各链 crate 的 WASM 兼容性
- 考虑 `wasm-bindgen` 的 `web-sys` 直接集成 WebAuthn API
- 探索 WASM SIMD 优化加密运算性能
- 支持 WebAuthn Large Blob 扩展，将加密 keystore 存储在认证器中
