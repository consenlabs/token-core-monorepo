# Phase 7 安全 Review 问题整改说明

本文用于回复 `consenlabs/infrastructure#461` 中提出的非阻塞安全 Review 问题，包括评论 `4987733923` 中提到的改进项。

本次整改保持现有 Protobuf 接口和 C ABI 函数签名不变。历史有效地址、签名、keystore 和交易序列化结果继续由兼容性测试覆盖。对于非法输入或可能造成资源耗尽的输入，现在会返回明确错误，不再发生 panic、整数回绕、内存泄漏或无上限资源消耗。

## 整改结果汇总

| 问题 | 状态 | 主要改进 |
| --- | --- | --- |
| PH7-SR-001 BCH 金额计算安全 | 已修复 | 对 UTXO 汇总和 `amount + fee` 使用检查运算；在访问设备前拒绝余额不足交易。 |
| PH7-SR-002 BCH panic 路径 | 已修复 | 校验目标地址、找零地址和 APDU 签名响应，不再使用 `unwrap` 或不安全切片。 |
| PH7-SR-003 TokenCoreX C ABI 非法输入 | 已修复 | 在 panic 边界内处理空指针、UTF-8、hex、Protobuf 和参数校验，并返回稳定错误。 |
| PH7-SR-004 TokenCoreX 字符串所有权 | 已修复 | `free_const_string` 现在会真正释放 Rust `CString`；Android、iOS、测试和工具调用点均改为每个返回指针只释放一次。 |
| PH7-SR-005 imKey APDU callback 所有权 | 已修复 | callback 请求为借用指针；响应在串行保护下复制；移动端响应存储改为有界、明确所有权。 |
| PH7-SR-006 多输入 Taproot PSBT | 已修复 | 按每个输入独立选择签名路径，并将脚本路径签名写入 BIP371 `tap_script_sigs`。 |
| NEW-01 Passkey/WASM 认证加密 | 代码已完成，仍需协同发布 | 新 keystore 使用 ChaCha20-Poly1305 和认证元数据；旧 AES-CTR 仅用于显式迁移。 |
| PH7-SR-007 外部 KDF 参数 | 已修复 | 在执行 KDF 前校验算法、salt、dklen、计算成本上限和资源计算结果。 |
| COMPAT-01 未压缩公钥 P2PKH | 已修复 | P2PKH 哈希保留原始公钥序列化形式；SegWit 仍保持压缩公钥要求。 |

## 详细整改说明

### 1. PH7-SR-001：BCH 金额下溢和溢出

#### 问题原因

原找零金额使用普通无符号整数减法，UTXO 金额汇总也没有使用检查加法。当交易余额不足，或者构造出的 UTXO 总额超过 `u64::MAX` 时，debug 构建可能 panic，release 构建则可能发生整数回绕。另外，相关校验发生在与设备通信之后，非法交易仍可能触发不必要的 APDU 调用。

#### 改进方式

- 使用 `checked_add` 汇总 UTXO 金额。
- 使用 `checked_add` 计算 `amount + fee`，使用 `checked_sub` 计算找零。
- 算术溢出返回 `invalid_number`。
- 余额不足返回 `imkey_insufficient_funds`。
- 在发送任何 APDU 前完成金额和目标输出校验。
- 保留原有零找零和 dust 找零处理逻辑。

#### 兼容性说明

有效交易的金额和输出结果不变。只有原来可能发生溢出、下溢或实际余额不足的输入会被拒绝。

### 2. PH7-SR-002：BCH 地址和签名响应 panic 路径

#### 问题原因

调用方提供的地址和设备返回值会进入未检查的解析、切片和 `unwrap` 路径。特别是设备返回空、过短、非十六进制或长度不正确的签名数据时，代码可能 panic，而不是返回钱包业务错误。

#### 改进方式

- 在构造输出前校验转账目标地址。
- 找零地址继续同时支持 CashAddr 和 legacy Base58 BCH 地址。
- 读取 APDU payload 前检查状态码和响应边界。
- 要求设备签名 payload 必须恰好是一份 64 字节 compact signature。
- 明确拒绝空响应、短响应、非十六进制响应和带多余数据的响应。
- 将签名和输入索引不一致转换为 `InvalidUtxo` 或 `MissingSignature` 错误。
- 移除交易组装路径中不必要的 `unwrap`。

#### 兼容性说明

新增 legacy BCH 找零地址回归测试。有效 compact signature 和历史地址格式继续正常工作。

### 3. PH7-SR-003：TokenCoreX C ABI 非法输入

#### 问题原因

原 C ABI 入口在进入 panic 捕获边界前就开始解析输入，同时对 Protobuf 参数使用 `unwrap`。空指针、非法 UTF-8、非法 hex、错误 Protobuf 或缺少参数都可能导致调用进程异常终止。

#### 改进方式

- 将指针、UTF-8、hex、Protobuf 解析和 action 分发全部移入 `landingpad`。
- 移除 Protobuf 参数的无条件 `unwrap`，仅在具体 method 确实需要参数时取值。
- 非法输入返回稳定的 `invalid_tcx_param:*` 错误。
- 未支持的方法返回 `unsupported_method`。
- 未预期 panic 统一转换为 `internal_error`，不向 API 调用方暴露内部实现细节。
- 保留 API 失败时返回空字符串的原有约定。
- 每次 API 调用前清理线程本地错误，避免读取上一次调用的错误状态。

#### 兼容性说明

导出函数签名和合法 Protobuf 请求的分发行为不变。本次改动只让非法请求得到确定且不会 panic 的结果。

### 4. PH7-SR-004：TokenCoreX 返回字符串所有权

#### 问题原因

原 `free_const_string` 没有通过 `CString::from_raw` 重新接管并释放 `CString::into_raw` 创建的内存，因此 API 的响应和错误字符串都会泄漏。部分跨语言桥接还直接把返回值映射为语言层 `String`，导致丢失用于释放 Rust 内存的原始指针。

#### 改进方式

- 使用 `CString::from_raw` 实现空指针安全的真正释放。
- 明确文档约定：每个非空 Rust-owned 返回指针必须且只能释放一次。
- Rust 测试辅助代码和 `tcx-tester` 改为先复制字符串，再释放响应和错误指针。
- Android/JNA 桥接改为接收 `Pointer`，复制 UTF-8 字符串，并在 `finally` 中释放响应和错误指针。
- iOS 桥接复制返回字符串后，通过就近 `defer` 分别释放 Rust 指针。
- 初始化接口丢弃返回值的调用点也补充释放逻辑。

#### 兼容性说明

C ABI 没有变化。本次改动只是落实原导出 free 函数所隐含的所有权约定，并消除已知调用方的内存泄漏。

### 5. PH7-SR-005：imKey APDU callback 所有权和生命周期

#### 问题原因

callback 的 APDU 请求指针来自 Rust 临时存储，只在 callback 调用期间有效，但部分移动端代码错误地尝试释放该指针。另一方面，callback 响应指针缺少清晰的生命周期约定：iOS 每次响应都可能产生无法回收的分配，Rust 还可能在另一次调用替换响应存储时读取旧指针。

普通 imKey API 返回值也存在类似问题：Android JNA 将 Rust 指针直接映射为 `String` 后再尝试释放，无法保证释放的是原始 Rust 分配；Android 和 iOS 初始化调用还会直接丢弃 Rust-owned 返回指针。

#### 改进方式

- 将 APDU 请求指针定义为 callback 调用期间的借用指针，删除 Android 调用方对该指针的错误释放。
- 未注册 callback 时返回明确错误，不再静默使用会产生泄漏的默认实现。
- callback 调用和响应复制保持串行，确保 Rust 复制完成前移动端不会替换响应存储。
- 空响应和通信错误转换为明确的 transport error。
- 默认 callback 使用静态响应，不再每次调用分配字符串。
- iOS 使用锁保护一份可复用响应指针；替换前释放旧分配，并保证响应在下一次串行 callback 前持续有效。
- Android 普通 imKey API 返回值改为 JNA `Pointer`，复制后在 `finally` 中分别释放响应和错误指针。
- Android 和 iOS 初始化调用均释放不再使用的 Rust-owned 返回指针。

#### 兼容性说明

callback 函数签名和 APDU 字符串格式不变。新增 100,000 次 host-side callback 回归测试，用于验证请求借用、响应复制和重复调用不会产生逐次 Rust 分配泄漏。

### 6. PH7-SR-006：多输入 Taproot PSBT 路径选择

#### 问题原因

原 Taproot 签名逻辑根据 PSBT 的第一个输入推断签名类型。在同时包含 key-path 和 script-path 的多输入 PSBT 中，后续输入可能错误复用第一个输入的路径。脚本路径签名还可能被当作 key-path 数据处理，而不是按照 BIP371 使用 `(xonly, leaf_hash)` 作为脚本签名 key。

#### 改进方式

- 根据当前输入和当前 prevout，为每个输入独立选择 key path 或 script path。
- 通过当前输入的 `tap_key_origins` 解析脚本叶子。
- 找不到叶子或存在多个无法确定的叶子时返回明确错误。
- 验证 control block 与当前输入 prevout 的 Taproot commitment 是否一致。
- script-path sighash 包含 leaf hash、key version 和 code-separator position。
- 将脚本路径签名写入 `tap_script_sigs[(xonly, leaf_hash)]`。
- key-path 输入独立执行自动 finalize。
- script-path 仅对明确支持的 `<xonly> OP_CHECKSIG` 脚本自动 finalize。
- 对复杂脚本保留 BIP371 字段，由标准外部 finalizer 处理。
- 只有真正生成 final witness 后才清理 Taproot 元数据。

#### 兼容性说明

单输入 key-path 行为保持不变。新增 host-side 测试覆盖：

- 同一 PSBT 中混合 key-path 和 script-path 输入。
- 每个输入独立选择签名路径。
- BIP371 key origin 选择。
- 缺少公钥。
- 多叶子歧义。

### 7. NEW-01：Passkey/WASM keystore 认证加密

#### 问题原因

原 Passkey keystore 使用不带认证的 AES-CTR。密文或 IV 被修改时，算法本身无法检测篡改；用户、credential、RP、网络和 identity 等关键元数据也没有与加密助记词进行密码学绑定。

#### 改进方式

- 引入版本化 v2 格式，使用 ChaCha20-Poly1305。
- 使用随机 96-bit nonce。
- 使用完整 32 字节 WebAuthn PRF 输出作为加密密钥。
- 将 version、cipher、user ID、credential ID、RP ID、创建时间、network 和 identity identifier 作为 associated data 认证。
- 在派生账户、导出或签名前，使用解密出的助记词重建 keystore，并校验 identity identifier。
- AES-CTR 只保留在显式 legacy migration 路径中，不再用于新写入。
- 新增 `migrate_keystore` API。
- v2 数据重复迁移保持幂等，迁移时保留未知的顶层 JSON 字段。
- alpha Passkey 钱包仅在本地 WebAuthn/PRF 认证成功后执行迁移。
- 写回前校验派生出的 ETH/TRON 地址。
- 所有检查通过后，才写回 local、remote 或 LargeBlob 存储。
- LargeBlob 存储完整的认证 v2 JSON，不再简单拼接 ciphertext 和 IV。
- WASM metadata 使用 JavaScript 时间，避免浏览器/Node WASM 环境不支持 `SystemTime::now` 的运行时问题。

#### 兼容性和发布要求

旧 v1 数据仍可在用户完成认证后执行迁移；所有新写入使用 v2。

token-core 和 alpha 的代码实现已经准备完成，但需要按以下顺序发布：

1. 发布包含 v2 和迁移 API 的新版本 `tcx-wasm` npm 包。
2. 将 alpha 的依赖和 lockfile 更新到已发布的新版本。
3. 执行 alpha 浏览器集成测试，再部署迁移流程。

不能继续复用已经发布的 `0.7.0` 版本号，否则 alpha 即使重新安装依赖，得到的仍然是旧实现。因此当前改动没有把 alpha 指向一个尚未发布、无法安装的版本。

### 8. PH7-SR-007：外部 KDF 参数缺少上限

#### 问题原因

导入 keystore 时，外部提供的 PBKDF2、Argon2id 或 scrypt 参数没有经过充分的结构和上限校验就传递给底层算法。恶意参数可能导致整数计算错误、过量 CPU/内存消耗，或者触发底层 crate panic。

#### 改进方式

- salt 必须是有效 hex，解码后长度限制为 16 到 64 字节。
- 只接受支持的 derived-key 长度。
- PBKDF2 仅允许 HMAC-SHA256，轮数上限为 10,000,000。
- Argon2id 内存上限为 256 MiB，time cost 上限为 10，parallelism 上限为 16。
- Argon2id 同时校验算法要求的每 lane 最小内存。
- scrypt 的 `N` 必须是 2 的幂。
- 限制 scrypt 的 `r`、`p`、估算内存和总工作因子。
- scrypt 估算内存上限为 512 MiB。
- 所有资源计算使用 checked arithmetic。
- KDF 派生和 MAC 计算改为可失败操作。
- 非法 salt、IV、ciphertext 或 derived-key 长度返回错误，不再 panic。
- verify 接口遇到错误格式时返回 `false`。
- 测试环境中的非法 `KDF_ROUNDS` 值不再突破限制，而是回退到配置值或默认值。

#### 兼容性说明

现有固定向量、有效历史 keystore 和原有 64 字节 credential 行为继续由测试覆盖。只有不支持或可能造成资源耗尽的参数会被拒绝。

### 9. COMPAT-01：未压缩公钥 P2PKH 语义

#### 问题原因

共享 Bitcoin 地址辅助函数在计算地址前把所有公钥统一转换为压缩格式。SegWit 要求压缩公钥，但 legacy P2PKH 地址必须对原始公钥序列化结果进行哈希。对未压缩公钥强制压缩会改变历史 P2PKH 地址，并可能破坏未压缩 WIF 账户的兼容性。

#### 改进方式

- 将输入解析为 Bitcoin public key。
- P2PKH 计算保留输入原有的压缩或未压缩序列化形式。
- SegWit helper 继续强制使用压缩公钥。
- 新增回归测试，证明同一密钥的压缩和未压缩 P2PKH 地址不同。
- 同时验证 SegWit 输出仍保持压缩规范化。
- 保留现有未压缩 WIF 端到端签名回归测试。

#### 兼容性说明

压缩公钥地址输出不变。未压缩 legacy 账户恢复正确的历史 P2PKH 语义。

## 已完成的验证

以下检查已在 `token-core-monorepo` 中通过：

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- --deny warnings
cargo test --workspace --no-run
make test-tcx
make test-ikc
make test-wasm
wasm-pack test --node（tcx-wasm 浏览器侧测试：2 passed）
git diff --check
```

以下聚焦 host-safe 回归测试也已通过：

- BCH 金额检查、地址兼容和 APDU 响应校验。
- TokenCoreX 非法 FFI 输入和 panic 错误收敛。
- APDU callback 所有权和重复调用。
- 多输入 Taproot PSBT。
- KDF 资源上限和恶意参数。
- Passkey AEAD 篡改检测和 legacy migration。
- 未压缩公钥 P2PKH 地址派生。

alpha 项目已通过 wallet-core 测试、wallet-core/web 类型检查、聚焦 formatter 检查和补丁空白检查。

## 仍需完成的外部验证

### 1. imKey 物理设备测试

需要连接真实 imKey 后执行：

```text
make test-hardware
```

此前使用较宽的 Taproot 测试过滤条件时，命中了三个现有硬件测试。这三个测试仅因为没有连接 imKey 设备而失败；新增的 host-safe Taproot 回归测试均已通过。

### 2. token-v2 Android/iOS 原生构建

token-v2 的 Android/iOS 跨语言所有权修改已经完成源代码检查和 `git diff --check`，但本工作区没有执行完整移动端应用构建。仍需在原生构建环境中完成编译和设备调用验证。

### 3. `tcx-wasm` 与 alpha 协同发布

需要先发布新的 `tcx-wasm` npm 版本，再更新 alpha 的依赖版本和 lockfile，最后执行浏览器集成测试。

以上三项属于设备环境、原生构建环境和发布顺序要求，不是尚未修复的代码问题。
