## 背景

`token-core-monorepo` 是 imToken 钱包使用的 Rust 原生加密签名库。它通过 C ABI（`call_tcx_api`）暴露接口，前端通过 protobuf 编码的消息进行调用。BTC 消息签名当前在 `tcx-btc-kin/src/message.rs` 中实现，对所有地址类型统一使用 BIP-322 流程，输出为 hex 编码。签名派发通过 `Keystore` 上的 `MessageSigner` trait 实现，经 `sign_msg` API 方法路由。

imKey 硬件钱包路径在 `imkey-core/ikc-wallet/coin-bitcoin/src/message.rs` 中有并行实现，同样对所有类型使用 BIP-322。

关键约束：
- 项目使用 `nightly-2023-06-15` Rust 工具链
- `bitcoin` crate 版本为 0.29.x（使用 `PackedLockTime`、`Script`，非新版 0.30+ API）
- PSBT 签名由 `tcx-btc-kin/src/psbt.rs` 中的 `PsbtSigner` 处理，已支持 P2PKH、P2SH-P2WPKH、P2WPKH 和 P2TR
- `Keystore` 上已有 `secp256k1_ecdsa_sign_recoverable` 方法，返回 `[u8; 65]`（recovery_id 在索引 64 处）

## 目标 / 非目标

**目标：**
- 为 Legacy 和 Nested SegWit 地址实现 BIP-137 签名（Standard + BIP-137）
- 将 Native SegWit 的 BIP-322 Simple 输出从 hex 改为 Base64
- 为 Taproot 实现 BIP-322 Full 格式（返回序列化的 `to_sign` 交易）
- 扩展 `BtcMessageInput` protobuf，新增 `signatureType` 枚举
- 验证格式与地址类型兼容性，不兼容时返回明确错误
- 在 imKey 硬件钱包路径中应用等效修改

**非目标：**
- BIP-322 资金证明（Proof of Funds，多 UTXO）不在范围内
- ETH 的 EIP-712 typed data 签名（ETH EIP-191 已完成）
- 非 BTC/ETH 链的消息签名
- BTC 消息签名的验证/恢复功能（仅实现签名）
- UI/前端修改（仅涉及 Rust 原生层）

## 技术决策

### 决策 1：基于 `signatureType` 字段派发，而非仅根据地址类型

**选择**：在 `BtcMessageInput` 中新增 `BtcSignatureType` 枚举，签名逻辑基于该字段与 `seg_wit` 的组合进行派发。

**理由**：不同地址类型可支持多种格式（如 Nested SegWit 支持 Standard、BIP-137 和 BIP-322）。让调用方指定格式提供了最大灵活性，也符合业界主流钱包的用户体验模式。

**否决的方案**：仅根据地址类型自动选择格式。否决原因：移除了用户选择权，不符合产品对格式选择的需求。

### 决策 2：将 `sign_message` 重构为格式专属函数

**选择**：将当前单体 `sign_message` 实现拆分为：
- `sign_message_bip137(seg_wit, message, keystore, params) → Base64`
- `sign_message_bip322_simple(message, keystore, params) → Base64`
- `sign_message_bip322_full(message, keystore, params) → Base64`

`MessageSigner` trait 实现变为派发器，负责验证兼容性并委派给对应函数。

**理由**：清晰的职责分离。BIP-137 和 BIP-322 的签名流程完全不同 — 混在一个函数中会造成混乱。

### 决策 3：BIP-137 复用已有的 `secp256k1_ecdsa_sign_recoverable`

**选择**：使用已有的 `Keystore::secp256k1_ecdsa_sign_recoverable` 方法，该方法返回 `[u8; 65]`，recovery_id 在字节索引 64。

**理由**：该方法已经实现了所需的 ECDSA 可恢复签名。只需：
1. 用 BIP-137 前缀对消息进行哈希（双 SHA256）
2. 调用 `secp256k1_ecdsa_sign_recoverable` 传入哈希
3. 重排输出为：`[标志字节(1), r(32), s(32)]`，使用对应的标志基数

无需新增加密依赖。

### 决策 4：BIP-322 Full（Taproot）提取并序列化带 witness 的完整交易

**选择**：PSBT 签名和终结（finalize）完成后，通过 `psbt.extract_tx()` 提取完整交易（或手动重建），使用 `bitcoin::consensus::serialize` 序列化，然后 Base64 编码。

**理由**：BIP-322 Full 格式要求以标准网络序列化格式返回完整 `to_sign` 交易。PSBT 终结后已包含完整签名交易。

### 决策 5：使用 `base64` crate 进行编码

**选择**：在 `tcx-btc-kin`（和 `tcx-common` 如果共享）中添加 `base64` 依赖，使用 `base64::engine::general_purpose::STANDARD` 进行编码。

**否决的方案**：手动实现 Base64 编码。否决原因 — `base64` crate 经过充分测试且广泛使用。

### 决策 6：`signatureType` 默认值为 STANDARD（枚举值 0）

**选择**：protobuf 枚举的第一个值（0）为 `STANDARD`，使其成为默认值以保持向后兼容。

**理由**：未设置 `signatureType` 的现有调用方将获得兼容性最广的格式。这是一个安全的默认值，适用于所有传统验证器。

## 风险 / 权衡

**[输出编码的破坏性变更]** → 现有消费 `BtcMessageOutput.signature` 为 hex 格式的调用方会受影响。缓解措施：与前端团队协调更新解析逻辑。proto 字段语义变更应在发布说明中记录。

**[BIP-137 标志字节约定在各钱包间有差异]** → 部分钱包使用略有不同的标志范围。缓解措施：严格遵循 BIP-137 规范（31-34 用于 P2PKH 压缩公钥，35-38 用于 P2SH-P2WPKH）。Standard 格式（始终 31-34）作为最大兼容性的备选方案。

**[imKey 硬件钱包可能不支持 BIP-137 APDU]** → 当前 imKey 固件可能没有专用的 BIP-137 签名命令。缓解措施：检查现有的 `personal_sign` 或通用 ECDSA 签名 APDU 是否可与预计算的 BIP-137 消息哈希配合使用。如不行，imKey 上的 BIP-137 可能需要延后。

**[Taproot 的 BIP-322 Full 增加签名体积]** → Full 格式包含完整交易而非仅 witness，数据量更大。缓解措施：这是 BIP-322 规范和 PRD 的要求。增量约 100-200 字节，可接受。

## 待确认问题

1. Native SegWit（P2WPKH）是否需要支持 BIP-137 格式（标志位 39-42）？PRD 仅提到 BIP-322 Simple，但 BIP-137 技术上为 P2WPKH 定义了标志范围。
2. imKey 固件当前是否支持生成可格式化为 BIP-137 的原始 ECDSA 可恢复签名？需要验证 APDU 能力。
3. BIP-137 签名是否需要支持十六进制消息输入（`0x` 前缀），以匹配现有 `utf8_or_hex_to_bytes` 的行为？
