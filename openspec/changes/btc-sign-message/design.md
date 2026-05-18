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

### 决策 7：imKey BIP-137 / Standard 走单 INS APDU 协议，BIP32 path 嵌入 prepare TLV

**选择**：imKey BTC applet 在 `>=1.6.11` 版本提供消息签名能力时采用**单一 INS（`BTC_MSG_SIGN = 0x51`）+ P2 分阶段**的协议形态，host 端按下述方式打包请求：

```
[Signature TLV: tag=0x00 | len | host_ecdsa_signature(DER)]
[Raw Data TLV:  tag=0x01 | len |
    [PRE_TAG_TXHASH(0xA6) | 0x20 | 32-byte BIP-137 digest]
    [PRE_TAG_PATH(0xA7)   | path_len | BIP32 path bytes]
]
```

- 所有 APDU 共享 `INS=0x51`、`P1=0x00`
- 中间块 `P2=0x00`：applet 仅缓冲数据并立即返回 `SW=9000`
- 最终块 `P2=0x80`：applet 在同一条 APDU 内串行完成 host 签名验证 → 内层 TLV 解析 → 用户屏幕确认 → RFC-6979 ECDSA 签名，并把 66 字节签名结果（`len | R | S | V`）作为响应返回；host 端不再发送独立的 sign APDU
- Host 对 Raw Data TLV 的完整字节（`tag | len | value`）做 ECDSA 签名；applet 用 app pubkey 校验，**hash 与 path 同时受 host 签名保护**

**理由**：
- **关闭 path 替换攻击面**：BTC applet 既有所有交易签名流程都把 BIP32 path 放在 sign APDU CDATA 中单独传，path 不在 host 签名覆盖范围内。在消息签名场景下，设备屏幕只展示通用 "Sign Message" 提示（无金额/地址等上下文可辨别），如果沿用"prepare + sign 双 INS、path 走 sign APDU"的旧式拆分，攻击者可以在两条 APDU 之间替换 path 而不被察觉。把 path 内嵌进 prepare TLV 并纳入 host 签名覆盖，从协议层堵住这条路径
- **消除跨 APDU 状态机**：单 INS 把"用户确认 → 签名输出"绑定在同一条 APDU 的状态转换中，applet 无需在两条独立 INS 之间维护 `confStat` 之类的跨 APDU 状态，host 也无法在 confirm 与 sign 之间插入额外 APDU
- **简化 host SDK**：host 端从"两条 INS 串行 + 两次响应解析"简化为"一条 INS 的分块循环 + 末块响应即签名"

**实现层面要点**：
- 复用既有 `BtcApdu::btc_prepare(0x51, 0x00, &prep_data)`：该 helper 已经按 LC_MAX 切分输出 `P2=0x00 ... 0x00 ... 0x80` 的 APDU 序列
- 旧的 `BtcApdu::btc_msg_sign(path)`（对应历史 INS `0x52`）已移除；INS `0x52` 在适配后保持为未分配值
- 末块 APDU 必须使用 `TIMEOUT_LONG`（120s），因为它在 applet 内部触发用户按键确认
- Applet 的响应已经是裸 `len(1) | R(32) | S(32) | V(1) | SW(2)`，host 端按既有格式解析并继续执行 BIP-62 low-S 归一化与 flag byte 拼装

**否决的方案 A**：沿用 prep + sign 双 INS（INS `0x51` + INS `0x52`，path 走第二条 APDU）。否决原因：path 不受 host 签名保护，存在 path 替换攻击面；并且依赖跨 APDU 状态机，攻击窗口更大。

**否决的方案 B**：把 path 加入 host 签名输入但仍保留双 INS。否决原因：需要 host 与 applet 双方都额外维护"已签名的 path"与"sign APDU 携带的 path"是否一致的校验逻辑，比直接把 path 内嵌进 TLV 复杂，收益相同。

## 风险 / 权衡

**[输出编码的破坏性变更]** → 现有消费 `BtcMessageOutput.signature` 为 hex 格式的调用方会受影响。缓解措施：与前端团队协调更新解析逻辑。proto 字段语义变更应在发布说明中记录。

**[BIP-137 标志字节约定在各钱包间有差异]** → 部分钱包使用略有不同的标志范围。缓解措施：严格遵循 BIP-137 规范（31-34 用于 P2PKH 压缩公钥，35-38 用于 P2SH-P2WPKH）。Standard 格式（始终 31-34）作为最大兼容性的备选方案。

**[imKey 硬件钱包可能不支持 BIP-137 APDU]** → 当前 imKey 固件可能没有专用的 BIP-137 签名命令。**已解决**：BTC applet `>=1.6.11` 已实现单 INS（`BTC_MSG_SIGN = 0x51`）消息签名能力，host 端按"Signature TLV + Raw Data TLV（内含 hash/path 子 TLV）"格式打包；host 在调用前通过 `get_btc_apple_version()` 检查版本，低版本返回 `UpgradeApplet` 错误提示。

**[Taproot 的 BIP-322 Full 增加签名体积]** → Full 格式包含完整交易而非仅 witness，数据量更大。缓解措施：这是 BIP-322 规范和 PRD 的要求。增量约 100-200 字节，可接受。

## 已确认事项

1. **Native SegWit（P2WPKH）需要支持全部三种签名格式**：Standard（标志位 31-34）、BIP-137（标志位 39-42）、BIP-322（Simple）。
2. **imKey BTC applet `>=1.6.11` 已交付消息签名指令**：采用单 INS（`BTC_MSG_SIGN = 0x51`）+ P2 分阶段（`0x00` 暂存 / `0x80` 触发完整流程）协议，BIP32 path 嵌入 prepare TLV 并由 host 签名覆盖；host 端通过 `get_btc_apple_version()` 做版本门控，低于 `1.6.11` 返回 `UpgradeApplet` 错误。
3. **BIP-137 签名支持十六进制消息输入**（`0x` 前缀），与现有 `utf8_or_hex_to_bytes` 行为一致。
4. **签名响应来自最终 P2=0x80 APDU**：host 不再发送独立的 sign APDU；末块响应直接携带 66 字节 `len | R | S | V` 签名结果，host 完成 BIP-62 low-S 归一化与 flag byte 拼装后输出 Base64。
