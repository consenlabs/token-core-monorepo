## 为什么要做

imToken 需要完整支持 Bitcoin Sign Message 功能，覆盖所有 BTC 地址格式（Legacy、Nested SegWit、Native SegWit、Taproot）。

token-core 目前仅支持 BIP-322 Simple 一种签名方式，且对所有地址类型统一使用该流程。为满足完整的消息签名需求，需要进行以下扩展：

1. **新增 Standard（标准）格式**：Bitcoin 最早的经典签名方式，验证器支持最广泛，适用于 Legacy 和 SegWit 地址
2. **新增 BIP-137 格式**：在标准格式基础上增加地址类型标识，支持精确验证，适用于 Legacy 和 SegWit 地址
3. **新增 BIP-322 Full 格式**：返回完整签名交易而非仅 witness 数据，适用于 Taproot 地址，兼容性优于 Simple

此外，当前 BIP-322 Simple 的签名输出为 hex 编码，不符合 BIP-322 规范要求的 Base64 编码，需要统一优化为 Base64 输出，确保签名结果可被主流第三方验证工具直接验证。

imkey-core 目前的现状与 token-core 一致，同样仅支持 BIP-322 Simple，需要与 token-core 并行实现上述扩展。但存在一个额外约束：**imKey 的 Bitcoin Applet 当前没有 message 签名的专用接口**，对于 Standard 和 BIP-137 签名格式的支持，需要同步修改 Bitcoin Applet 固件以提供相应的签名能力。BIP-322 相关的修改（输出格式变更和 Full 格式）可基于现有 PSBT 签名接口实现，无需修改 Applet。

---

## 为什么需要三种签名类型

BTC 生态中消息签名没有像 ETH（EIP-191）那样的统一标准。由于 BTC 地址格式的历史演进（P2PKH → P2SH-P2WPKH → P2WPKH → P2TR），社区逐步发展出三种签名协议，各有其适用场景和生态支持度：

### Standard（标准格式）
- **来源**：Bitcoin 最早的消息签名方式，也称为 Electrum 格式
- **必要性**：这是历史最久、**验证器支持最广泛**的格式。几乎所有 BTC 验证工具和交易所都能识别。无论实际地址类型如何，签名的恢复标志位始终使用 P2PKH 压缩公钥范围（31-34），因此任何支持经典 `Bitcoin Signed Message` 的验证器都能验证
- **适用场景**：需要**最大兼容性**的场景，如交易所 KYC 验证、第三方审计等
- **局限性**：验证器只能恢复出 P2PKH 地址，无法从签名本身区分实际的地址类型

### BIP-137
- **来源**：BIP-137 提案，在标准格式基础上扩展了地址类型标识
- **必要性**：解决了标准格式无法区分地址类型的问题。通过不同的恢复标志位范围（P2PKH: 31-34, P2SH-P2WPKH: 35-38, P2WPKH: 39-42），验证器可以准确恢复出**对应格式的地址**，实现精确验证
- **适用场景**：需要**精确证明特定格式地址所有权**的场景
- **局限性**：不支持 Taproot 地址（BIP-137 规范发布时 Taproot 尚未激活）；部分老旧验证器不识别高范围标志位

### BIP-322
- **来源**：BIP-322 提案，基于比特币虚拟交易的通用签名格式
- **必要性**：这是唯一能**原生支持所有地址类型**（包括 Taproot）的签名协议。它通过构造虚拟的比特币交易来完成签名，不依赖 ECDSA 恢复标志位机制，因此可以支持 Schnorr 签名（Taproot）等新签名算法
- **适用场景**：**Taproot 地址的唯一选择**；也适用于需要使用 BIP-322 验证流程的 DApp 和协议
- **局限性**：相对较新，验证器生态还在完善中

### 三种格式共存的必要性

不提供选择将导致以下问题：
1. **只提供 Standard** → 无法支持 Taproot 地址签名，且无法精确验证 SegWit 地址
2. **只提供 BIP-137** → 无法支持 Taproot 地址签名，且与部分老旧验证器不兼容
3. **只提供 BIP-322** → Legacy 和 Nested SegWit 地址缺乏验证器支持（BIP-322 对非纯 SegWit 地址的 Simple 格式不适用）

因此三种格式互补覆盖，缺一不可。

---

## 接口设计：BtcMessageInput 新增 signatureType

在 BTC 消息签名的请求参数 `BtcMessageInput` 中新增 `signatureType` 枚举字段，由前端根据用户选择或业务场景指定签名格式：

```protobuf
enum BtcSignatureType {
  STANDARD = 0;   // 标准格式 — 默认值，最大兼容性
  BIP137   = 1;   // BIP-137 — 精确地址类型标识
  BIP322   = 2;   // BIP-322 — 通用签名（Taproot 必须）
}

message BtcMessageInput {
  string           message       = 1;  // 待签名的消息内容（UTF-8 文本）
  BtcSignatureType signatureType = 2;  // 签名格式类型
}
```

**默认行为**：`signatureType` 未设置时默认为 `STANDARD`（枚举值 0），保持向后兼容。现有未适配的调用方无需修改即可正常工作。

---

## 地址类型与签名格式兼容性矩阵

不同地址类型可使用的签名格式如下，不兼容的组合将返回明确的错误提示：

| 地址格式 | 地址前缀 | Standard | BIP-137 | BIP-322 |
|---------|---------|----------|---------|---------|
| Legacy（P2PKH） | `1...` | ✅ flag 31-34 | ✅ flag 31-34 | ❌ 不支持 |
| Nested SegWit（P2SH-P2WPKH） | `3...` | ✅ flag 31-34 | ✅ flag 35-38 | ❌ 不支持 |
| Native SegWit（P2WPKH） | `bc1q...` | ✅ flag 31-34 | ✅ flag 39-42 | ✅ Simple（Base64） |
| Taproot（P2TR） | `bc1p...` | ❌ 不支持 | ❌ 不支持 | ✅ Full（Base64） |

**不兼容的原因说明**：
- **Legacy / Nested SegWit 不支持 BIP-322**：BIP-322 Simple 格式要求地址为纯 SegWit 地址，Legacy（P2PKH）和 Nested SegWit（P2SH 包裹）不满足条件
- **Taproot 不支持 Standard / BIP-137**：Standard 和 BIP-137 基于 ECDSA 可恢复签名机制，而 Taproot 使用 Schnorr 签名算法（BIP-340），两者不兼容。BIP-137 规范中也未定义 Taproot 的标志位范围

---

## 签名输出格式

所有签名输出统一为 Base64 编码字符串（当前 BIP-322 输出为 hex，需修改）：

| 签名类型 | 输出内容 | 编码 |
|---------|---------|------|
| Standard / BIP-137 | 65 字节紧凑签名：`[标志字节(1), r(32), s(32)]` | Base64 |
| BIP-322 Simple（Native SegWit） | witness stack 的共识编码 | Base64 |
| BIP-322 Full（Taproot） | 完整签名交易的网络序列化 | Base64 |

---

## 关于 BIP-322 Full 格式的必要性

当前项目已实现 BIP-322 Simple（仅返回 witness stack），是否有必要额外支持 Full 格式（返回完整交易）？

### 从实现成本看
- 当前 BIP-322 Simple 已经完成了 Full 所需的全部签名流程（构造 `to_spend`、`to_sign`、PSBT 签名）
- **Simple 只是在最后一步仅提取 witness，Full 则是序列化整个交易**
- 改动量很小：约 5-10 行代码的差异，只需在 Taproot 分支中将 `提取 witness` 替换为 `序列化整个交易`

### 从兼容性看
- BIP-322 Simple 格式要求验证器自行重建 `to_spend` 和 `to_sign` 交易结构，再填入 witness 进行验证
- BIP-322 Full 格式直接提供完整交易，验证器**无需自行重建交易**，直接反序列化即可验证
- Taproot 使用 Schnorr 签名，签名验证依赖交易上下文（sighash 计算）。Full 格式提供了完整上下文，**降低了验证器实现的复杂度和出错概率**
- 由于 BIP-322 对 Taproot 的支持是较新的特性，目前并非所有验证器都正确实现了 Taproot Simple 的交易重建逻辑，**Full 格式的兼容性明显优于 Simple**

### 从长期演进看
- BIP-322 Full 是规范中更完整的格式，支持未来扩展（如时间锁、多输入资金证明等）
- 如果后续需要支持 BIP-322 Proof of Funds（资金证明）功能，Full 格式是必要基础
- 行业趋势上，Taproot 的采用率在持续增长，提前支持 Full 格式为后续需求做好准备

### 结论
**建议 Taproot 使用 BIP-322 Full 格式**：实现成本极低（基于已有 Simple 实现），但在验证器兼容性和长期扩展性上有明显优势。

---

## 变更内容

- **新增 BIP-137 消息签名**：为 Legacy（P2PKH）和 Nested SegWit（P2SH-P2WPKH）地址实现 `Bitcoin Signed Message:\n` 前缀 + 双 SHA256 哈希 + 65 字节紧凑可恢复 ECDSA 签名（含地址类型专属恢复标志位）
- **新增 Standard（标准）格式支持**：与 BIP-137 相同的签名流程，但无论实际地址类型，一律使用 P2PKH 压缩公钥标志位（31-34），提供最大兼容性
- **修改 BIP-322 输出编码**：Native SegWit（P2WPKH）和 Taproot（P2TR）地址的签名输出从 hex 改为 Base64
- **实现 BIP-322 Full 格式**：Taproot 地址返回完整序列化的 `to_sign` 交易（Base64 编码），而非仅返回 witness stack
- **保留 BIP-322 Simple**：Native SegWit 地址仍返回 witness stack 的 Base64 编码（逻辑不变，仅修改编码格式）
- **扩展 `BtcMessageInput` protobuf**：新增 `signatureType` 字段，允许调用方指定签名格式（Standard / BIP-137 / BIP-322）
- **同步修改 imKey 硬件钱包路径**

## 能力清单

### 新增能力
- `bip137-message-signing`：为 Legacy（P2PKH）和 Nested SegWit（P2SH-P2WPKH）地址提供 BIP-137 及 Standard 格式消息签名，输出 65 字节紧凑签名的 Base64 编码
- `bip322-full-taproot`：为 Taproot（P2TR）地址提供 BIP-322 Full 格式消息签名，返回完整序列化 `to_sign` 交易的 Base64 编码
- `btc-message-signing-format-selection`：扩展 Protobuf API，允许调用方指定 BTC 消息签名格式（Standard、BIP-137、BIP-322）

### 修改的能力
- `bip322-simple-segwit`：现有 Native SegWit（P2WPKH）的 BIP-322 Simple 消息签名 — 输出编码从 hex 改为 Base64

## 影响范围

- **Protobuf API**：`btc_kin.proto` — `BtcMessageInput` 新增 `signatureType` 枚举字段；`BtcMessageOutput` 的 signature 字段语义变更（hex → Base64）
- **token-core**：`tcx-btc-kin/src/message.rs` — 重构为按地址类型和签名格式分流派发
- **imkey-core**：`ikc-wallet/coin-bitcoin/src/message.rs` — 同步修改硬件钱包签名路径（新增 BIP-137 / Standard 格式支持、BIP-322 Full 格式支持）
- **imKey 集成侧（imToken → imKey 调用路径）**：**无需适配**。imKey 的签名输出在集成到 imToken 时已统一转换为 Base64 返回，本次 BIP-322 hex→Base64 的编码变更仅影响 token-core 直接调用方，不影响通过 imKey 路径获取签名的客户端
- **破坏性变更**：BIP-322 签名输出从 hex 改为 Base64。**影响范围仅限直接解析 token-core BIP-322 签名输出的调用方**（即直接使用 TCX API 获取 BIP-322 hex 签名的客户端），这些调用方必须更新解析逻辑。通过 imKey 路径的调用方不受影响
