## 为什么要做

钱包当前对所有 BTC 地址类型统一使用 BIP-322 流程进行消息签名，输出为 hex 编码。这不符合行业标准：Legacy 和 Nested SegWit 地址应使用 BIP-137（经典 `Bitcoin Signed Message` 格式），输出应按规范使用 Base64 编码，Taproot 则需要 BIP-322 Full 格式（而非仅 Simple）。由于缺乏标准合规性，我们钱包产出的签名无法被主流第三方工具（Sparrow、mempool.space 等）验证，限制了钱包在地址所有权证明、交易所 KYC、审计等场景的实用性。

## 变更内容

- **新增 BIP-137 消息签名**：为 Legacy（P2PKH）和 Nested SegWit（P2SH-P2WPKH）地址实现 `Bitcoin Signed Message:\n` 前缀 + 双 SHA256 哈希 + 65 字节紧凑可恢复 ECDSA 签名（含地址类型专属恢复标志位）。
- **新增 Standard（标准）格式支持**：与 BIP-137 相同的签名流程，但无论实际地址类型，一律使用 P2PKH 压缩公钥标志位（31-34），提供最大兼容性。
- **修改 BIP-322 输出编码**：Native SegWit（P2WPKH）和 Taproot（P2TR）地址的签名输出从 hex 改为 Base64。
- **实现 BIP-322 Full 格式**：Taproot 地址返回完整序列化的 `to_sign` 交易（Base64 编码），而非仅返回 witness stack。
- **保留 BIP-322 Simple**：Native SegWit 地址仍返回 witness stack 的 Base64 编码（逻辑不变，仅修改编码格式）。
- **扩展 `BtcMessageInput` protobuf**：新增 `signatureType` 字段，允许调用方指定签名格式（Standard / BIP-137 / BIP-322）。
- **同步修改 imKey 硬件钱包路径**（`imkey-core/ikc-wallet/coin-bitcoin/src/message.rs`）。

## 能力清单

### 新增能力
- `bip137-message-signing`：为 Legacy（P2PKH）和 Nested SegWit（P2SH-P2WPKH）地址提供 BIP-137 及 Standard 格式消息签名，输出 65 字节紧凑签名的 Base64 编码。
- `bip322-full-taproot`：为 Taproot（P2TR）地址提供 BIP-322 Full 格式消息签名，返回完整序列化 `to_sign` 交易的 Base64 编码。
- `btc-message-signing-format-selection`：扩展 Protobuf API，允许调用方指定 BTC 消息签名格式（Standard、BIP-137、BIP-322）。

### 修改的能力
- `bip322-simple-segwit`：现有 Native SegWit（P2WPKH）的 BIP-322 Simple 消息签名 — 输出编码从 hex 改为 Base64。

## 影响范围

- **Protobuf API**：`btc_kin.proto` — `BtcMessageInput` 新增 `signatureType` 枚举字段；`BtcMessageOutput` 的 signature 字段语义变更（hex → Base64）。
- **token-core**：`tcx-btc-kin/src/message.rs` — 重构为按地址类型和签名格式分流派发。
- **imkey-core**：`ikc-wallet/coin-bitcoin/src/message.rs` — 同步修改硬件钱包签名路径。
- **依赖项**：可能需要在 `tcx-btc-kin/Cargo.toml` 中添加 `base64` crate（需检查是否已通过传递依赖可用）。
- **破坏性变更**：所有 BTC 地址类型的 BIP-322 签名输出从 hex 改为 Base64，消费 `BtcMessageOutput.signature` 字段的调用方必须更新解析逻辑。
