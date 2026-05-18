## 修改的需求

### 需求：BIP-322 Simple 消息签名输出编码变更
现有 Native SegWit（P2WPKH，`bc1q...`）地址的 BIP-322 Simple 消息签名必须将输出编码从十六进制（hex）改为 Base64。签名流程（构造 `to_spend`、`to_sign`、PSBT 签名、提取 witness stack）保持不变。witness stack 必须按 BIP-322 规范进行共识编码（编码为字节向量的向量），然后进行 Base64 编码。

#### 场景：Native SegWit BIP-322 Simple 输出 Base64 编码
- **当** 收到签名请求，`seg_wit = "VERSION_0"` 且 `signatureType = BIP322`
- **则** 系统返回 Base64 编码字符串（而非 hex），代表共识编码的 witness stack

#### 场景：Base64 输出可解码为 witness stack
- **当** 对 Base64 输出进行解码
- **则** 可解析为包含 `[ECDSA 签名, 压缩公钥]` 的共识编码 witness stack

#### 场景：imKey 硬件钱包 Native SegWit BIP-322 Simple 输出 Base64
- **当** Native SegWit 地址的 `signatureType = BIP322` 签名请求通过 imKey 硬件钱包路由
- **则** 系统返回 Base64 编码的 witness stack（与软件钱包输出格式一致）

#### 场景：向后兼容性注意事项
- **当** 现有调用方收到新的 Base64 编码输出
- **则** 调用方必须将解析逻辑从 hex 解码更新为 Base64 解码（这是一个**破坏性变更**）
