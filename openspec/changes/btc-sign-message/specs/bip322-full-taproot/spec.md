## 新增需求

### 需求：Taproot（P2TR）地址的 BIP-322 Full 格式
系统必须使用 BIP-322 Full 格式为 Taproot（`bc1p...`）地址签署消息。签名流程必须：
1. 构造 `to_spend` 交易，其中 `message_hash = SHA256_tag("BIP0322-signed-message", 消息内容)`，`message_challenge = P2TR scriptPubKey`
2. 构造 `to_sign` 交易，花费 `to_spend` 的输出，`nVersion=0`、`nLockTime=0`、`nSequence=0`，输出为 `OP_RETURN`
3. 使用 Schnorr 签名（BIP-340）通过 PSBT 签名流程对 `to_sign` 交易签名
4. 使用标准比特币网络序列化格式序列化整个已签名的 `to_sign` 交易
5. 返回序列化交易的 Base64 编码字符串

#### 场景：Taproot 消息签名生成 Full 格式输出
- **当** 收到签名请求，`seg_wit = "VERSION_1"`
- **则** 系统返回一个 Base64 编码字符串，解码后为完整序列化的比特币交易（而非仅 witness 数据）

#### 场景：Full 格式签名可被验证
- **当** 将生成的 Base64 签名解码并反序列化为比特币交易
- **则** 交易第一个输入的 witness 包含有效的 Schnorr 签名，且交易花费了正确构造的 `to_spend` 交易

#### 场景：Full 格式包含完整交易结构
- **当** 对 Base64 输出进行解码
- **则** 包含完整交易：版本号、输入（prevout 引用 `to_spend.txid:0`）、输出（`OP_RETURN`）和 witness 数据（Schnorr 签名）

### 需求：imKey 硬件钱包 Taproot BIP-322 Full 签名
系统必须通过 imKey 硬件钱包路径支持 Taproot 地址的 BIP-322 Full 格式签名。

#### 场景：硬件钱包 Taproot BIP-322 Full 签名
- **当** Taproot 消息签名请求通过 imKey 硬件钱包路由
- **则** 系统生成 BIP-322 Full 格式签名（Base64 编码的序列化 `to_sign` 交易），包含来自硬件设备的 Schnorr 签名
