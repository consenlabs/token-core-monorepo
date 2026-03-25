## 新增需求

### 需求：Legacy（P2PKH）地址的 BIP-137 消息签名
系统必须支持使用 BIP-137 标准为 Legacy（P2PKH，`1...`）地址签署任意 UTF-8 文本消息。签名流程必须：
1. 构造消息摘要：`SHA256(SHA256("\x18Bitcoin Signed Message:\n" + varint(消息长度) + 消息内容))`
2. 生成 secp256k1 ECDSA 可恢复签名
3. 输出 65 字节紧凑签名：`[标志字节, r(32字节), s(32字节)]`，其中 `标志字节 = 31 + recovery_id`（压缩公钥 P2PKH 范围）
4. 返回 Base64 编码的签名字符串

#### 场景：使用 Legacy P2PKH 地址签名消息
- **当** 收到签名请求，`seg_wit = "NONE"` 且 `signatureType = BIP137`
- **则** 系统生成标志字节在 31-34 范围的 65 字节紧凑 ECDSA 签名，Base64 编码输出

#### 场景：签名可被标准 BIP-137 验证器验证
- **当** 生成的签名与原始消息和 P2PKH 地址一起提交给 BIP-137 合规验证器
- **则** 验证器确认签名有效

### 需求：Nested SegWit（P2SH-P2WPKH）地址的 BIP-137 消息签名
系统必须支持使用 BIP-137 标准为 Nested SegWit（P2SH-P2WPKH，`3...`）地址签署任意 UTF-8 文本消息。签名流程与 Legacy P2PKH 完全相同，唯一区别是标志字节必须使用 `35 + recovery_id`（P2SH-P2WPKH 范围）。

#### 场景：使用 Nested SegWit 地址签名消息
- **当** 收到签名请求，`seg_wit = "P2WPKH"` 且 `signatureType = BIP137`
- **则** 系统生成标志字节在 35-38 范围的 65 字节紧凑 ECDSA 签名，Base64 编码输出

#### 场景：签名标志位正确标识 P2SH-P2WPKH 地址类型
- **当** 对生成的签名进行 Base64 解码
- **则** 第一个字节在 35-38 范围内，使验证器能从恢复的公钥重建 P2SH-P2WPKH 地址

### 需求：Standard（标准）格式消息签名
系统必须支持"标准"签名格式，该格式使用与 BIP-137 相同的消息摘要和 ECDSA 签名流程，但标志字节始终使用 P2PKH 压缩公钥范围（`31 + recovery_id`），无论实际地址类型如何。此格式提供与传统验证器的最大向后兼容性。

#### 场景：Nested SegWit 地址使用 Standard 格式
- **当** 收到签名请求，`seg_wit = "P2WPKH"` 且 `signatureType = STANDARD`
- **则** 系统生成标志字节在 31-34 范围的 65 字节紧凑签名（与 P2PKH 相同），Base64 编码输出

#### 场景：Legacy 地址使用 Standard 格式
- **当** 收到签名请求，`seg_wit = "NONE"` 且 `signatureType = STANDARD`
- **则** 行为与 Legacy 地址的 BIP-137 签名完全一致（标志字节 31-34）

### 需求：imKey 硬件钱包 BIP-137 和 Standard 签名
系统必须通过 imKey 硬件钱包路径支持 BIP-137 和 Standard 格式消息签名。签名过程必须在硬件设备上完成，遵循相同的标志字节约定。

#### 场景：硬件钱包 Legacy BIP-137 签名
- **当** Legacy 地址的 `signatureType = BIP137` 签名请求通过 imKey 硬件钱包路由
- **则** 系统通过 APDU 与 imKey 设备通信，生成标志字节在 31-34 范围的有效 BIP-137 签名

#### 场景：硬件钱包 Nested SegWit BIP-137 签名
- **当** Nested SegWit 地址的 `signatureType = BIP137` 签名请求通过 imKey 硬件钱包路由
- **则** 系统生成标志字节在 35-38 范围的有效 BIP-137 签名

#### 场景：硬件钱包 Legacy Standard 签名
- **当** Legacy 地址的 `signatureType = STANDARD` 签名请求通过 imKey 硬件钱包路由
- **则** 系统生成标志字节在 31-34 范围的签名（与 BIP-137 Legacy 行为一致）

#### 场景：硬件钱包 Nested SegWit Standard 签名
- **当** Nested SegWit 地址的 `signatureType = STANDARD` 签名请求通过 imKey 硬件钱包路由
- **则** 系统生成标志字节在 31-34 范围的签名（使用 P2PKH 压缩公钥标志，而非 P2SH-P2WPKH 标志）
