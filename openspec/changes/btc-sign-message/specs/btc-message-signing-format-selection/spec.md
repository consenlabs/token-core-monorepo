## 新增需求

### 需求：BtcMessageInput protobuf 新增签名类型字段
`BtcMessageInput` protobuf 消息必须包含 `signatureType` 字段，允许调用方指定所需的签名格式。该字段必须为枚举类型，可选值为：`STANDARD`、`BIP137`、`BIP322`。

#### 场景：调用方指定 BIP-137 格式
- **当** 发送的 `BtcMessageInput` 中 `signatureType = BIP137`
- **则** 系统使用 BIP-137 签名流程，包含地址类型专属标志字节

#### 场景：调用方指定 Standard 格式
- **当** 发送的 `BtcMessageInput` 中 `signatureType = STANDARD`
- **则** 系统使用 BIP-137 签名流程，标志字节始终为 P2PKH 压缩公钥范围（31-34），无论地址类型

#### 场景：调用方指定 BIP-322 格式
- **当** 发送的 `BtcMessageInput` 中 `signatureType = BIP322`
- **则** 系统使用 BIP-322 签名流程（Native SegWit 使用 Simple，Taproot 使用 Full）

#### 场景：未指定 signatureType 时的默认行为
- **当** 发送的 `BtcMessageInput` 未设置 `signatureType`（默认为 0 / 枚举第一个值）
- **则** 系统必须默认使用 `STANDARD` 格式，确保向后兼容

### 需求：格式与地址类型兼容性验证
系统必须验证请求的签名格式与地址类型是否兼容，对不兼容的组合返回错误。

#### 场景：Legacy 地址请求 BIP-322
- **当** 对 Legacy（P2PKH）地址（`seg_wit = "NONE"`）请求 `signatureType = BIP322`
- **则** 系统返回错误，说明 BIP-322 Simple 不支持非 SegWit 地址

#### 场景：Taproot 地址请求 BIP-137
- **当** 对 Taproot 地址（`seg_wit = "VERSION_1"`）请求 `signatureType = BIP137` 或 `signatureType = STANDARD`
- **则** 系统返回错误，说明 BIP-137 不支持 Taproot 地址（Taproot 必须使用 BIP-322）

#### 场景：Native SegWit 支持所有格式
- **当** 收到 Native SegWit（`seg_wit = "VERSION_0"`）的签名请求
- **则** 系统必须支持全部三种格式：STANDARD（标志位 31-34）、BIP137（标志位 39-42）、BIP322（Simple）
