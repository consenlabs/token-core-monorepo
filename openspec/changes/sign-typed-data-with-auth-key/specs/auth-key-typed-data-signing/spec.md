## 新增需求

### 需求：提供 auth key TypedData 签名接口

系统必须提供 `sign_typed_data_with_auth_key` 接口，允许调用方传入 `identifier`、明文 EIP-712 TypedData JSON，以及 password 或 derivedKey，由 token-core 使用该 `identifier` 对应的 auth key 签名 TypedData digest。

#### 场景：使用 password 签名 TypedData

- **当** 调用方传入有效的 `identifier`、`typedData` 和 `password`
- **则** 系统必须找到该 `identifier` 对应的 keystore
- **并且** 系统必须用 password 解锁 keystore crypto
- **并且** 系统必须解密 `identity.encAuthKey`
- **并且** 系统必须按 EIP-712 计算 TypedData digest
- **并且** 系统必须返回 auth key 对 digest 的 recoverable secp256k1 签名

#### 场景：使用 derivedKey 签名 TypedData

- **当** 调用方传入有效的 `identifier`、`typedData` 和 `derivedKey`
- **则** 系统必须使用 derivedKey 完成与 password 路径等价的 auth key 解密与签名流程

#### 场景：identifier 不存在

- **当** 调用方传入的 `identifier` 不存在于当前加载的 keystore 中
- **则** 系统必须返回错误 `identity_not_found`

### 需求：TypedData digest 必须由 token-core 内部计算

系统必须接收明文 EIP-712 TypedData JSON，并在 token-core 内部计算签名 digest。系统不得要求调用方预先传入 `domainSeparator`、`hashStruct(message)` 或最终 digest。

#### 场景：计算 EIP-712 digest

- **当** 调用方传入合法 TypedData JSON
- **则** 系统必须计算 `domainSeparator = hashStruct(EIP712Domain)`
- **并且** 系统必须计算 `messageHash = hashStruct(primaryType message)`
- **并且** 系统必须计算 `digest = keccak256("\x19\x01" || domainSeparator || messageHash)`
- **并且** 系统必须对该 digest 签名

#### 场景：TypedData JSON 非法

- **当** `typedData` 不是合法 JSON，或缺少 `types`、`primaryType`、`domain`、`message` 任一必要字段
- **则** 系统必须返回明确的 typed data 解析或校验错误

### 需求：签名输出格式必须稳定

系统必须返回 65 字节 recoverable secp256k1 签名的 `0x` hex 字符串，字节顺序为 `r || s || v`，其中 `v = recovery_id + 27`。

#### 场景：签名成功

- **当** auth key 签名成功
- **则** `signature` 必须是长度为 132 字符的 `0x` hex 字符串
- **并且** 最后一个字节必须为 `0x1b` 或 `0x1c`

### 需求：业务 TypedData 必须支持防重放字段

系统接口必须允许业务 TypedData 携带 nonce、expiration、domain 等字段。重放保护由业务后端执行，但 token-core 文档必须明确建议调用方在 TypedData 中包含防重放字段。

#### 场景：stake 绑定 xpub

- **当** stake 业务构造 xpub 绑定 TypedData
- **则** TypedData message 应包含 `identifier`、`xpub`、`purpose`、`nonce` 和 `expiration`
- **并且** domain 应包含业务名称和版本

### 需求：不得改变现有认证签名接口

新增接口不得改变 `sign_authentication_message` 的输入、输出和签名结果。

#### 场景：旧接口继续可用

- **当** 调用方继续使用 `sign_authentication_message`
- **则** 系统必须保持现有固定 payload 签名行为不变
