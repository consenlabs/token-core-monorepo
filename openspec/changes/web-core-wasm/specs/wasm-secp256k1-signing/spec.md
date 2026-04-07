## ADDED Requirements

### Requirement: secp256k1 ECDSA 签名
系统 SHALL 提供 WASM 导出函数 `secp256k1_sign`，接受私钥（32 字节 hex）和消息哈希（32 字节 hex），返回 ECDSA 签名。签名 SHALL 使用 RFC 6979 确定性 nonce 生成。

#### Scenario: 对消息哈希签名
- **WHEN** 调用 `secp256k1_sign(private_key_hex, message_hash_hex)`，传入有效私钥和 32 字节消息哈希
- **THEN** 返回包含 `r`（32 字节 hex）、`s`（32 字节 hex）和 `v`（recovery_id, 0 或 1）的签名对象

#### Scenario: 签名可恢复公钥
- **WHEN** 使用返回的签名（r, s, v）和原始消息哈希执行公钥恢复
- **THEN** 恢复出的公钥与签名时使用的私钥对应的公钥一致

#### Scenario: 签名 normalize_s
- **WHEN** 生成签名后
- **THEN** 签名的 `s` 值 SHALL 为 low-S 形式（s <= curve_order / 2），符合 BIP-62 规范

#### Scenario: 无效私钥
- **WHEN** 调用 `secp256k1_sign` 传入全零私钥或超出曲线阶的值
- **THEN** 返回错误，说明私钥无效

#### Scenario: 无效消息哈希长度
- **WHEN** 调用 `secp256k1_sign` 传入长度不为 64 字符（32 字节）的消息哈希
- **THEN** 返回错误，说明消息哈希长度必须为 32 字节

### Requirement: secp256k1 签名验证
系统 SHALL 提供 WASM 导出函数 `secp256k1_verify`，验证签名是否与给定公钥和消息哈希匹配。

#### Scenario: 验证有效签名
- **WHEN** 调用 `secp256k1_verify(public_key_hex, message_hash_hex, signature_hex)`，传入正确的公钥、消息哈希和签名
- **THEN** 返回 `true`

#### Scenario: 验证无效签名
- **WHEN** 调用 `secp256k1_verify` 传入被篡改的签名
- **THEN** 返回 `false`
