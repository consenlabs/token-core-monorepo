## ADDED Requirements

### Requirement: FIDO PRF 对称密钥派生
系统 SHALL 提供 WASM 导出的异步函数 `fido_derive_prf_key`，通过 WebAuthn PRF 扩展（`hmac-secret`）从 FIDO 设备派生确定性的对称密钥。函数 SHALL 接受 `credential_id`、`rp_id`、`salt`（用于 PRF 计算的输入盐值），返回派生的对称密钥。

#### Scenario: 成功派生 PRF 密钥
- **WHEN** 调用 `fido_derive_prf_key({ credential_id: <base64url>, rp_id: "example.com", salt: <32 bytes hex> })`，且用户在 FIDO 设备上确认
- **THEN** 返回包含 `symmetric_key`（32 字节 hex 编码）的结果对象
- **AND** 使用相同的 credential_id、rp_id 和 salt 重复调用时，返回的 symmetric_key SHALL 相同（确定性）

#### Scenario: 使用不同 salt 派生不同密钥
- **WHEN** 使用相同 credential_id 和 rp_id，但不同的 salt 值调用 `fido_derive_prf_key`
- **THEN** 返回的 symmetric_key SHALL 与使用其他 salt 值时不同

#### Scenario: 设备不支持 PRF 扩展
- **WHEN** 使用不支持 PRF 扩展的 FIDO 设备调用 `fido_derive_prf_key`
- **THEN** 返回错误，错误类型为 `PrfNotSupported`，说明该 FIDO 设备不支持 PRF 扩展

#### Scenario: 用户取消认证
- **WHEN** 用户在 FIDO 设备交互过程中取消操作
- **THEN** 返回错误，错误类型为 `UserCancelled`

#### Scenario: credential_id 无效
- **WHEN** 传入不存在或已被撤销的 credential_id
- **THEN** 返回错误，说明凭证不可用
