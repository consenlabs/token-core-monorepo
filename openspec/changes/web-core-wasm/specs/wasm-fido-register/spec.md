## ADDED Requirements

### Requirement: FIDO 设备注册
系统 SHALL 提供 WASM 导出的异步函数 `fido_register`，调用浏览器 `navigator.credentials.create()` API 完成 FIDO2/WebAuthn 设备注册。函数 SHALL 接受 relying party 信息（rp_id, rp_name）、用户信息（user_id, user_name）和可选参数，返回注册结果。

#### Scenario: 成功注册 FIDO 设备
- **WHEN** 调用 `fido_register({ rp_id: "example.com", rp_name: "Example", user_id: <bytes>, user_name: "user@example.com" })`，且用户在 FIDO 设备上确认注册
- **THEN** 返回包含 `credential_id`（Base64URL 编码）、`public_key`（COSE 格式）和 `attestation_object`（Base64URL 编码）的注册结果对象

#### Scenario: 注册时声明 PRF 支持
- **WHEN** 调用 `fido_register` 时
- **THEN** 系统 SHALL 在 `publicKeyCredentialCreationOptions.extensions` 中自动包含 `prf: {}` 扩展，以声明 PRF 能力需求
- **AND** 返回结果 SHALL 包含 `prf_supported` 布尔值，指示设备是否支持 PRF 扩展

#### Scenario: 用户取消注册
- **WHEN** 用户在 FIDO 设备交互过程中取消操作
- **THEN** 返回错误，错误类型为 `UserCancelled`

#### Scenario: 浏览器不支持 WebAuthn
- **WHEN** 当前浏览器不支持 `navigator.credentials` API
- **THEN** 返回错误，错误类型为 `WebAuthnNotSupported`
