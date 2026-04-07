## ADDED Requirements

### Requirement: BIP44 路径密钥派生
系统 SHALL 提供 WASM 导出函数 `derive_key`，从 seed（hex 编码）和 BIP44 派生路径派生出 secp256k1 密钥对。函数 SHALL 返回包含公钥（压缩格式，33 字节 hex）和私钥（32 字节 hex）的对象。

#### Scenario: 标准 BIP44 ETH 路径派生
- **WHEN** 调用 `derive_key(seed_hex, "m/44'/60'/0'/0/0")`
- **THEN** 返回的公钥和私钥与 BIP32/BIP44 参考实现一致

#### Scenario: 标准 BIP44 BTC 路径派生
- **WHEN** 调用 `derive_key(seed_hex, "m/44'/0'/0'/0/0")`
- **THEN** 返回有效的 secp256k1 压缩公钥（以 `02` 或 `03` 开头，66 字符 hex）和 32 字节私钥

#### Scenario: 无效路径格式
- **WHEN** 调用 `derive_key` 传入无效路径（如 `"invalid_path"` 或空字符串）
- **THEN** 返回错误，说明路径格式无效

#### Scenario: 无效 seed
- **WHEN** 调用 `derive_key` 传入非法 hex 字符串或长度不为 128 字符的 seed
- **THEN** 返回错误，说明 seed 无效

### Requirement: 从派生路径获取公钥
系统 SHALL 提供 WASM 导出函数 `derive_public_key`，仅返回公钥（不暴露私钥），适用于前端只需要公钥的场景。

#### Scenario: 获取公钥
- **WHEN** 调用 `derive_public_key(seed_hex, "m/44'/60'/0'/0/0")`
- **THEN** 返回 secp256k1 压缩公钥（33 字节 hex 编码）
