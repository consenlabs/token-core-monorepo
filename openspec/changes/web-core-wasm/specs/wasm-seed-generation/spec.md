## ADDED Requirements

### Requirement: 生成 BIP39 助记词
系统 SHALL 提供 WASM 导出函数 `generate_mnemonic`，生成符合 BIP39 规范的助记词。函数 SHALL 支持指定词数（12 或 24 个单词，对应 128 或 256 位熵）。随机熵 SHALL 通过浏览器 `crypto.getRandomValues()` 获取（经由 `getrandom` crate 的 `js` feature）。

#### Scenario: 生成 12 词助记词
- **WHEN** 调用 `generate_mnemonic(12)`
- **THEN** 返回包含 12 个 BIP39 英文单词的字符串，单词间以空格分隔，且最后一个词包含正确的校验位

#### Scenario: 生成 24 词助记词
- **WHEN** 调用 `generate_mnemonic(24)`
- **THEN** 返回包含 24 个 BIP39 英文单词的字符串

#### Scenario: 无效词数
- **WHEN** 调用 `generate_mnemonic` 传入非 12 或 24 的词数
- **THEN** 返回错误，说明仅支持 12 或 24 词

### Requirement: 从助记词生成 seed
系统 SHALL 提供 WASM 导出函数 `mnemonic_to_seed`，接受助记词字符串和可选的密码（passphrase），返回 64 字节的 BIP39 seed（hex 编码字符串）。

#### Scenario: 无密码生成 seed
- **WHEN** 调用 `mnemonic_to_seed("abandon abandon ... about", "")`，传入有效助记词和空密码
- **THEN** 返回 128 字符的 hex 字符串（64 字节 seed），结果与 BIP39 参考实现一致

#### Scenario: 带密码生成 seed
- **WHEN** 调用 `mnemonic_to_seed(mnemonic, "my_passphrase")`，传入有效助记词和非空密码
- **THEN** 返回的 seed 与空密码时不同，且与 BIP39 参考实现（使用相同 passphrase）一致

#### Scenario: 无效助记词
- **WHEN** 调用 `mnemonic_to_seed` 传入无效助记词（校验位错误或包含非 BIP39 词）
- **THEN** 返回错误，说明助记词无效
