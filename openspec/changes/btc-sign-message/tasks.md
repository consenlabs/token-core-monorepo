## 1. Protobuf API 扩展

- [ ] 1.1 在 `token-core/tcx-proto/src/btc_kin.proto` 中新增 `BtcSignatureType` 枚举（`STANDARD = 0`、`BIP137 = 1`、`BIP322 = 2`）
- [ ] 1.2 在 `btc_kin.proto` 的 `BtcMessageInput` 中新增 `BtcSignatureType signatureType` 字段
- [ ] 1.3 运行 proto 构建（`tcx-proto/build.rs`）重新生成 Rust protobuf 结构体
- [ ] 1.4 更新 `tcx-btc-kin/src/transaction.rs` 中的 `BtcMessageInput` 结构体，加入新的 `signature_type` 字段

## 2. BIP-137 实现（token-core）

- [ ] 2.1 在 `tcx-btc-kin/Cargo.toml` 中添加 `base64` crate 依赖
- [ ] 2.2 在 `tcx-btc-kin/src/message.rs` 中实现 `bip137_message_hash(message: &[u8]) -> [u8; 32]` 函数 — 构造 `"\x18Bitcoin Signed Message:\n" + varint(长度) + 消息` 并双 SHA256 哈希
- [ ] 2.3 实现 `sign_message_bip137(keystore, params, message, flag_base) -> Result<String>` — 调用 `secp256k1_ecdsa_sign_recoverable`，构造 65 字节紧凑签名 `[flag_base + recovery_id, r, s]`，返回 Base64
- [ ] 2.4 添加 BIP-137 Legacy（P2PKH）签名的单元测试，使用已知测试向量验证
- [ ] 2.5 添加 BIP-137 Nested SegWit（P2SH-P2WPKH）签名的单元测试，验证标志字节在 35-38 范围
- [ ] 2.6 添加 Standard 格式签名的单元测试，验证无论地址类型标志字节始终在 31-34 范围

## 3. BIP-322 输出格式修改（token-core）

- [ ] 3.1 修改 `tcx-btc-kin/src/message.rs` 中 BIP-322 Simple 输出（Native SegWit / VERSION_0）— 将 `witness_to_vec().to_hex()` 改为 `base64::encode(witness_to_vec())`
- [ ] 3.2 实现 Taproot（VERSION_1）的 BIP-322 Full 输出 — PSBT 签名后通过 `psbt.extract_tx()` 提取已签名交易，使用 `bitcoin::consensus::serialize()` 序列化，返回 `base64::encode(序列化交易)`
- [ ] 3.3 更新现有 BIP-322 单元测试，期望输出从 hex 改为 Base64
- [ ] 3.4 添加 Taproot BIP-322 Full 格式的单元测试，验证 Base64 输出解码后为有效的序列化交易

## 4. 签名派发器与验证（token-core）

- [ ] 4.1 重构 `MessageSigner<BtcMessageInput, BtcMessageOutput>` 实现，基于 `signature_type` 字段结合 `seg_wit` 进行派发
- [ ] 4.2 实现格式与地址类型兼容性验证：Legacy 不支持 BIP-322，Taproot 不支持 BIP-137/Standard
- [ ] 4.3 在 `tcx-btc-kin/src/lib.rs` 的 Error 枚举中添加不兼容组合的错误类型
- [ ] 4.4 添加兼容性验证的单元测试 — 验证无效组合返回正确的错误

## 5. imKey 硬件钱包路径

- [ ] 5.1 更新 `imkey-core/ikc-wallet/coin-bitcoin/src/btcapi.rs` 中的 `BtcMessageInput` 结构体，加入 `signature_type` 字段
- [ ] 5.2 在 `imkey-core/ikc-wallet/coin-bitcoin/src/message.rs` 中实现 BIP-137 签名 — 调查 APDU 是否支持使用 BIP-137 消息哈希的原始 ECDSA 可恢复签名
- [ ] 5.3 修改 `imkey-core/ikc-wallet/coin-bitcoin/src/message.rs` 中 BIP-322 Simple 输出为 Base64
- [ ] 5.4 在 `imkey-core/ikc-wallet/coin-bitcoin/src/message.rs` 中实现 Taproot 的 BIP-322 Full 输出
- [ ] 5.5 添加与 token-core 实现一致的派发器和格式地址兼容性验证

## 6. 集成测试

- [ ] 6.1 在 `token-core/tcx/tests/sign_test.rs` 中添加 BIP-137 Legacy 消息签名的集成测试（通过 `sign_msg` API）
- [ ] 6.2 添加 BIP-137 Nested SegWit 消息签名的集成测试（通过 `sign_msg` API）
- [ ] 6.3 添加 Standard 格式消息签名的集成测试（通过 `sign_msg` API）
- [ ] 6.4 更新现有 BIP-322 集成测试，验证 Base64 输出
- [ ] 6.5 添加 Taproot BIP-322 Full 格式的集成测试（通过 `sign_msg` API）
- [ ] 6.6 添加格式与地址类型不兼容错误场景的集成测试
