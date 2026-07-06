## 1. 提案确认

- [x] 1.1 API method 名称使用 `sign_typed_data_with_auth_key`
- [x] 1.2 请求参数只包含 `identifier`，不包含 keystore `id`
- [x] 1.3 返回结果不包含 `digest`
- [x] 1.4 确认 EIP-712 crate 选型与类型支持范围
- [ ] 1.5 确认 stake 业务 TypedData JSON 示例

## 2. Protobuf API 扩展

- [x] 2.1 在 `token-core/tcx-proto/src/api.proto` 中新增 `SignTypedDataWithAuthKeyParam`
- [x] 2.2 在 `api.proto` 中新增 `SignTypedDataWithAuthKeyResult`
- [x] 2.3 更新 `token-core/tcx/src/api.rs`

## 3. EIP-712 TypedData 哈希

- [x] 3.1 评估 `alloy-dyn-abi` 对运行时 TypedData JSON 的支持、许可证、依赖体积与 Rust 版本兼容性
- [x] 3.2 评估 ethers `types::transaction::eip712` 能力与 deprecating 状态影响
- [x] 3.3 确认最终 crate 选型为 `alloy-dyn-abi 1.6.0`
- [x] 3.4 接入 `alloy-dyn-abi 1.6.0`，计算 `domainSeparator`、`hashStruct(message)` 与最终 digest
- [x] 3.5 使用 EIP-712 官方 Ether Mail 样例添加单元测试
- [ ] 3.6 使用 stake 业务 TypedData 示例添加单元测试

## 4. Auth Key 签名

- [x] 4.1 在 `Identity` 上新增内部方法，对 32-byte digest 使用 auth key 签名
- [x] 4.2 签名输出统一为 `r || s || v`，`v = recovery_id + 27`
- [x] 4.3 保持 auth key 解密只通过 `Unlocker` 完成，不暴露明文 key 到公共 API

## 5. TCX Handler 接入

- [x] 5.1 在 `token-core/tcx/src/handler.rs` 新增 `sign_typed_data_with_auth_key`
- [x] 5.2 根据 `identifier` 查找 keystore，找不到返回 `identity_not_found`
- [x] 5.3 使用 password/derivedKey 获取 `Unlocker`
- [x] 5.4 返回 `SignTypedDataWithAuthKeyResult`
- [x] 5.5 在 `token-core/tcx/src/lib.rs` 注册 `call_tcx_api` method

## 6. 测试

- [x] 6.1 添加 EIP-712 官方样例 digest 测试
- [ ] 6.2 添加 stake xpub 绑定 TypedData digest 测试
- [x] 6.3 添加 `sign_typed_data_with_auth_key` API 集成测试
- [x] 6.4 添加 password 与 derivedKey 两种解锁路径测试
- [x] 6.5 添加 identifier 不存在错误测试
- [x] 6.6 添加 malformed typedData 错误测试
- [x] 6.7 添加 password/derivedKey 缺失错误测试
- [x] 6.8 添加语义非法 TypedData 错误测试

## 7. 文档

- [x] 7.1 记录接口参数与返回格式
- [x] 7.2 记录支持的 EIP-712 类型范围
