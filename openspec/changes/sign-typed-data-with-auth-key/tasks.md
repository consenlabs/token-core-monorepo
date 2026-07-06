## 1. 提案确认

- [x] 1.1 API method 名称使用 `sign_typed_data_with_auth_key`
- [x] 1.2 请求参数只包含 `identifier`，不包含 keystore `id`
- [x] 1.3 返回结果不包含 `digest`
- [ ] 1.4 确认 EIP-712 类型支持范围
- [ ] 1.5 确认 stake 业务 TypedData schema

## 2. Protobuf API 扩展

- [ ] 2.1 在 `token-core/tcx-proto/src/params.proto` 中新增 `SignTypedDataWithAuthKeyParam`
- [ ] 2.2 在 `params.proto` 中新增 `SignTypedDataWithAuthKeyResult`
- [ ] 2.3 运行 proto 构建，更新 `token-core/tcx/src/api.rs`

## 3. EIP-712 TypedData 哈希

- [ ] 3.1 新增 TypedData JSON 解析结构
- [ ] 3.2 实现 `encodeType(primaryType)`，包含依赖 struct 收集与排序
- [ ] 3.3 实现 `typeHash = keccak256(encodeType(type))`
- [ ] 3.4 实现 atomic 类型编码：`address`、`bool`、`bytes1..bytes32`、`int*`、`uint*`
- [ ] 3.5 实现 dynamic 类型编码：`bytes`、`string`
- [ ] 3.6 实现 nested struct 的 `hashStruct`
- [ ] 3.7 实现 array 类型编码
- [ ] 3.8 实现 `domainSeparator`
- [ ] 3.9 实现最终 digest：`keccak256("\x19\x01" || domainSeparator || hashStruct(message))`
- [ ] 3.10 使用 EIP-712 官方 Ether Mail 样例添加单元测试

## 4. Auth Key 签名

- [ ] 4.1 在 `Identity` 上新增内部方法，对 32-byte digest 使用 auth key 签名
- [ ] 4.2 签名输出统一为 `r || s || v`，`v = recovery_id + 27`
- [ ] 4.3 保持 auth key 解密只通过 `Unlocker` 完成，不暴露明文 key 到公共 API

## 5. TCX Handler 接入

- [ ] 5.1 在 `token-core/tcx/src/handler.rs` 新增 `sign_typed_data_with_auth_key`
- [ ] 5.2 根据 `identifier` 查找 keystore，找不到返回 `identity_not_found`
- [ ] 5.3 使用 password/derivedKey 获取 `Unlocker`
- [ ] 5.4 返回 `SignTypedDataWithAuthKeyResult`
- [ ] 5.5 在 `token-core/tcx/src/lib.rs` 注册 `call_tcx_api` method

## 6. 测试

- [ ] 6.1 添加 EIP-712 官方样例 digest 测试
- [ ] 6.2 添加 stake xpub 绑定 TypedData digest 测试
- [ ] 6.3 添加 `sign_typed_data_with_auth_key` API 集成测试
- [ ] 6.4 添加 password 与 derivedKey 两种解锁路径测试
- [ ] 6.5 添加 identifier 不存在错误测试
- [ ] 6.6 添加 malformed typedData 错误测试

## 7. 文档

- [ ] 7.1 记录接口参数与返回格式
- [ ] 7.2 记录支持的 EIP-712 类型范围
