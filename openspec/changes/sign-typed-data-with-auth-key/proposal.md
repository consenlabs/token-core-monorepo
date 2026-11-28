## 为什么要做

stake 业务需要把某个 `xpub` 关联到某个 `identifier` 下，以便业务方能够按 `identifier` 聚合展示该身份下所有 account 的 stake 信息。为了确认这次关联确实由 `identifier` 的持有者授权，需要 token-core 提供一个基于身份 auth key 的结构化数据签名接口。

当前 token-core 已有 `sign_authentication_message`，它使用 `identity.encAuthKey` 解密出的 auth key 对固定格式认证消息签名。但该接口只适合登录/认证类固定 payload，不适合 stake 这类需要携带 `xpub` 等业务字段的授权场景。

因此需要新增 `sign_typed_data_with_auth_key`：

1. 调用方传入明文 EIP-712 TypedData JSON
2. token-core 内部按 EIP-712 计算 `keccak256("\x19\x01" || domainSeparator || hashStruct(message))`
3. token-core 使用 `identifier` 对应 keystore 的 auth key 签名该 digest

该接口证明的是："某个 `identifier` 的持有者签署了这段结构化业务数据"。

## 变更内容

- 新增 `sign_typed_data_with_auth_key` protobuf API，入参包含 `identifier`、`typedData`、password 或 derivedKey
- 新增基于 `alloy-dyn-abi 1.6.0` 的 EIP-712 TypedData JSON 解析与哈希能力
- 新增 auth key typed data 签名实现，复用现有 `identity.encAuthKey` 解密流程
- 输出 65 字节 recoverable secp256k1 签名的 `0x` hex 字符串，其中 `v = recovery_id + 27`
- 添加 EIP-712 官方样例与接口集成测试；最终 stake 业务样例待业务方确认后补充

## 能力清单

### 新增能力

- `auth-key-typed-data-signing`：通过 `identifier` 找到本地 keystore，解密 auth key，对明文 EIP-712 TypedData 的 digest 进行签名

## 影响范围

- **Protobuf API**：`token-core/tcx-proto/src/api.proto` 新增请求与返回消息
- **tcx RPC 分发**：`token-core/tcx/src/lib.rs` 新增 `sign_typed_data_with_auth_key` method
- **tcx handler**：`token-core/tcx/src/handler.rs` 新增业务 handler
- **tcx-keystore**：建议在 `Identity` 上新增 auth key 签任意 32-byte digest 的内部方法，避免 handler 直接操作 `encAuthKey`
- **EIP-712 hashing**：在 `tcx` handler 层接入 `alloy_dyn_abi::eip712::TypedData`，由 token-core 内部计算 EIP-712 signing hash
- **依赖与工具链**：引入 `alloy-dyn-abi 1.6.0` 后，工具链升级到 Rust 1.85 级别的 nightly，并同步更新受影响的基础依赖锁定版本

## 非目标

- 不改变现有 `sign_authentication_message`
- 不要求 imKey 硬件钱包支持该接口；auth key 是 token-core identity key，不是硬件 applet 派生路径签名
- 不签任意预哈希 typed data；调用方必须传明文 TypedData JSON，由 token-core 内部计算 digest

## 待确认问题

1. **stake 业务 TypedData 示例**：最终由产品/业务方提供用于联调和测试的 TypedData JSON 示例。

## 上线策略

本次按 OpenSpec 提案实现，按 tasks 分步提交：

1. 先实现 EIP-712 hash 并用官方测试向量锁定行为
2. 再接入 auth key 签名接口
3. 最后补充 stake 业务样例和集成测试
