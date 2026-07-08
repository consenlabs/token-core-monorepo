## 背景

token-core 目前已有基于 identity auth key 的固定认证消息签名接口。stake xpub 绑定场景需要签署结构化业务数据，因此新增接口应复用现有 auth key 解锁与签名能力，并将待签 payload 改为 EIP-712 TypedData digest。

新接口需要签的是调用方传入的 EIP-712 TypedData 明文对应的标准 digest：

```text
keccak256("\x19\x01" || domainSeparator || hashStruct(message))
```

## 目标 / 非目标

**目标：**

- 提供 `sign_typed_data_with_auth_key` API
- 调用方传入明文 EIP-712 TypedData JSON
- token-core 内部完成 TypedData 解析、编码、哈希
- 使用 `identifier` 对应的 auth key 对 digest 做 secp256k1 recoverable 签名
- 输出 65 字节 `0x` hex 签名
- 添加 EIP-712 官方样例测试，避免编码实现偏离规范

**非目标：**

- 不实现 UI 展示与用户确认
- 不改变 account 私钥或链交易签名路径
- 不使用派生路径 account key 签名
- 不支持硬件钱包 applet 签名路径

## API 设计

新增 protobuf：

```protobuf
message SignTypedDataWithAuthKeyParam {
  string identifier = 1;
  string typedData = 2;
  oneof key {
    string password = 3;
    string derivedKey = 4;
  }
}

message SignTypedDataWithAuthKeyResult {
  string identifier = 1;
  string signature = 2;
}
```

### 参数说明

- `identifier`：要证明持有权的 identity identifier
- `typedData`：明文 EIP-712 JSON 字符串，包含 `types`、`primaryType`、`domain`、`message`
- `password` / `derivedKey`：用于解锁 keystore crypto，解密 `encAuthKey`

### 返回说明

- `signature`：65 字节 recoverable secp256k1 签名，`0x` hex 编码，字节顺序为 `r || s || v`，`v = recovery_id + 27`

## EIP-712 处理流程

TypedData JSON 结构：

```json
{
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" },
      { "name": "verifyingContract", "type": "address" }
    ],
    "BindStakeXpub": [
      { "name": "identifier", "type": "string" },
      { "name": "xpub", "type": "string" }
    ]
  },
  "primaryType": "BindStakeXpub",
  "domain": {
    "name": "imToken Stake",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000"
  },
  "message": {
    "identifier": "im...",
    "xpub": "..."
  }
}
```

处理步骤：

1. JSON 解析并校验必要字段
2. 计算 `domainSeparator = hashStruct(EIP712Domain)`
3. 计算 `messageHash = hashStruct(primaryType message)`
4. 计算 `digest = keccak256("\x19\x01" || domainSeparator || messageHash)`
5. 使用 auth key 签名 `digest`

## 技术决策

### 决策 1：token-core 内部计算 EIP-712 digest

**选择**：调用方只能传明文 TypedData JSON，不能直接传 digest。

**理由**：

- 需求明确要求 token-core 内部执行 `sign(keccak256(...))`
- 避免调用方传错 hash 或传入非 EIP-712 hash
- 有利于后续审计和测试

### 决策 2：签名使用 auth key，不使用 account key

**选择**：通过 `identifier` 找到 keystore，解密 `identity.encAuthKey` 签名。

**理由**：

- 该接口证明对象是 `identifier` 持有者
- stake 业务要将 `xpub` 绑定到 identity 下，不是证明某个 ETH 地址或派生路径地址
- auth key 与 identifier 存在可验证的派生关系

### 决策 3：接口只使用 identifier 定位 keystore

**选择**：请求参数不包含 keystore `id`，只通过 `identifier` 在当前加载的 keystore 中查找目标 identity。

**理由**：

- 现有 `sign_authentication_message` 已采用相同方式
- `identifier` 是该接口的证明对象，接口语义更直接
- 正常导入流程会按 source fingerprint 识别已存在 keystore，不预期同一 identity 重复加载

### 决策 4：EIP-712 编码采用 `alloy-dyn-abi 1.6.0`

**选择**：采用 `alloy-dyn-abi = 1.6.0` 实现 EIP-712 TypedData hash。

实现入口使用 `alloy_dyn_abi::eip712::TypedData` 解析调用方传入的运行时 TypedData JSON，并调用 `eip712_signing_hash()` 生成标准 digest。依赖配置使用 `default-features = false`，开启 `std` 与 `eip712` feature。

**理由**：

- EIP-712 编码规则复杂，开源实现能降低自实现偏差风险
- 本接口接收运行时 JSON TypedData，优先选择能直接处理动态 TypedData 的 crate
- `ethers-core` 已处于 deprecating 过程，不适合作为新功能的直接依赖入口
- `alloy-dyn-abi` 属于 alloy 生态，维护状态更适合作为新实现基础

**工具链影响**：

- `alloy-dyn-abi 1.6.0` 需要 Rust 1.85 级别工具链
- 当前项目仍使用 `#![feature(test)]`，因此工具链升级为 `nightly-2024-11-28`
- 依赖求解后需要同步升级部分基础依赖，并在 `Cargo.lock` 中锁定兼容当前工具链的 transitive dependency 版本

### 决策 5：类型支持范围跟随 `alloy-dyn-abi 1.6.0`

**选择**：第一版支持的 EIP-712 类型范围跟随 `alloy-dyn-abi 1.6.0` 的运行时 TypedData 能力确定。

**理由**：

- `alloy-dyn-abi` 覆盖常见运行时 Solidity 类型、nested struct 与 EIP-712 hash
- 如果 crate 存在不支持的类型，应返回明确的 typed data 校验错误，而不是隐式签名错误 digest
- stake 首版所需字段以最终 TypedData 示例为准，但接口实现不应硬编码 stake 字段

### 决策 6：`v` 使用 ETH 兼容格式 27/28

**选择**：签名返回 `r || s || v`，其中 `v = recovery_id + 27`。

**理由**：

- 现有 `sign_authentication_message` 已采用该格式
- recoverable secp256k1 签名输出格式与现有身份认证签名保持一致

## 风险 / 权衡

**[依赖与工具链升级]** → `alloy-dyn-abi 1.6.0` 引入 alloy 生态依赖，并要求 Rust 1.85 级别工具链。项目需要同步升级到 `nightly-2024-11-28`，同时更新部分基础依赖版本以通过新 Cargo 的依赖求解与编译检查。

**[transitive dependency 版本]** → alloy 依赖链中的部分 transitive dependency 最新版本可能要求更高 Rust 版本，当前实现需要在 `Cargo.lock` 中固定兼容当前工具链的版本。

**[类型支持范围]** → 支持范围跟随 `alloy-dyn-abi 1.6.0`。需要用 EIP-712 官方样例和 stake 业务样例验证行为，不支持或非法的 TypedData 应返回明确错误。

## 待确认事项

1. stake 业务用于联调和测试的最终 TypedData JSON 示例。
