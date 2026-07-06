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

### 决策 4：EIP-712 编码优先采用开源 crate

**选择**：优先采用成熟开源 crate 实现 EIP-712 TypedData hash。当前优先评估：

- `alloy-dyn-abi`：运行时 ABI 与 EIP-712 实现，提供 `alloy_dyn_abi::eip712::TypedData` 与 `eip712_signing_hash()`，更贴合"调用方传入明文 TypedData JSON"的需求
- `ethers`/`ethers-core` 的 `types::transaction::eip712`：包含 `TypedData` / `Eip712` 相关能力；但 `ethers-core` 文档已提示该库在 deprecating，并建议使用 `utils`、`types`、`abi` re-export，因此不应直接依赖已废弃入口

**理由**：

- EIP-712 编码规则复杂，开源实现能降低自实现偏差风险
- 本接口接收运行时 JSON TypedData，优先选择能直接处理动态 TypedData 的 crate
- 选型需确认依赖体积、许可证、维护状态，以及是否兼容项目当前 Rust 工具链

**备选方案**：如果候选 crate 因许可证、依赖体积、Rust 版本或功能缺口不适合引入，再实现项目内最小 EIP-712 encoder。

### 决策 5：类型支持范围由 crate 选型确认

**选择**：第一版支持的 EIP-712 类型范围跟随最终选定 crate 的能力确定。

**理由**：

- 如果采用 `alloy-dyn-abi`，预期可以覆盖常见运行时 Solidity 类型、nested struct 与 EIP-712 hash
- 如果 crate 存在不支持的类型，应在接口文档和测试中明确列出，而不是隐式失败
- stake 首版所需字段以最终 TypedData 示例为准，但接口实现不应硬编码 stake 字段

### 决策 6：`v` 使用 ETH 兼容格式 27/28

**选择**：签名返回 `r || s || v`，其中 `v = recovery_id + 27`。

**理由**：

- 现有 `sign_authentication_message` 已采用该格式
- recoverable secp256k1 签名输出格式与现有身份认证签名保持一致

## 风险 / 权衡

**[EIP-712 crate 选型]** → 优先采用开源 crate，但需要确认候选 crate 的维护状态、许可证、依赖体积、Rust 版本要求，以及能否处理调用方传入的运行时 TypedData JSON。

**[类型支持范围]** → 最终支持的 EIP-712 类型范围取决于 crate 能力。需要用 EIP-712 官方样例和 stake 业务样例验证行为，文档中明确不支持的类型。

## 待确认事项

1. 最终采用哪个 EIP-712 crate，以及其支持的 TypedData 类型范围。
2. stake 业务用于联调和测试的 TypedData JSON 示例。
