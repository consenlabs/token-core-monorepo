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

### 决策 4：EIP-712 编码优先自实现小模块

**选择**：第一版建议在代码中实现 EIP-712 TypedData hash，而不是直接引入第三方 crate。

**理由**：

- 当前项目未引入 `ethers-core` / `alloy` / `ethabi`
- `ethers-core` 成熟但依赖较重
- `eip712_enc` 是专门 crate，但 docs 显示许可证为 GPL-3.0，不适合作为 SDK 依赖的默认选择
- 自实现可将依赖面控制在现有 `serde_json`、`ethereum-types`、`keccak256`

**保留选项**：如果 review 后认为完整 EIP-712 支持优先级高于依赖体积，可评估引入 `ethers-core` 的 `TypedData` hash 能力。

### 决策 5：第一版应尽量完整支持标准类型

**建议**：实现完整 EIP-712 常用类型：

- atomic：`address`、`bool`、`bytes1`-`bytes32`、`int8`-`int256`、`uint8`-`uint256`
- dynamic：`bytes`、`string`
- reference：nested struct
- arrays：定长和动态数组

**理由**：

- 只支持 stake 当前字段会让接口名和 EIP-712 语义不匹配
- EIP-712 编码最容易出错，后续补类型会带来兼容性风险

**可裁剪选项**：若实现周期必须压缩，第一版至少支持 `string`、`uint256`、`address`、nested struct，并明确数组与 bytes 类型暂不支持。

### 决策 6：`v` 使用 ETH 兼容格式 27/28

**选择**：签名返回 `r || s || v`，其中 `v = recovery_id + 27`。

**理由**：

- 现有 `sign_authentication_message` 已采用该格式
- recoverable secp256k1 签名输出格式与现有身份认证签名保持一致

## 风险 / 权衡

**[EIP-712 编码复杂度]** → `encodeType`、nested struct、array、bytes/int 处理容易出错。缓解：使用 EIP-712 官方样例和至少一个外部实现生成的测试向量交叉验证。

**[依赖选择]** → 自实现减少依赖但增加实现责任；第三方 crate 降低编码风险但增加依赖体积和许可证审查成本。

## 待确认事项

1. 第一版是否必须完整支持 EIP-712 arrays / bytes / signed int？
2. stake 绑定 xpub 的最终 TypedData schema。
