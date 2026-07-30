# tron-batch-tx-signing Specification

## Purpose
TBD - created by archiving change add-tron-batch-tx-signing. Update Purpose after archive.
## Requirements
### Requirement: TRON 交易批量签名入口

token-core 与 imkey-core SHALL 在本轮与 ETH 批签共同引入的 SDK 动作 `sign_txs` 中接受 `chainType = "TRON"`，一次调用接收至少一笔有序的 TRON 交易，并按输入顺序返回一一对应的签名结果。除首次支持的 `ETHEREUM` 与 `TRON` 之外，其他 chain type MUST 在鉴权或设备交互前返回 `sign_txs unsupported_chain`。

#### Scenario: token-core 通过通用入口批量签署 TRON 交易

- **WHEN** host 调用 `call_tcx_api("sign_txs")`，提交合法 keystore 凭证、`chainType = "TRON"` 和 N 个编码后的 `TronTxInput`
- **THEN** SDK 返回恰好 N 个 `SignTxsResult.Output`
- **AND** 输出顺序与输入顺序一致
- **AND** 整个调用只需要一份 password / derivedKey 凭证

#### Scenario: imkey-core 通过通用入口批量签署 TRON 交易

- **WHEN** host 调用 `call_imkey_api("sign_txs")`，提交 `chainType = "TRON"` 和包含 N 个合法 item 的 `tronapi.SignTxsInput`
- **THEN** SDK 返回恰好 N 个 `tronapi.SignTxsItemOutput`
- **AND** 输出顺序与输入顺序一致

#### Scenario: 未支持的 chain type 被拒绝

- **WHEN** host 使用 `sign_txs` 提交既不是 `ETHEREUM` 也不是 `TRON` 的 chain type
- **THEN** SDK 返回包含 `sign_txs unsupported_chain` 的错误
- **AND** token-core SHALL NOT 解锁 keystore
- **AND** imkey-core SHALL NOT 选择任何 applet

### Requirement: token-core 复用通用批签信封

token-core 的 ETH/TRON 批签 SHALL 共同使用 `SignTxsParam`、`SignTxsItem` 与 `SignTxsResult`。每个 TRON `SignTxsItem.input` MUST 是 protobuf 编码的 `transaction.TronTxInput`；每个成功输出 MUST 使用 `SignTxsResult.Output { signature, txHash, fromAddress }`，且后续不得改变首次定义的字段编号。由于 `txHash` 与 `fromAddress` 的取值格式按 `chainType` 不同（ETH 的 txHash 带 `0x` 前缀、地址为 EIP-55；TRON 的 txID 不带前缀、地址为 Base58Check），`api.proto` 中这两个字段的注释 MUST 显式说明按链解释。

#### Scenario: TRON input 从通用 bytes 字段解码

- **WHEN** `SignTxsParam.chainType` 为 `TRON`，且某个 item.input 是合法编码的 `TronTxInput { raw_data }`
- **THEN** token-core 使用该 `raw_data` 执行 TRON 单笔等价签名

#### Scenario: item input 无法解码

- **WHEN** 下标 i 的 item.input 不是合法的 `TronTxInput` protobuf
- **THEN** token-core 返回匹配 `sign_txs failed at index i` 的错误
- **AND** SHALL NOT 解锁 keystore
- **AND** SHALL NOT 返回任何批量输出

### Requirement: imkey-core 使用 TRON 链专属批量消息

imkey-core 的 `tronapi` SHALL 提供 `SignTxsInput`、`SignTxsItem`、`SignTxsItemOutput` 与 `SignTxsOutput`。每个输入 item MUST 携带一个 `TronTxInput`、`payment`、`receiver`、非空 `sender` 和可选 path；外层 `common.SignParam` MUST 继续承载默认 path 与 `chainType = "TRON"`。TRON item MUST NOT 定义 `fee` 字段，因为 TRON 单笔签名 APDU 不打包该值。为便于 host 复用字段映射，`tronapi` 的批量消息 SHALL 与 `ethapi` 的同名消息对齐公共字段编号：`SignTxsItem` 保留 tag 5（ETH 的 `fee`）不用、`path` 使用 tag 6；`SignTxsItemOutput` 的 `from_address` 使用 tag 2，TRON 特有的 `tx_hash` 使用 tag 3。

#### Scenario: 每笔展示和校验字段传入现有单签

- **WHEN** 某 item 的 `payment`、`receiver` 和 `sender` 分别为 host 提供的字符串
- **THEN** imkey-core 使用这些值和该 item 的 effective path 构造单笔 `SignParam`
- **AND** 现有 `TronSigner::sign_transaction` 使用 payment/receiver 构建设备展示数据并使用 sender 做地址校验

#### Scenario: 缺失交易或 sender

- **WHEN** 下标 i 的 item 不含 `tx` 或 `sender` 为空字符串
- **THEN** imkey-core 在选择 TRON applet 前返回匹配 `sign_txs failed at index i` 的错误
- **AND** SHALL NOT 返回任何批量输出

### Requirement: 批量签名与单笔签名等价

对任一合法 item，批量路径产生的签名 SHALL 与在相同引擎、相同交易、相同 effective path 以及相同显示/校验字段下调用一次现有 `sign_tx` 的结果完全一致。批量能力 MUST NOT 改变两个引擎各自既有的签名十六进制格式或 recovery-id 表示。

#### Scenario: token-core 批量签名等于逐笔签名

- **WHEN** 使用同一解锁后的 keystore 和同一 path 分别通过 TRON `sign_tx` 与 `sign_txs` 签署相同 raw_data
- **THEN** `SignTxsResult.Output.signature` 等于单笔 `TronTxOutput.signatures` 中唯一的签名

#### Scenario: imkey-core 批量签名等于逐笔签名

- **WHEN** 在相同设备绑定、TRON applet 状态、path、payment、receiver 和 sender 下分别通过 `sign_tx` 与 `sign_txs` 签署相同 raw_data
- **THEN** `SignTxsItemOutput.tx.signature` 与单笔 `TronTxOutput.signature` 完全相等

### Requirement: 共享 path 与逐笔 path 覆盖

两个引擎 SHALL 为每个 item 计算 effective path：item.path 非空时使用 item.path，否则使用外层默认 path。同一批次 MUST 允许部分 item 继承外层 path、部分 item 使用独立 path。任何 item 的 effective path 为空时 MUST 在解锁或设备交互前拒绝整批。

该拒绝行为是相对 TRON 单笔签名的刻意收紧：单笔 `sign_tx` 接受空 path（HD keystore 会回落到 BIP-32 master key `m` 并签名成功），批签不接受。因此 token-core 的私钥 keystore 批签请求也 MUST 携带非空且满足 TRON path 约束的 path（例如 `m/44'/195'/0'/0/0`）；该值对私钥 keystore 只用于通过校验，不参与密钥选择。集成文档 MUST 说明这一迁移要求。

#### Scenario: 所有 item 继承外层 path

- **WHEN** 外层 path 为 `m/44'/195'/0'/0/0` 且所有 item.path 为空
- **THEN** 所有交易使用 `m/44'/195'/0'/0/0` 对应的签名密钥
- **AND** 所有输出的 fromAddress 相同

#### Scenario: item path 覆盖外层 path

- **WHEN** 外层 path 为 `m/44'/195'/0'/0/0`，下标 1 的 item.path 为 `m/44'/195'/0'/0/1`
- **THEN** 下标 0 使用外层 path
- **AND** 下标 1 使用自身 path
- **AND** 两个输出的 fromAddress 分别对应各自 effective path

#### Scenario: effective path 为空

- **WHEN** 下标 i 的 item.path 和外层 path 均为空
- **THEN** SDK 返回同时包含 `failed at index i` 与 `empty derivation path` 的错误
- **AND** token-core SHALL NOT 解锁 keystore
- **AND** imkey-core SHALL NOT 选择 TRON applet

#### Scenario: path 非法

- **WHEN** 下标 i 的 effective path 不满足该引擎现有 TRON 单笔 path 约束（token-core：至少 4 层且 coin type 为 `195'`；imkey-core：`check_path_validity` 的层级范围）
- **THEN** SDK 在签名前返回匹配 `sign_txs failed at index i` 的 path 错误
- **AND** SHALL NOT 返回任何批量输出

#### Scenario: 私钥 keystore 必须显式给出 path

- **WHEN** host 用私钥 keystore 提交 TRON 批签请求，外层 path 与所有 item.path 均为空
- **THEN** SDK 在解锁前返回同时包含 `failed at index 0` 与 `empty derivation path` 的错误
- **WHEN** 同一请求把外层 path 改为 `m/44'/195'/0'/0/0`
- **THEN** 批量签名成功，且签名结果与该私钥 keystore 用单笔 `sign_tx` 签同一 `raw_data` 的结果相同

### Requirement: 每笔输出提供 signature、txID 与签名地址

每个成功输出 SHALL 包含单笔等价 signature、TRON txID 与本次签名密钥对应的 Base58Check from address。txID MUST 为 `raw_data` 解码字节的 SHA-256 小写十六进制，长度为 64 且不带 `0x`。token-core MUST 用签名所用的同一 keystore 和同一 effective path 取公钥派生 fromAddress；imkey-core 的 from_address MUST 等于已通过设备派生地址校验的 item.sender。

#### Scenario: txID 与 raw_data 对应

- **WHEN** 某 item 的 raw_data 解码为字节序列 R
- **THEN** 输出 txHash 等于 `hex_lower(SHA256(R))`
- **AND** txHash 不带 `0x` 前缀

#### Scenario: token-core HD keystore 返回 path 派生地址

- **WHEN** token-core 用 HD keystore 成功签署使用 effective path P 的 item
- **THEN** 输出 fromAddress 等于该 keystore 在 P 上的 secp256k1 公钥转换出的 TRON Base58Check 地址

#### Scenario: token-core 私钥 keystore 返回私钥对应地址

- **WHEN** token-core 用私钥 keystore 成功签署一批 item
- **THEN** 每个输出的 fromAddress 都等于该私钥对应的 TRON Base58Check 地址
- **AND** 该地址不随各 item 的 effective path 变化

#### Scenario: imkey-core 返回设备核验地址

- **WHEN** imkey-core 成功签署 sender 与设备在 effective path 上派生地址一致的 item
- **THEN** 输出 from_address 等于 item.sender

#### Scenario: sender 与设备派生地址不一致

- **WHEN** 下标 i 的 item.sender 与设备在其 effective path 上派生的地址不一致
- **THEN** imkey-core 返回匹配 `sign_txs failed at index i` 的错误
- **AND** SHALL NOT 返回任何批量输出

### Requirement: 有序且 all-or-nothing 的错误语义

批量 SHALL 按输入顺序同步处理。若任意 item 在校验、派生、地址核验或签名阶段失败，整个调用 MUST 返回错误且不得返回任何部分输出；与 item 关联的错误 MUST 使用 `sign_txs failed at index {i}: {source}`，其中 i 为零基输入下标。

批级错误（空批量、超过上限）不关联任何 item，因此 MUST NOT 带下标，两个引擎 MUST 使用相同文案：空批量为 `sign_txs batch is empty`，超限为 `sign_txs batch exceeds max size of {max}`。

#### Scenario: 中间 item 的 raw_data 非法

- **WHEN** 批量中下标 0 合法、下标 1 的 raw_data 不是合法十六进制、下标 2 合法
- **THEN** SDK 返回匹配 `sign_txs failed at index 1` 的错误
- **AND** SHALL NOT 对调用方返回下标 0 的签名
- **AND** 所有静态输入校验 SHALL 在任何签名操作前完成

#### Scenario: 硬件用户在中间 item 拒绝签名

- **WHEN** imkey 用户确认前若干笔，但在下标 i 拒绝设备签名
- **THEN** imkey-core 返回匹配 `sign_txs failed at index i` 的错误
- **AND** 已在内存中生成的前缀签名 SHALL 被丢弃
- **AND** SHALL NOT 返回部分 `SignTxsOutput`

#### Scenario: 非单调交易序列保持顺序

- **WHEN** 输入 raw_data 对应的 txID 顺序为非单调序列 `[A, C, B]`
- **THEN** 输出 txHash 顺序 SHALL 为 `[A, C, B]`

### Requirement: 批量上限

token-core 的 `TRON_MAX_BATCH_SIZE` MUST 为 2048，imkey-core 的 `TRON_MAX_BATCH_SIZE` MUST 为 100；两端 MUST 使用各自独立的具名常量。超过上限的请求 SHALL 在 keystore 解锁或 TRON applet 选择前被拒绝。

#### Scenario: token-core 拒绝超限批量

- **WHEN** token-core 收到 2049 个 item
- **THEN** 请求返回 `sign_txs batch exceeds max size of 2048`
- **AND** keystore SHALL NOT 被解锁

#### Scenario: imkey-core 拒绝超限批量

- **WHEN** imkey-core 收到 101 个 item
- **THEN** 请求返回 `sign_txs batch exceeds max size of 100`
- **AND** TRON applet SHALL NOT 被选择

#### Scenario: 空批量

- **WHEN** 任一引擎收到零个 item
- **THEN** SDK 返回 `sign_txs batch is empty`
- **AND** SHALL NOT 执行鉴权、设备交互或签名

### Requirement: 鉴权和硬件交互与现有单笔能力对齐

token-core TRON 批签 MUST 接受 `SignTxsParam` 共同定义的 password 或 derivedKey 鉴权，并在整批中最多解锁一次。imkey-core MUST 要求与单笔 TRON `sign_tx` 相同的设备绑定和 applet 前置条件（未绑定设备返回与单笔一致的绑定错误），并 SHALL 对每个 item 完整调用现有 `TronSigner::sign_transaction`，不得在批量层缓存 applet 选择、xpub 或用户确认。

#### Scenario: token-core 使用 password 或 derivedKey

- **WHEN** host 提供正确 password 或正确 derivedKey
- **THEN** token-core 在一次解锁后顺序签署全部 item
- **WHEN** 凭证错误
- **THEN** SDK 返回与现有单笔签名一致的鉴权错误
- **AND** SHALL NOT 签署任何 item

#### Scenario: imkey-core 每笔都需要设备确认

- **WHEN** imkey-core 批量包含 N 个合法 item
- **THEN** 用户 SHALL 在设备上确认 N 次才能拿到全部输出
- **AND** 批量层 SHALL NOT 假设固件支持一次确认多笔交易

### Requirement: 向后兼容

同一分支首次引入的 ETH/TRON 批签 MUST 是相对于既有单笔 API 的纯增量变更。TRON 批签路径 MUST NOT 改变同批交付的 ETH `sign_txs` 契约，也 MUST NOT 改变既有 TRON `sign_tx`、TRON `sign_message` 及其 protobuf 字段编号和编码。

#### Scenario: ETH 与 TRON 批签契约相互独立

- **WHEN** host 使用 `chainType = "ETHEREUM"` 调用同批交付的 `sign_txs`
- **THEN** 请求由 ETH 输入类型解释并进入 ETH 批签路径
- **AND** TRON 分支 SHALL NOT 改变 ETH 的签名、txHash、fromAddress 或编码契约

#### Scenario: 旧 TRON 单笔调用方继续可用

- **WHEN** 旧 host 继续调用 TRON `sign_tx` 或 `sign_message`
- **THEN** SDK 的请求解析、签名格式、错误与输出保持不变
