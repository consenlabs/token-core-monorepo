## ADDED Requirements

### Requirement: ETH 交易批量签名入口

两个签名引擎 SHALL 各自暴露一个 SDK 动作，接受任意 N 笔（其中 N ≥ 1）有序的 ETH 交易输入列表，并按相同顺序返回对应的已签名交易。N 的合法上界由各引擎的批量上限 Requirement 单独约束，不限定具体业务场景：N 既可以是少量（如 staking 流程的 prepay + stake 两笔、合约批量 approve 数笔），也可以是数十乃至上百笔（如批量空投、归集出账、dApp 一次性下发的多笔 meta-tx）。该动作 SHALL 在 `call_tcx_api`（token-core）与 `call_imkey_api`（imkey-core）中均命名为 `eth_batch_sign_tx`。

#### Scenario: token-core 在一次解锁内完成 N 笔批量签名

- **WHEN** host 通过 `call_tcx_api` 以 `eth_batch_sign_tx` 方法发送一个包含合法 keystore `id`、`password`（或 `derivedKey`）、外层 HD `path`、`chainType` 为 `ETHEREUM`、以及 N 个 `EthBatchSignTxItem`（N 取自 `{1, 2, 50, 256, 2048}` 这一组覆盖少量 / 中量 / 上限的代表值；item.path 均为空；item 内交易的 `tx_type` 可同可不同，例如混合 legacy 与 EIP-1559）的请求
- **THEN** 响应 SHALL 按相同顺序包含恰好 N 个 `EthTxOutput`，每个 `signature` 解码后为有效的已签名以太坊交易，每个 `tx_hash` 与该交易规范编码的 keccak256 一致
- **AND** keystore SHALL 在整批执行过程中至多解锁一次

#### Scenario: token-core 大批量签名（数十至上百笔）保持单次解锁

- **WHEN** host 在 token-core 上提交 100 笔合法批量请求，每笔 nonce 严格递增（这模拟了批量空投、归集等 dApp / 后台批处理场景）
- **THEN** 响应 SHALL 按输入顺序返回 100 个 `EthTxOutput`
- **AND** 解码后第 i 个交易（0 ≤ i < 100）的 nonce SHALL 等于第 i 个输入的 nonce
- **AND** keystore SHALL 在整批执行过程中只解锁 1 次

#### Scenario: imkey-core 通过对每个 item 复用单笔 sign 流程完成 N 笔批量签名

- **WHEN** host 通过 `call_imkey_api` 以 `eth_batch_sign_tx` 方法发送一个包含 `chainType` 为 `ETHEREUM`、外层 `SignParam.path`、以及 N 个 `EthBatchTxItem`（N 取自 `{1, 2, 10, 50, 100}` 这一组覆盖少量到上限的代表值）的请求，且每笔交易随附其 `payment`、`receiver`、`sender`、`fee` 显示字符串
- **THEN** 响应 SHALL 按输入顺序包含恰好 N 个 `EthTxOutput`，其 `signature` 解码后为有效的已签名以太坊交易、`tx_hash` 与该交易的规范哈希一致
- **AND** 对每个 item，批量动作的执行 SHALL 等价于以该 item 的有效 path（item.path 非空时优先；否则回落到外层 `SignParam.path`）与该 item 的 `payment` / `receiver` / `sender` / `fee` 调用一次现有单笔 `sign_tx`：完整的 `select_applet` / `prepare_sign` / `get_xpub` / 地址校验 / `sign_digest` / 用户在设备屏上的物理确认 SHALL 对每笔输入交易各发生一次（不假设固件改造，不在批量层做任何 device-session 优化）

#### Scenario: imkey-core 批量每笔输出与单笔 sign_tx 在相同上下文下逐字节相同

- **WHEN** 用 `eth_batch_sign_tx` 对一个含 N 个 item 的请求成功完成签名
- **AND** 在相同设备绑定、相同 ETH applet 状态、相同 path 与显示字符串下分别对每个 item 调用一次现有单笔 `sign_tx`
- **THEN** 两条路径在每个下标位置上得到的 `EthTxOutput.signature` 与 `EthTxOutput.tx_hash` SHALL 完全相等

### Requirement: 与单笔 sign_tx 的输入对等

批量动作 SHALL 接受当前单笔 `sign_tx` 所支持的全部 ETH 交易形态，包括 legacy（type 0）、EIP-2930 风格 access list、以及 EIP-1559（`tx_type == "0x02"`，含 `max_fee_per_gas` / `max_priority_fee_per_gas`）。对任意一笔输入，批量路径生成的签名输出 SHALL 与在相同签名上下文中调用一次 `sign_tx` 得到的输出逐字节相同。

#### Scenario: legacy 与 EIP-1559 混合批量与逐笔调用结果一致

- **WHEN** 通过 `eth_batch_sign_tx` 对 `[legacy_tx, eip1559_tx]` 进行批量签名
- **AND** 在相同 keystore、相同密码、相同派生路径下分别用 `sign_tx` 各签一次
- **THEN** 两条路径在每个下标位置上得到的 `signature` 与 `tx_hash` SHALL 完全相等

#### Scenario: access list 字段被保留

- **WHEN** 批量输入中存在某个 `EthTxInput` 包含非空 `access_list`
- **THEN** 该 access list SHALL 被原样 RLP 编码进对应的已签名交易

### Requirement: 每笔 path 可独立覆盖外层 path

批量请求 SHALL 同时支持"整批共享同一 path"与"每笔指定独立 path"两种使用方式。每个 item 包含一个可选的 `path` 字段：当该字段为空字符串时，签名引擎 SHALL 使用外层 `path`（`tcx`：`EthBatchSignTxParam.path`；`ikc`：`SignParam.path`）；当该字段非空时，签名引擎 SHALL 使用该 item 自带的 `path` 进行派生与签名。同一批中允许部分 item 留空、部分 item 自带 `path`。

#### Scenario: 整批共享外层 path

- **WHEN** 提交一个包含三个 item 的批量请求，每个 item 的 `path` 均为空字符串，外层 `path` 为 `m/44'/60'/0'/0/0`
- **THEN** 三笔交易 SHALL 全部使用 `m/44'/60'/0'/0/0` 派生出的私钥进行签名
- **AND** 解码三笔已签名交易得到的 `from` 地址 SHALL 全部相同

#### Scenario: 每笔使用独立 path

- **WHEN** 提交一个包含三个 item 的批量请求，外层 `path` 为 `m/44'/60'/0'/0/0`，三个 item 的 `path` 分别为 `m/44'/60'/0'/0/0`、`m/44'/60'/0'/0/1`、`""`
- **THEN** 第一、第二笔 SHALL 分别按其 item.path 派生签名，第三笔 SHALL 回落到外层 `path` 进行签名
- **AND** 解码三笔已签名交易得到的 `from` 地址 SHALL 与上述三个有效 path 各自派生出的地址一致

#### Scenario: 非法 item.path 在签名前被拒

- **WHEN** 提交一个 item 的 `path` 字符串不符合 BIP-32 派生格式
- **THEN** 该动作 SHALL 返回错误，错误信息包含失败 item 的下标
- **AND** 不 SHALL 返回任何 `EthTxOutput`

### Requirement: 全成功或全失败的原子语义与错误下标

批量动作 SHALL 采用 all-or-nothing 语义。若任意一笔输入在校验、派生或签名阶段失败，该动作 SHALL 中止整批、不返回任何部分签名结果，并通过与 `sign_tx` / `eth_batch_personal_sign` 相同的字符串错误返回路径抛出错误。该错误信息 SHALL 形如 `"eth_batch_sign_tx failed at index {i}: {source}"`，其中 `{i}` 为失败 item 的零基下标，`{source}` 为底层错误原文。

#### Scenario: 非法 `to` 导致整批中止

- **WHEN** 批量请求中第一笔合法、第二笔的 `to` 为非法地址
- **THEN** 该动作 SHALL 返回错误
- **AND** 错误信息 SHALL 匹配正则 `failed at index 1`
- **AND** 不 SHALL 向调用方返回任何 `EthTxOutput`

#### Scenario: 拒绝空批量

- **WHEN** 提交一个不含任何 item 的批量请求
- **THEN** 该动作 SHALL 返回错误，提示批量为空
- **AND** SHALL 不返回任何签名

### Requirement: 不同引擎不同的批量上限

每个引擎 SHALL 根据自身资源约束设置批量上限：`token-core` 的上限 SHALL 为 2048（软件签名，仅受内存与单次 FFI 时长约束）；`imkey-core` 的上限 SHALL 为 100（硬件签名，每笔仍需用户在设备上按确认；100 为协议层硬上限，旨在为 stake / 合约批量 approve 等典型业务流留出余量，host 业务层应根据具体 UX 进一步收紧实际允许的笔数）。每个上限 SHALL 以单一具名常量定义在对应引擎的 handler 同位置，便于在不变更协议的前提下调整。任何超过对应引擎上限的请求 SHALL 在解锁 / 选择 applet 之前被拒绝。

#### Scenario: token-core 接受 2048 笔但拒绝 2049 笔

- **WHEN** 在 token-core 上提交 2048 笔合法批量请求
- **THEN** 该动作 SHALL 返回 2048 个 `EthTxOutput`，顺序与输入一致
- **WHEN** 在 token-core 上提交 2049 笔批量请求
- **THEN** 该动作 SHALL 返回错误，提示批量超过上限 2048
- **AND** keystore SHALL 不被解锁

#### Scenario: imkey-core 接受 100 笔但拒绝 101 笔

- **WHEN** 在 imkey-core 上提交 101 笔批量请求
- **THEN** 该动作 SHALL 返回错误，提示批量超过上限 100
- **AND** imKey ETH applet SHALL 不被 select

### Requirement: 与单笔 sign_tx 的鉴权对等

token-core 批量动作 SHALL 接受与现有单笔 `sign_tx` 和 `eth_batch_personal_sign` 相同的鉴权方式（`password` 或 `derivedKey` 二选一），并在两者均缺失或凭证错误时返回相同的错误。imkey-core 批量动作 SHALL 要求与单笔 `sign_tx` 相同的设备绑定前置条件（设备已绑定、ETH applet 存在）。

#### Scenario: 错误密码导致批量被拒

- **WHEN** host 提交批量请求时携带的 `password` 错误
- **THEN** 该动作 SHALL 返回与 `sign_tx` 相同的鉴权错误
- **AND** SHALL 不对任何输入执行签名

#### Scenario: 未绑定的 imKey 拒绝批量

- **WHEN** 在设备未绑定的状态下调用 imkey-core 的 `eth_batch_sign_tx`
- **THEN** 该动作 SHALL 返回与单笔 `sign_tx` 相同的设备绑定错误

### Requirement: imKey 每笔 payment/receiver/sender/fee 由 host 提供

imkey-core 路径下，每个 `EthBatchTxItem` SHALL 由 host 显式提供 `payment`、`receiver`、`sender`、`fee` 四个字符串字段，语义与现有 `SignParam` 中同名字段完全一致：`payment` / `receiver` / `fee` 用于设备屏幕展示，`sender` 用于在签名前与本批次有效 path 派生出的地址做校验，校验不通过则中止整批。SDK SHALL NOT 自动从 `EthTxInput` 派生这四个字段。

#### Scenario: sender 与有效 path 派生地址不一致即中止

- **WHEN** 某 item 的有效 path 派生出的地址为 `0xAAA...`，但其 `sender` 字段为 `0xBBB...`
- **THEN** 该动作 SHALL 返回错误（与单笔 `sign_tx` 在 `address_checksummed != *sender` 时返回的同一错误）
- **AND** 错误信息 SHALL 包含失败 item 的下标
- **AND** 不 SHALL 返回任何已签名交易

#### Scenario: payment / receiver / fee 原样写入设备 prompt

- **WHEN** 某 item 的 `payment` 为 `"0.01 ETH"`、`receiver` 为 `"0xE6F4...931F3"`、`fee` 为 `"0.0032 ether"`
- **THEN** 设备的 `prepare_sign` apdu 数据包中 TLV(7) / TLV(8) / TLV(9) 段 SHALL 严格按这三个字符串原样填充

### Requirement: 输出顺序与可观测性

输出数组 SHALL 按下标与输入数组逐一对应。每个输出条目的 `signature`（已签名交易原始字节的十六进制编码）与 `tx_hash`（带 `0x` 前缀的规范编码 keccak256）字段语义 SHALL 与现有 `EthTxOutput` 一致。

#### Scenario: 顺序在 FFI 边界上保持稳定（少量批次）

- **WHEN** 批量签名三笔 nonce 分别为 `[7, 8, 9]` 的交易
- **THEN** 返回的输出解码后得到的 nonce SHALL 依次为 `[7, 8, 9]`

#### Scenario: 顺序在大批次下也保持稳定

- **WHEN** 批量签名 N 笔 nonce 为非单调序列（例如来自不同业务流的 `[100, 5, 42, 7, ...]`，N 取 64）的交易
- **THEN** 返回的输出第 i 个解码后的 nonce SHALL 等于第 i 个输入的 nonce，对所有 0 ≤ i < N 成立

### Requirement: 与既有单笔 API 的向后兼容

引入批量动作 SHALL 仅作为增量改动。两个引擎现有的 `sign_tx` 动作及 `EthTxInput` / `EthTxOutput` 结构 SHALL 保持不变。

#### Scenario: 仅了解 sign_tx 的旧调用方继续可用

- **WHEN** 仅了解 `sign_tx` 的旧版 host 在批量动作上线后仍调用 `sign_tx`
- **THEN** 行为、编码与输出 SHALL 与本次变更前逐字节一致
