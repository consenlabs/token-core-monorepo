## Context

本轮批量签名工作在同一分支中为 ETH 与 TRON 首次共同引入链无关动作 `sign_txs`。两条链共享动作名和路由原则，各自保留链专属的交易输入、输出与签名流程：

- `token-core` 共同定义的 `SignTxsParam` 使用 `chainType` 路由，`SignTxsItem.input` 是链专属交易消息的编码字节，`SignTxsResult.Output` 统一返回 `signature`、`txHash` 与 `fromAddress`；首次实现同时路由 `ETHEREUM` 与 `TRON`。
- `imkey-core` 共同定义 `"sign_txs"` dispatcher，使用外层 `common.SignParam` 路由，内层 `input` 与输出由各 coin 的 protobuf 包定义；首次实现同时提供 ETH 与 TRON 分支。

TRON 单笔软件签名由 `tcx-tron` 的 `Keystore::sign_transaction` 完成：解码 `TronTxInput.raw_data`，计算 SHA-256，再用 effective path 做 recoverable secp256k1 签名。TRON 单笔硬件签名由 `coin_tron::signer::TronSigner::sign_transaction` 完成：校验 path、构建展示 TLV、选择 TRON applet、获取设备公钥并校验 sender、发送签名 APDU，最后返回单个签名。

本设计描述首次交付中的 TRON 部分，并与 ETH 提案共同确定上述通用 `sign_txs` 信封。两个引擎保持各自既有单笔签名编码和错误体系，ETH/TRON 批签则在同一分支中一起交付。

## Goals / Non-Goals

**Goals:**

- 让 `call_tcx_api` 与 `call_imkey_api` 的同一动作 `sign_txs` 接受 `chainType = "TRON"`。
- 保证批量输出与使用相同上下文逐笔调用 `sign_tx` 的签名完全一致，并保持输入顺序。
- token-core 整批只解锁一次；imkey-core 只减少 FFI 往返，不改变每笔设备交互。
- 支持外层共享 path 和逐 item path 覆盖；所有 effective path 必须非空。
- 输出每笔 TRON txID 和设备/SDK 已核验的签名地址，供 host 做交叉校验。
- 所有可静态发现的输入错误在解锁或设备交互之前完成整批预检。
- 失败时不编码或返回任何部分结果，并稳定报告失败 item 下标。

**Non-Goals:**

- 不修改 ETH `sign_txs`、TRON `sign_tx` 或 `sign_message` 的请求、响应或行为。
- 不实现 TRON 消息批签、多签签名聚合、自动追加已有 signatures 或交易广播。
- 不修改 imKey 固件、TRON applet 或 APDU 协议，也不缓存 applet/xpub/device session。
- 不引入异步、流式或可恢复的部分批量接口。
- 不在本变更中生成移动端高级封装；只同步后续实现所必需的 protobuf 生成物和文档。

## Decisions

### 1. ETH/TRON 共同建立 `sign_txs`，不新增链专属 dispatcher 动作

token-core 首次实现的 handler 按 `SignTxsParam.chain_type` 分派：

- `ETHEREUM` 解码 ETH 输入并进入 ETH 批签路径。
- `TRON` 解码每个 `SignTxsItem.input` 为 `transaction.TronTxInput`，进入 TRON 批签路径。
- 其他值继续返回 `sign_txs unsupported_chain`，且不解锁 keystore。

imkey-core 的 `"sign_txs"` dispatcher 在首次实现中同时注册 `ETHEREUM` 与 `TRON => tron_signer::sign_txs(...)`。这样 host 只需要一个批签动作，并由 chain type 决定请求体和响应体。

**替代方案：** 分别新增 `eth_batch_sign` 与 `tron_batch_sign` 动作。该方案隔离更强，但会在首次实现时形成两套入口并增加 host 分支，因此不采用。

### 2. token-core 复用通用请求和输出

token-core 不新增顶层批签 protobuf：

```proto
SignTxsParam {
  id, password/derivedKey, chainType = "TRON",
  path, network, segWit,
  repeated SignTxsItem items
}

SignTxsItem {
  bytes input; // encoded transaction.TronTxInput
  string path; // empty means inherit SignTxsParam.path
}

SignTxsResult.Output {
  string signature;
  string txHash;
  string fromAddress;
}
```

后续实现只把 proto 注释从 ETH 专属说明改为按链解释，不改字段编号。TRON 每个单笔 signer 当前只产生一个新签名，因此 `Output.signature` 取单笔 `TronTxOutput.signatures` 中唯一元素；若内部返回数量不是 1，批量路径按对应下标返回内部一致性错误。

`txHash` 定义为 `hex_lower(SHA256(hex_decode(raw_data)))`，长度固定为 64 且不带 `0x`，与 TRON txID 约定一致。注意 ETH 分支在同一字段返回带 `0x` 前缀的 keccak256，所以 `Output.txHash` 是按 `chainType` 解释的字段，`api.proto` 的注释必须写明这一点，避免 host 跨链统一处理时踩坑。`fromAddress` 使用同一 effective path 取得 secp256k1 公钥，再通过 `tcx_tron::TronAddress::from_public_key` 生成 Base58Check 地址；对私钥 keystore 该地址由私钥本身决定，与 path 无关。

### 3. imkey-core 使用 TRON 包内的链专属 body

在 `imkey-core/ikc-proto/src/tron.proto` 追加：

```proto
message SignTxsInput {
  repeated SignTxsItem items = 1;
}

message SignTxsItem {
  TronTxInput tx = 1;
  string payment = 2;
  string receiver = 3;
  string sender = 4;
  reserved 5;          // ethapi.SignTxsItem 的 fee，TRON 不使用
  string path = 6;
}

message SignTxsItemOutput {
  TronTxOutput tx = 1;
  string from_address = 2;
  string tx_hash = 3;
}

message SignTxsOutput {
  repeated SignTxsItemOutput outputs = 1;
}
```

外层 `common.SignParam` 继续携带 `chainType = "TRON"`、默认 path、network 和其他通用字段。TRON applet 当前只使用 `payment`、`receiver` 和 `sender`，因此这些值必须放到每个 item；`fee` 不进入 TRON 单笔 APDU，不在 item 中新增一个无行为字段。

字段编号刻意与 `ethapi` 的同名消息对齐：`ethapi.SignTxsItem` 已经把 `fee` 占在 tag 5、`path` 占在 tag 6，所以 TRON 保留 tag 5 不用而把 `path` 放到 tag 6；`ethapi.SignTxsItemOutput` 的 `from_address` 是 tag 2，TRON 也放 tag 2，TRON 特有的 `tx_hash` 追加在 tag 3。两个消息位于不同 package（`ethapi` / `tronapi`）、由 `ikc-proto/build.rs` 生成到不同 crate，本来不会冲突；对齐的目的是让 host 侧复用同一段字段映射代码时不会因为 tag 错位而写出静默错误。

`SignTxsItemOutput` 保留 `tx` 这层包装（而不是直接摊平成 `string signature`），尽管当前 `tronapi.TronTxOutput` 只有一个 `signature` 字段：一是与 ETH 批量输出保持同一形状，host 可以用同一套解包逻辑；二是 `TronTxOutput` 将来增加字段时不需要再改批量输出的结构。

### 4. effective path 与预检

两个引擎都按 `effective_path = item.path.is_empty() ? outer.path : item.path` 折叠路径，并在任何鉴权或设备操作前遍历整个批量：

- 拒绝空批量和超过引擎上限的批量。
- 解码每个 item 的 TRON protobuf；imkey-core 额外拒绝缺失的 `tx` 和空 `sender`。
- 拒绝空 effective path，包括 token-core 私钥 keystore 请求。
- 按各引擎既有的单笔约束校验 path：token-core 复用其 TRON 单笔签名已有的"至少 4 层且 coin type 为 `195'`"检查；imkey-core 复用现有 `check_path_validity`，该函数当前只校验层级（3 到 10 层），本变更不给它增加 BIP-32 语法校验，以免改动 imKey 既有 path 校验的兼容边界。
- 验证 `raw_data` 是合法的偶数长度十六进制，并预先计算 txID。

token-core 将单笔 signer 中的 TRON path 检查抽成可复用且返回 `Result` 的 helper，使 handler 能在解锁前调用；单笔逻辑继续调用同一 helper，错误名称保持 `invalid_sign_path`。imkey-core 在 wrapper 中预检，避免现有单笔函数的 `unwrap` 在批量错误包装之外 panic。

#### 空 path 与私钥 keystore

拒绝空 effective path 是本变更相对 TRON 单笔签名的一处刻意收紧，需要写进集成文档：

- TRON 单笔 `sign_tx` 今天接受空 path。HD keystore 在空 path 下会回落到 BIP-32 master key `m` 并签名成功，`token-core/tcx/tests/sign_test.rs` 中还有对应的固定签名断言；私钥 keystore 的 TRON 用例也普遍传 `path: ""`。批签一律拒绝空 path，因此这类调用方迁移到 `sign_txs` 时必须显式给出 path。
- 私钥 keystore 的签名密钥与 path 无关（`Keystore::PrivateKey` 分支忽略 `derivation_path`），但 token-core 的 TRON path 检查发生在 keystore 类型分派之前，所以私钥 keystore 的批签请求必须传一个形状合法的 TRON path，例如 `m/44'/195'/0'/0/0`；该值只用于通过校验，不影响签名结果。
- 对私钥 keystore，输出的 `fromAddress` 是该私钥对应的地址，不随 path 变化。

#### 错误文案

任何与具体 item 关联的错误必须包装为 `sign_txs failed at index {i}: {source}`。批级错误（空批量、超过上限）不带下标，两个引擎统一为：

- 空批量：`sign_txs batch is empty`
- 超过上限：`sign_txs batch exceeds max size of {max}`

这与 token-core 侧 ETH 批签现有文案一致。imkey-core 侧 ETH 批签原本把这两类批级错误也写成 `sign_txs failed at index 0: ...`，而空批量并不存在下标 0；随本变更一并把 `ikc/src/ethereum_signer.rs` 的这两条文案改成同一形式，使 `sign_txs` 在两个引擎、两条链上对同一类失败只有一种文案。

### 5. token-core 一次解锁、顺序薄循环

TRON 预检完成后，handler 才查找 keystore 并用现有 password/derivedKey 执行一次 `KeystoreGuard::unlock`。新的 `tcx_tron::sign_txs` 接受已折叠 path 的内部 item：

1. 顺序调用现有 `Keystore::sign_transaction`。
2. 计算/携带预检得到的 txID。
3. 从同一 effective path 派生 `fromAddress`。
4. 任一操作失败时附加下标并立即返回 `Err`。

所有输出只在循环全部成功后编码成一个 `SignTxsResult`。`TRON_MAX_BATCH_SIZE` 单独定义为 2048，不复用 `ETH_MAX_BATCH_SIZE` 常量，以便两条链以后独立调整。

2048 沿用 ETH 批签的同级论证：软件路径没有设备瓶颈，secp256k1 单次签名在 ~30µs 量级，2048 笔的签名核心耗时仍在几十毫秒。TRON 每笔比 ETH 多一次 `get_public_key` 派生加一次 Base58Check 编码和一次 SHA-256，都不改变量级；`Keystore` 内部的 HD 派生缓存让同 path 重复项的派生开销接近于零。如果实测发现更小批量就出现问题，下调常量即可，不需要改协议。

### 6. imkey-core 每笔复用完整单签

`ikc/src/tron_signer.rs::sign_txs` 先完成整批预检，再为每个 item 构造临时 `SignParam`：

- effective path 写入 `path`。
- `payment`、`receiver`、`sender` 取自 item。
- 其余通用字段继承外层 `SignParam`。

wrapper 随后直接调用现有 `TronSigner::sign_transaction`。每笔都会重新执行 path 校验、select applet、get xpub、sender 地址校验、签名 APDU 和用户物理确认。成功后 `from_address` 回显 item.sender；该值不是未经验证的 host 声明，因为 `sender` 被强制设为非空，且单笔 signer 已验证设备派生地址与其相等。`tx_hash` 使用预检阶段对同一 `raw_data` 计算的 txID。

所有 item 成功后才编码 `SignTxsOutput`。`TRON_MAX_BATCH_SIZE` 为 100；该上限只是防滥用硬限制，host 可以根据设备 UX 设置更小的业务限制。

**替代方案：** 整批只 select 一次并缓存相同 path 的 xpub。该方案需要拆分 `TronSigner::sign` 和改变已验证的 APDU 生命周期，回归风险高于本变更的一次 FFI 收益，因此不采用。

### 7. 兼容与错误语义

- protobuf 只追加新消息或修改注释，不删除、重排现有字段。
- ETH `sign_txs` 分支在重构后必须通过现有测试，输出逐字节不变。
- TRON 批签的签名字节保持各引擎现有单笔格式；本变更不尝试统一 token-core 与硬件实现历史上不同的 recovery-id 表示。
- 批量函数在内存中可能已生成前缀签名，但发生后续失败时必须丢弃它们，FFI 边界不返回部分结果。

## Risks / Trade-offs

- **[设备在第 N 笔被拒绝或断连]** → 前 N-1 个签名只存在于进程内存并被丢弃；错误包含失败下标，host 可重新构造整批，但 SDK 不自动续签或广播。
- **[100 笔硬件批量耗时过长]** → 100 仅为协议硬上限，文档要求 host 提前提示 N 次确认并设置更小的产品上限。
- **[通用 token-core 输出隐藏了 TronTxOutput 的 repeated 形态]** → 当前单签实现每次只创建一个签名；批量路径断言恰好一个，避免静默丢失。
- **[跨 path 批量扩大授权范围]** → 每笔输出 fromAddress；token-core 从签名 path 派生，imkey-core 由设备 sender 校验担保，host 可展示并交叉核对。
- **[前置校验与单笔行为漂移]** → 复用 path helper 和同一 raw-data 解码规则，并用批量/逐笔等价测试锁定。
- **[批签拒绝空 path，与 TRON 单笔行为不同]** → 单笔 `sign_tx` 仍可用空 path 签出 master-key 地址的交易（并有既有固定签名断言），批签一律拒绝。这是有意的安全收紧，代价是历史上依赖空 path 的调用方（含私钥 keystore）迁移时必须补 path，集成文档要写清占位 path 的写法。
- **[imkey path 校验只有层级检查]** → `check_path_validity` 不做 BIP-32 语法校验，形状怪异但层级合法的 path 会一路走到设备端由 applet 拒绝。本变更保持现状，不在批签路径上单独加严，避免两条路径校验强度不一致。

## Migration Plan

1. 追加 protobuf 消息并生成 Rust 类型，不发布破坏性 schema 变更。
2. 在同一交付批次中实现并测试 token-core 的 ETH/TRON 路由与两条批签路径。
3. 实现 imkey-core TRON wrapper 和 dispatcher，先验证无设备预检，再使用绑定测试设备验证成功路径。
4. 同步 SDK 文档和必要的生成绑定后发布新版本；旧 host 继续使用 `sign_tx`。
5. 若需要回滚，只移除 `TRON` dispatcher 分支；新增 protobuf 类型可以保留，ETH 与单笔接口不受影响。

## Open Questions

无。公开动作、批量上限、path 模型、硬件复用方式、输出字段与 txID 格式均已在本提案中锁定。
