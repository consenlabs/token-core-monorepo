## Context

当前钱包栈中，以太坊单笔签名分别由两个引擎提供：

- **token-core (`tcx`)** —— 软件 keystore 签名（HD / 私钥）。入口：`call_tcx_api` → `sign_tx`（`token-core/tcx/src/lib.rs:101`）→ `handler::sign_tx`（`token-core/tcx/src/handler.rs:1053`）→ `sign_transaction_internal`（`token-core/tcx/src/macros.rs:92`）→ `tcx_eth::signer::sign_transaction`（`token-core/tcx-eth/src/signer.rs:28`）。每次调用执行一次 `KeystoreGuard::unlock`，输出一个 `EthTxOutput`。
- **imkey-core (`ikc`)** —— imKey 硬件钱包签名。入口：`call_imkey_api` → `sign_tx`（`imkey-core/ikc/src/lib.rs:184`）→ `ethereum_signer::sign_eth_transaction`（`imkey-core/ikc/src/ethereum_signer.rs:14`）→ `coin_ethereum::transaction::Transaction::sign`（`imkey-core/ikc-wallet/coin-ethereum/src/transaction.rs:53`）。每次调用都会选择 ETH applet、发送一次 `prepare_sign`、获取 xpub、再发送 `sign_digest`，最后拼出一笔已签名交易。

代码库中已有 ETH 批量操作的先例：`eth_batch_personal_sign`（`token-core/tcx/src/handler.rs:1671`，proto 在 `token-core/tcx-proto/src/api.proto:134`）能在一次解锁内打包多条 personal-sign 消息。本提案对该模式做两处扩展：扩展到 ETH **交易**，并在 **两个引擎** 上同时实现。

最近一个具体驱动场景是 staking：钱包必须先发一笔 "prepay/approve"，紧接着再发一笔 "stake"。今天这意味着两次 FFI 调用、两次解锁提示，用户会看到两次相隔的密码弹窗 / 设备确认；中间存在非原子窗口，用户可能退出、丢失 nonce，或者最终只广播了 prepay。但本提案的应用范围并不限于 staking 这种 2 笔的场景：

- **少量批次**（个位数）：staking 的 prepay + stake、合约批量 approve、L2 桥跨链的 lock + claim。
- **中量批次**（几十笔）：dApp 一次性下发的多笔 meta-tx、复合 DeFi 策略一键执行。
- **大量批次**（上百乃至上千笔）：批量空投、批量归集出账、企业财务批处理、链上分析与回放工具。

本提案在 SDK 边界一次性把 N 笔交易统一签完，N 由各引擎的批量上限约束（`tcx` 至 2048，`ikc` 至 100）。所有上述场景共用同一个 `sign_txs` 入口，在 host 侧不需要再为不同业务场景做差异化处理。

## Goals / Non-Goals

**Goals:**

- 在 `call_tcx_api` 与 `call_imkey_api` 上同时新增 SDK 动作 `sign_txs`，接受有序的 item 列表（每个 item 包含一个 `EthTxInput` 加可选的 per-item path）并返回有序的 `EthTxOutput` 列表。
- 单次 FFI 完成整批签名，输入与现有 `sign_tx` 完全等价（legacy / EIP-1559 / access list、十六进制或十进制数值串、十六进制 chain id 都支持）。
- token-core 整批共用一次解锁（仅一次密码 / derived-key 校验）；imkey-core **不在批量层引入任何 device-session 优化**——每个 item 在 FFI handler 内薄循环里复用现有 `Transaction::sign` 单笔流程（`select_applet` / `prepare_sign` / `get_xpub` / `sign_digest` / 设备确认逐笔重新发生），以最大化代码复用并保证单笔路径零回归。
- 全成功或全失败的批量语义，错误以与现有 `sign_tx` / `eth_batch_personal_sign` 相同的字符串错误返回路径抛出，错误信息形如 `"sign_txs failed at index {i}: {source}"`。
- 不同引擎设定不同上限：`tcx` 上限 2048（软件签名，仅受内存与单次 FFI 时长约束）、`ikc` 上限 100（硬件每笔仍由用户在设备上按确认；100 已显著超出 stake 等典型业务的笔数需要，再大对 UX 与 BLE/USB 会话稳定性收益有限）。
- 在 `tcx-eth`、`coin-ethereum` 添加单元测试，并在 `tcx/tests/sign_test.rs` 添加端到端测试，覆盖等价性、原子性、上限拒绝、空批量、共享 path 与 per-item path 覆盖。

**Non-Goals:**

- **不修改 imKey 固件。** 硬件路径仍要求用户对每笔交易单独确认；本提案纯粹做 SDK 侧的捆绑。"设备端一次确认 N 笔"这种特性（如有需要）应作为另一个独立提案，需要新增 APDU 命令并升级 applet。
- 不为以太坊以外的链（TRON、Cosmos、Filecoin、Bitcoin 等）做批量支持。这些链如有需要，由各自独立的提案处理。
- 不做 EIP-712 批签或除现有 `eth_batch_personal_sign` 之外的多消息签名。
- 不引入异步 / 流式签名 API；调用仍如 `sign_tx` 一样是同步的。
- 不提供 nonce 自增辅助；host SDK 仍需自行显式提供每笔 `nonce`。批量 API 不会校验 nonce 是否连续（不同 stake 操作可能存在合理的 nonce 间隔）。
- 不让 SDK 自动从 `EthTxInput` 推算 imKey 设备屏上的 `payment` / `receiver` / `fee` 字符串；与单笔 `sign_tx` 一致，由 host 显式提供。

## Decisions

### 1. Protobuf 形态——以现有 `EthTxInput` 列表为基础，并支持 per-item path 覆盖

我们扩展现有的单笔 schema，而不是另起一套，以便字段保持自动对齐。新增以下顶层消息：

- token-core（`token-core/tcx-proto/src/api.proto`）：

  ```proto
  message SignTxsParam {
    string id = 1;
    oneof key {
      string password = 2;
      string derivedKey = 3;
    }
    string chainType = 4;     // 必须为 "ETHEREUM"
    string path = 5;          // 整批共享的默认 HD 派生路径
    string network = 6;       // 可选，与 SignParam 对齐
    string segWit = 7;        // ETH 不使用，但保留以对齐参数
    repeated SignTxsItem items = 8;
  }

  message SignTxsItem {
    transaction.EthTxInput tx = 1;
    string path = 2;          // 可选；空字符串表示回落到外层 path
  }

  message SignTxsResult {
    repeated transaction.EthTxOutput outputs = 1;
  }
  ```

- imkey-core（`imkey-core/ikc-proto/src/eth.proto`）：

  ```proto
  message SignTxsInput {
    repeated SignTxsItem items = 1;
  }

  message SignTxsItem {
    EthTxInput tx = 1;
    string payment = 2;     // 设备上每笔的展示字符串
    string receiver = 3;    // 设备上每笔的展示字符串
    string sender = 4;      // 期望派生出的地址（不一致则中止）
    string fee = 5;         // 设备上每笔的展示字符串
    string path = 6;        // 可选；空字符串表示回落到 SignParam.path
  }

  message SignTxsOutput {
    repeated EthTxOutput outputs = 1;
  }
  ```

  imkey-core 的 dispatcher 从 `SignParam.input`（即现有的 `google.protobuf.Any` 信封）中读取 `SignTxsInput`，因此外层 `SignParam` 仍负责承载 `chainType` 与默认 `path`。每笔的 `payment` / `receiver` / `sender` / `fee` 放在每个 item 中，因为设备的提示是逐笔的；同时每笔可选的 `path` 让"跨地址批量"成为协议层一等公民。

#### 设计依据

- **per-item `path` 覆盖**：staking 这类同地址多笔场景下所有 item 的 `path` 留空即可；未来如需跨地址归集（例如把 3 个子账户的 ETH 合并到一个收款地址），则填写 item.path 即可，不需要再做协议升级。空串语义而非 `oneof`/`optional`，是为了与既有 proto 风格一致、避免 prost 生成 `Option<String>` 的序列化与默认值踩坑。
- **复用 `transaction.EthTxInput` / `EthTxOutput`** 让所有字段（legacy / EIP-1559 / access list）自动跟随单笔 API，不需任何额外维护。
- **`payment` / `receiver` / `sender` / `fee` 由 host 提供**，与单笔 `sign_tx` 完全一致；这样调用方从单笔升级到批量时只是把这 4 个字段从外层 `SignParam` 移到每个 item，零学习成本，同时保留 host 自由格式化（合约方法名、本地化文案等）的能力。

### 2. 各引擎实现

#### token-core

- 在 `tcx-eth/src/signer.rs` 新增函数 `pub fn sign_txs(keystore: &mut Keystore, items: &[(EthTxInput, String)], default_path: &str) -> Result<Vec<EthTxOutput>>`（item.path 在调用前已和 default_path 折叠为生效 path）。内部循环复用现有的 `Transaction::try_from(&EthTxInput)` 和 `keystore.secp256k1_ecdsa_sign_recoverable(&tx.sighash(), effective_path)`。`Keystore` 内部的 HD 派生缓存让重复 path 的派生开销极低；不重复的 path 也只是普通 secp256k1 派生，对 2048 笔的开销可接受。
- 在 `tcx/src/handler.rs` 新增 handler `pub(crate) fn sign_txs(data: &[u8])`，参考 `eth_batch_personal_sign`（`token-core/tcx/src/handler.rs:1671`）的结构。在解锁前先做 `items.is_empty()` 与 `items.len() <= ETH_MAX_BATCH_SIZE` 检查；执行单次 `KeystoreGuard::unlock`；折叠每个 item 的有效 path（item.path 非空则用 item.path，否则用外层 path）；调用 `sign_txs`；编码 `SignTxsResult`。
- 新增 `impl_to_key!(crate::api::sign_txs_param::Key);`，让新 param 的 `oneof key` 与 `tcx-crypto::Key` 对接。
- 在 `token-core/tcx/src/lib.rs:74` 注册 dispatcher 分支 `"sign_txs" => landingpad(|| sign_txs(&action.param.unwrap().value))`（紧邻 `"eth_batch_personal_sign"`，约第 131 行），并在 `use` 块（约第 27 行）引入新 handler。
- 与 handler 同位置定义常量 `pub const ETH_MAX_BATCH_SIZE: usize = 2048;`。

#### imkey-core

核心约束：**`coin-ethereum/src/transaction.rs` 一行不动**——单笔 `Transaction::sign` 不重构、不抽 helper、不新增 `batch_sign`。批量层完全是 FFI handler 上的一个薄循环，每笔 item 直接走现有单笔 `Transaction::sign`，以保证单笔路径零回归、所有现有 fixture 与端到端用例无需重新校准。

- 在 `imkey-core/ikc/src/ethereum_signer.rs` 新增：
  - 常量 `pub const ETH_MAX_BATCH_SIZE: usize = 100;`（与 handler 同位置定义，可在不改协议的情况下调整）。
  - （可选重构）把现有 `sign_eth_transaction` 内部那段 `EthTxInput → Transaction + chain_id` 的解析提取为私有 helper（`fn build_eth_transaction(input: &EthTxInput) -> Result<(Transaction, u64)>`），让单笔 / 批量两条路径共用同一段解析；语义零变化，仅是为了避免 batch 内重复 inline 同一段几十行的 RLP / access list 解析。这一步是 nice-to-have，**不是**对 `Transaction::sign` 本身的重构。
  - `pub fn sign_txs(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>>`，做法是：
    1. 解码 `SignTxsInput`，前置同步校验：`items.is_empty()` / `items.len() <= ETH_MAX_BATCH_SIZE` / 外层 `sign_param.path` 与每个 item.path（非空时）的 BIP-32 合法性 / 每个 item.sender 非空。任一失败即在触达设备会话之前返回错误（错误信息携带触发失败的 item 下标）。
    2. 顺序遍历 items；对每个 item：
       - 折叠出有效 path：`item.path` 非空则用 item.path，否则用 `sign_param.path`。
       - 调用 `build_eth_transaction(&item.tx)` 得到 `(eth_tx, chain_id)`。
       - 直接调用现有单笔 `eth_tx.sign(Some(chain_id), &effective_path, &item.payment, &item.receiver, &item.sender, &item.fee)` 拿到 `EthTxOutput`——这一步和今天 `sign_eth_transaction` 调用的是同一个 `Transaction::sign`，所以包括 `select_applet` / `prepare_sign` / `get_xpub` / 地址校验 / `sign_digest` / 拼装在内的整套设备会话动作都被原样执行一次。
       - 按下标聚合到 `outputs`。
    3. 任意一笔出错立即中止整批，错误用 `"sign_txs failed at index {i}: {source}"` 形式包装并向上传递；不返回任何部分签名。
- 在 `imkey-core/ikc/src/lib.rs` 紧邻 `"sign_tx"` 处注册 dispatcher 分支 `"sign_txs"`：解码 `SignParam`，分支判断 `chain_type == "ETHEREUM"`，否则返回 `Err(anyhow!("sign_txs unsupported_chain"))`，再调用 `ethereum_signer::sign_txs`。

显式的 **非目标**：
- 不在批量层做 `select_applet` 一次化、`get_xpub` 缓存、TLV 复用等任何 device-session 优化。这些优化要求把单笔 `Transaction::sign` 拆开，与本设计"不动单笔实现"的约束相冲突。如未来 stake / 长批量场景的实测延迟成为问题，可以另起独立提案做 device-session 优化（届时已有对应的 perf benchmark 可作为 baseline）。
- 不在 `coin-ethereum` 引入任何"批量"概念。`coin-ethereum` 这一层永远只见单笔 `Transaction::sign`；批量是上层 FFI handler 的事。

### 3. 全成功或全失败的错误语义

- 校验分两阶段：先做一次同步校验（批量大小、空列表、每个 item.path 是否符合 BIP-32 派生格式、`to` 解析、chain id 解析、`sender` 非空），任何失败都在解锁 / 选择 applet 之前发生；之后才在循环中执行逐笔签名。
- 签名期间发生错误立即中止，并以 `"sign_txs failed at index {i}: {source}"` 形式包装。永远不返回部分 `SignTxsResult`。
- 错误返回路径与现有 `sign_tx` / `eth_batch_personal_sign` 完全一致——通过 `landingpad` + `LAST_ERROR` + `get_last_err_message()`（`tcx`）/ `imkey_get_last_err_message()`（`ikc`）抛出。host 通过同样的 API 拿到字符串，只需 parse `"failed at index (\d+)"` 即可定位失败下标。
- 该策略让 host SDK 的错误处理与今天的 `sign_tx` 一致（一次错误 → 一种失败模式），同时为定位提供精确诊断。

### 4. 批量上限

- **`tcx`：2048**。理由：软件签名没有设备瓶颈，2048 足以覆盖批量归集、链上分析等大批量场景；以 secp256k1 单次签名 ~30µs 估算，2048 笔签名核心耗时 ≈ 60ms，加上 RLP / proto 序列化也在亚秒级，FFI 一次走得动。
- **`ikc`：100**。理由：硬件路径每笔都要等用户在设备上按确认，cap 主要约束的是 BLE/USB 会话总时长 + applet 状态保持，而不是 UX——UX 端的实际可接受笔数应由 host 业务层根据流程语义自行收紧（stake 2 笔、批量 approve 几笔等都远小于 100）。100 给了协议层一个有意义的硬上限：一方面让 stake / 多步合约调用等场景永远不会触线，另一方面也阻止 host 误把成百上千的归集需求当成 imkey 的一次批量发出来（应当走软件签名路径）。
- 上限只是每个引擎中的一行 `const`，并在解锁 / 选择 applet 之前就执行检查。错误尺寸的请求绝不会触发解锁或设备会话。

### 5. 向后兼容

- 纯增量。`sign_tx`、`EthTxInput`、`EthTxOutput`、`eth_batch_personal_sign` 全部保持不变。proto 字段编号不重新编排。
- `sign_txs` 是一个新的 dispatcher key，旧版 host SDK 仍可继续按旧方式调用 `sign_tx`。
- proto 改动在文件层面是 append-only，不会让既有生成的 Rust 类型字段编号发生变化。

### 6. 测试策略

- **等价性测试（`tcx-eth/src/signer.rs`）**：把当前文件中的每个 EIP-155 / EIP-1559 / access-list 用例分别按"单笔签"和"作为批量的一员签"两种方式跑一遍，断言 `signature` + `tx_hash` 逐字节一致。
- **per-item path 测试**：构造一批 3 笔交易，第 1、2 笔指定不同 item.path，第 3 笔留空回落外层 path；断言三笔解码后的 `from` 地址分别等于三个 path 派生出的地址。
- **原子性测试**：构造一个第二项（下标 1）`to` 字段非法的批量；断言错误信息含 `failed at index 1`，且未返回任何签名。
- **上限测试**：在 tcx 拒绝 2049 笔、在 ikc 拒绝 101 笔；用一个能感知解锁次数的 keystore 探针，断言未发生解锁副作用。
- **空批量测试**：拒绝 0 笔。
- **非法 item.path 测试**：item.path 不符合 BIP-32 时整批被拒，错误带下标。
- **端到端测试（`tcx/tests/sign_test.rs`）**：参考 `test_eth_batch_personal_sign`（约第 1415 行），但针对交易，调用 FFI dispatcher，覆盖 prepay + stake 这一对组合及错误密码反例，并加入一个 per-item path 的端到端用例。
- **imkey 测试（`imkey-core/ikc/src/ethereum_signer.rs`）**：把现有 fixture（`test_sign_eth_transaction_eip1559`、`..._legacy`、`..._multi_access_list`）按下标 0 和下标 1 各封装成 1 笔批量与 2 笔批量后再跑，断言每个 `outputs[i]` 与对应单笔调用 `sign_eth_transaction(item.tx, sign_param_i)` 的结果逐字节一致；与该文件其余用例一样以 `bind_test()` 守护。这一断言的含义就是"批量 = N 次单笔"——任何偏差都意味着我们错误地引入了 batch-only 路径。
- **批量 wrapper 的无设备单测（`imkey-core/ikc/src/ethereum_signer.rs`）**：批量层引入的新逻辑（前置校验、path 折叠、错误下标包装、上限拒绝）应当在 select_applet 之前发生，可以做无设备依赖的单测覆盖：空批量 / 101 笔批量 / 非法 item.path / 缺失 tx 字段——断言错误信息分别匹配 `invalid_param` / `oversized batch` / `failed at index N` 等模式，且分支不会触发任何 APDU。这部分的 `Transaction::sign` 路径不被进入，因此无需 `bind_test()`。

### 7. 文档

- 在 `token-core/tcx-docs` 与 `imkey-core/ikc-docs` 增加新动作的说明：请求/响应形态、共享 path 与 per-item path 的两种用法、不同引擎的批量上限（2048 vs 100）、错误信息格式（`"sign_txs failed at index {i}: {source}"`）、以及 imKey 路径仍需逐笔确认的提示，避免 host UX 误以为只需一次确认。

### 8. 安全加固（来自 infrastructure#312 评审）

安全团队在评审报告 [PR #175 安全风险评估报告](https://github.com/consenlabs/infrastructure/issues/312) 中提出 3 项健壮性建议（H-1 / H-2 / H-3）。报告结论"不阻塞合入"，但建议在合入前完成 H-1 / H-2（每个 ≤ 3 行）、随后用单独 PR 跟进 H-3。本提案将三项一并落实，并在 §6 测试中补充对应的端到端 / 单元 / 预检测试。

#### H-1：`chain_type` 严格校验（解锁前）

**事实**：`tcx::handler::sign_txs` 原先不校验 `param.chain_type`；proto 注释虽写 `// must be "ETHEREUM"`，但 host 误填 `chain_type: "BITCOIN"` 仍走 ETH 流程，与 `imkey-core` 的 `"sign_txs"` 分支（已显式返回 `unsupported_chain`）行为不对称。

**决定**：在 `tcx::handler::sign_txs` 顶部、解码 `SignTxsParam` 之后、`KEYSTORE_MAP.write()` 之前补一段：

```rust
if param.chain_type != "ETHEREUM" {
    return Err(anyhow!("sign_txs unsupported_chain"));
}
```

这把 tcx 与 ikc 两侧的拒绝行为统一为"非 ETHEREUM 即 unsupported_chain"。报告指出这"不扩大攻击面"——`sign_txs` 这个 action name 已表明 ETH-only 意图——但消除了"不可预测的失败模式"。

#### H-2：空 effective path 在签名前被拒

**事实**：tcx 与 ikc 均在 effective path 折叠后允许 `""`；下游 HD keystore 在 `derivation_path == ""` 时回退到 BIP-32 master `m`，从而签出一笔 `from` 是 master-key 地址的交易。`ikc` 的 `Transaction::sign` 内部 `check_path_validity("")` 虽会失败，但这发生在 `select_applet` 与若干 APDU 之后，用户已看到一次令人困惑的设备 prompt。报告指出该 footgun 已存在于单笔 `sign_tx`，批量场景下被复制了 N 份。

**决定**：

- **tcx**：在 handler 折叠出 `effective_path` 后立即追加：

  ```rust
  if effective_path.is_empty() {
      return Err(anyhow!("sign_txs failed at index {}: empty derivation path", index));
  }
  ```

- **ikc**：在预检循环里同样折叠 effective path 并 reject 空串。`Transaction::sign` 内部仍保留 `check_path_validity` 作为最后一道防线，但批量 SDK 层会在 `select_applet` 之前把这类错误吃掉。

#### H-3：每笔输出附带 `from_address`

**事实**：批量 + per-item path 允许"一次密码授权 / 一次设备绑定签出 N 个不同 from 地址的交易"。安全契约依赖 host UI 在密码弹框前展示完整的 `{path → from_address}` 集合；若 host UI 实现错误，用户可能在不知情下授权了非常用账户的交易。报告把这判定为"设计性、需 host 配合"——非可利用漏洞——但建议把"让 host 拿到 from_address"的契约从"靠 host 自行 recover"前移到"SDK 直接给"，作为 follow-up PR。

**决定**：在两个引擎的 per-item 输出中新增 `from_address` 字段：

- **token-core**：`SignTxsResult.Output` 新增 `string fromAddress = 3;`。`tcx-eth::sign_txs` 的内部循环用与本次签名相同的 effective path 调一次 `Keystore::get_public_key`（HD 派生，无签名工作量），再走 `EthAddress::from_public_key` 拿到 EIP-55 校验和形式。`Keystore::get_public_key` 复用已解锁的 keystore，不会触发额外的 KDF 解锁开销。
- **imkey-core**：`SignTxsOutput` 的 `outputs` 元素类型从 `EthTxOutput` 改为新增的包装结构 `SignTxsItemOutput { EthTxOutput tx = 1; string from_address = 2; }`。`from_address` 等于 `SignTxsItem.sender` —— 这一相等关系由 `Transaction::sign` 内部的"设备派生地址 ≟ sender"校验强制保证，因此该字段对调用方而言是"设备已确认"的 from 地址。这里采用包装结构而非"直接把 `from_address` 加到 `EthTxOutput`"，避免污染单笔 `sign_tx` 的输出 schema。

#### 与单笔 `sign_tx` 的关系

- H-1 / H-2 的 footgun 在单笔 `sign_tx` 中同样存在；本次只在批量入口收紧。原因：单笔 sign_tx 的 schema / 行为不在本提案的修改范围；统一收敛是单独 PR 的事（见 §6 测试中保留的兼容性断言）。
- H-3 的 `from_address` 字段仅出现在 `SignTxs*` 输出中；单笔 `sign_tx` 的 `EthTxOutput` 不变。host 升级到批量 API 时即"免费"获得 cross-check 能力，单笔旧调用方零回归。

## Risks / Trade-offs

- **硬件路径上的"半批" UX**。我们刻意不动固件，因此当 imKey 用户在第二次确认时拒绝，第一笔签名实际上已经在我们内存里产生——但 host 还没有拿到（我们会中止整批并丢弃部分结果）。钱包 UX 必须清楚提示"需要确认全部交易"，否则用户会困惑。我们之所以选择 all-or-nothing 而不是返回部分结果，是为了避免 host 只广播第 1 笔而没有第 2 笔——而这正是本提案要消除的故障模式。
- **批量过程中设备掉线（BLE/USB）**。同样的缓解：错误体里带 `index`（字符串中），host 可以以剩余尾段为新的批量、调整 nonce 后重发。
- **per-item path 不引入额外复杂度**。批量层只在调用 `Transaction::sign` 之前折叠出每个 item 的有效 path，然后把它当作"独立的一次单笔签名"传进去——每笔仍执行各自的 `get_xpub`，没有缓存逻辑，自然也就没有缓存命中 / 失效的边界条件需要 reason about。代价是同一 path 在 N 笔中重复派生 N 次（每次约一个 USB 往返），实测开销由 perf benchmark 衡量；典型 stake (2 笔) 场景的增量可忽略。
- **`tcx` 上限 2048 的内存与时延**。2048 笔在内存中存放 raw + signed 两份字节切片估算 < 10MB，可接受；FFI 单次返回的 protobuf 序列化也在亚秒级。如果未来发现 host 在更小批量上就遇到性能问题，可以下调该常量而无需改协议。
- **错误下标走字符串**。host 需要 parse 字符串才能拿到下标。考虑到与既有 `sign_tx` / `eth_batch_personal_sign` 的错误模型必须保持一致，结构化错误会让此 API 成为整个 SDK 的孤例，反而造成更高的维护成本。我们用稳定的固定字符串模板（`"sign_txs failed at index {i}: ..."`）以正则可靠提取下标。
- **测试覆盖（硬件路径）**。imkey 大部分测试需要绑定测试设备才能运行。本提案的薄循环架构让这件事比较自然：`Transaction::sign` 这一层的所有现有 fixture（无论 `bind_test()` 守护与否）都直接覆盖了批量"每一笔"的等价路径；批量 wrapper 上新增的逻辑（前置校验、错误下标包装、path 折叠、上限拒绝）都在 `select_applet` 之前，能在无设备环境下做覆盖（详见 §6 测试）。
- **主动放弃 imkey 设备会话优化**。我们没有把 `select_applet` 拉到批量循环外、也没有缓存 `get_xpub`，因此 N 笔批量在 USB / BLE 上的总耗时近似 N × 单笔耗时。这是为了保证 `Transaction::sign` 的实现完全不动、单笔路径零回归。如果 stake 这类小批量（≤ 5 笔）的实测延迟在产品 UX 上仍可接受，这个 trade-off 就是合理的；否则后续可以另起独立提案，把 device-session 优化作为下一步演进，届时已有的 `sign_txs` perf benchmark 可作为 baseline 量化收益。
- **proto 重新生成的扰动**。在 `tcx-proto` 与 `ikc-proto` 中新增消息会触发两个 crate 的 Rust 代码重新生成。缓解：本次改动是 append-only，diff 体量小、便于 review。
