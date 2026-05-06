## Context

当前钱包栈中，以太坊单笔签名分别由两个引擎提供：

- **token-core (`tcx`)** —— 软件 keystore 签名（HD / 私钥）。入口：`call_tcx_api` → `sign_tx`（`token-core/tcx/src/lib.rs:101`）→ `handler::sign_tx`（`token-core/tcx/src/handler.rs:1053`）→ `sign_transaction_internal`（`token-core/tcx/src/macros.rs:92`）→ `tcx_eth::signer::sign_transaction`（`token-core/tcx-eth/src/signer.rs:28`）。每次调用执行一次 `KeystoreGuard::unlock`，输出一个 `EthTxOutput`。
- **imkey-core (`ikc`)** —— imKey 硬件钱包签名。入口：`call_imkey_api` → `sign_tx`（`imkey-core/ikc/src/lib.rs:184`）→ `ethereum_signer::sign_eth_transaction`（`imkey-core/ikc/src/ethereum_signer.rs:14`）→ `coin_ethereum::transaction::Transaction::sign`（`imkey-core/ikc-wallet/coin-ethereum/src/transaction.rs:53`）。每次调用都会选择 ETH applet、发送一次 `prepare_sign`、获取 xpub、再发送 `sign_digest`，最后拼出一笔已签名交易。

代码库中已有 ETH 批量操作的先例：`eth_batch_personal_sign`（`token-core/tcx/src/handler.rs:1671`，proto 在 `token-core/tcx-proto/src/api.proto:134`）能在一次解锁内打包多条 personal-sign 消息。本提案对该模式做两处扩展：扩展到 ETH **交易**，并在 **两个引擎** 上同时实现。

最近一个具体驱动场景是 staking：钱包必须先发一笔 "prepay/approve"，紧接着再发一笔 "stake"。今天这意味着两次 FFI 调用、两次解锁提示，用户会看到两次相隔的密码弹窗 / 设备确认；中间存在非原子窗口，用户可能退出、丢失 nonce，或者最终只广播了 prepay。但本提案的应用范围并不限于 staking 这种 2 笔的场景：

- **少量批次**（个位数）：staking 的 prepay + stake、合约批量 approve、L2 桥跨链的 lock + claim。
- **中量批次**（几十笔）：dApp 一次性下发的多笔 meta-tx、复合 DeFi 策略一键执行。
- **大量批次**（上百乃至上千笔）：批量空投、批量归集出账、企业财务批处理、链上分析与回放工具。

本提案在 SDK 边界一次性把 N 笔交易统一签完，N 由各引擎的批量上限约束（`tcx` 至 2048，`ikc` 至 10）。所有上述场景共用同一个 `eth_batch_sign_tx` 入口，在 host 侧不需要再为不同业务场景做差异化处理。

## Goals / Non-Goals

**Goals:**

- 在 `call_tcx_api` 与 `call_imkey_api` 上同时新增 SDK 动作 `eth_batch_sign_tx`，接受有序的 item 列表（每个 item 包含一个 `EthTxInput` 加可选的 per-item path）并返回有序的 `EthTxOutput` 列表。
- 单次 FFI 完成整批签名，输入与现有 `sign_tx` 完全等价（legacy / EIP-1559 / access list、十六进制或十进制数值串、十六进制 chain id 都支持）。
- token-core 整批共用一次解锁（仅一次密码 / derived-key 校验）；imkey-core 整批共用一次 applet 选择（无需在交易之间反复 `select_applet`）。
- 全成功或全失败的批量语义，错误以与现有 `sign_tx` / `eth_batch_personal_sign` 相同的字符串错误返回路径抛出，错误信息形如 `"eth_batch_sign_tx failed at index {i}: {source}"`。
- 不同引擎设定不同上限：`tcx` 上限 2048（软件签名，仅受内存与单次 FFI 时长约束）、`ikc` 上限 10（硬件设备会话与逐笔确认体验约束）。
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
  message EthBatchSignTxParam {
    string id = 1;
    oneof key {
      string password = 2;
      string derivedKey = 3;
    }
    string chainType = 4;     // 必须为 "ETHEREUM"
    string path = 5;          // 整批共享的默认 HD 派生路径
    string network = 6;       // 可选，与 SignParam 对齐
    string segWit = 7;        // ETH 不使用，但保留以对齐参数
    repeated EthBatchSignTxItem items = 8;
  }

  message EthBatchSignTxItem {
    transaction.EthTxInput tx = 1;
    string path = 2;          // 可选；空字符串表示回落到外层 path
  }

  message EthBatchSignTxResult {
    repeated transaction.EthTxOutput outputs = 1;
  }
  ```

- imkey-core（`imkey-core/ikc-proto/src/eth.proto`）：

  ```proto
  message EthBatchTxInput {
    repeated EthBatchTxItem items = 1;
  }

  message EthBatchTxItem {
    EthTxInput tx = 1;
    string payment = 2;     // 设备上每笔的展示字符串
    string receiver = 3;    // 设备上每笔的展示字符串
    string sender = 4;      // 期望派生出的地址（不一致则中止）
    string fee = 5;         // 设备上每笔的展示字符串
    string path = 6;        // 可选；空字符串表示回落到 SignParam.path
  }

  message EthBatchTxOutput {
    repeated EthTxOutput outputs = 1;
  }
  ```

  imkey-core 的 dispatcher 从 `SignParam.input`（即现有的 `google.protobuf.Any` 信封）中读取 `EthBatchTxInput`，因此外层 `SignParam` 仍负责承载 `chainType` 与默认 `path`。每笔的 `payment` / `receiver` / `sender` / `fee` 放在每个 item 中，因为设备的提示是逐笔的；同时每笔可选的 `path` 让"跨地址批量"成为协议层一等公民。

#### 设计依据

- **per-item `path` 覆盖**：staking 这类同地址多笔场景下所有 item 的 `path` 留空即可；未来如需跨地址归集（例如把 3 个子账户的 ETH 合并到一个收款地址），则填写 item.path 即可，不需要再做协议升级。空串语义而非 `oneof`/`optional`，是为了与既有 proto 风格一致、避免 prost 生成 `Option<String>` 的序列化与默认值踩坑。
- **复用 `transaction.EthTxInput` / `EthTxOutput`** 让所有字段（legacy / EIP-1559 / access list）自动跟随单笔 API，不需任何额外维护。
- **`payment` / `receiver` / `sender` / `fee` 由 host 提供**，与单笔 `sign_tx` 完全一致；这样调用方从单笔升级到批量时只是把这 4 个字段从外层 `SignParam` 移到每个 item，零学习成本，同时保留 host 自由格式化（合约方法名、本地化文案等）的能力。

### 2. 各引擎实现

#### token-core

- 在 `tcx-eth/src/signer.rs` 新增函数 `pub fn batch_sign_transaction(keystore: &mut Keystore, items: &[(EthTxInput, String)], default_path: &str) -> Result<Vec<EthTxOutput>>`（item.path 在调用前已和 default_path 折叠为生效 path）。内部循环复用现有的 `Transaction::try_from(&EthTxInput)` 和 `keystore.secp256k1_ecdsa_sign_recoverable(&tx.sighash(), effective_path)`。`Keystore` 内部的 HD 派生缓存让重复 path 的派生开销极低；不重复的 path 也只是普通 secp256k1 派生，对 2048 笔的开销可接受。
- 在 `tcx/src/handler.rs` 新增 handler `pub(crate) fn eth_batch_sign_tx(data: &[u8])`，参考 `eth_batch_personal_sign`（`token-core/tcx/src/handler.rs:1671`）的结构。在解锁前先做 `items.is_empty()` 与 `items.len() <= ETH_MAX_BATCH_SIZE` 检查；执行单次 `KeystoreGuard::unlock`；折叠每个 item 的有效 path（item.path 非空则用 item.path，否则用外层 path）；调用 `batch_sign_transaction`；编码 `EthBatchSignTxResult`。
- 新增 `impl_to_key!(crate::api::eth_batch_sign_tx_param::Key);`，让新 param 的 `oneof key` 与 `tcx-crypto::Key` 对接。
- 在 `token-core/tcx/src/lib.rs:74` 注册 dispatcher 分支 `"eth_batch_sign_tx" => landingpad(|| eth_batch_sign_tx(&action.param.unwrap().value))`（紧邻 `"eth_batch_personal_sign"`，约第 131 行），并在 `use` 块（约第 27 行）引入新 handler。
- 与 handler 同位置定义常量 `pub const ETH_MAX_BATCH_SIZE: usize = 2048;`。

#### imkey-core

- 在 `coin-ethereum/src/transaction.rs` 新增 `pub fn batch_sign(items: &[EthBatchTxItem], default_path: &str, chain_id: Option<u64>) -> EthResult<Vec<EthTxOutput>>`，做法是：
  1. 前置同步校验（批量大小、结构、空列表、每个 item.path 的 BIP-32 合法性、`sender` 非空）。
  2. 对整批只调一次 `EthApdu::select_applet()`。
  3. 对每个 item：折叠出有效 path → 构建现有的 TLV `data_pack`（`tx` 的 RLP + `payment` + `receiver` + `fee`）→ 发送 `prepare_sign` → 调用 `EthApdu::get_xpub` 得到该 path 派生的地址（同一 path 连续多次时复用上一次结果，避免冗余 apdu）→ 与 item.sender 比对 → 调用 `sign_digest` → 拼装已签名交易。
  4. 任意一笔出错即中止并向上传递。
- 在 `imkey-core/ikc/src/ethereum_signer.rs` 新增 `pub fn sign_eth_batch_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>>`，结构对齐 `sign_eth_transaction`（`imkey-core/ikc/src/ethereum_signer.rs:14`）。
- 在 `imkey-core/ikc/src/lib.rs` 紧邻 `"sign_tx"` 处注册 dispatcher 分支 `"eth_batch_sign_tx"`：解码 `SignParam`，分支判断 `chain_type == "ETHEREUM"`，否则返回 `Err(anyhow!("eth_batch_sign_tx unsupported_chain"))`，再调用 `ethereum_signer::sign_eth_batch_transaction`。
- 与函数同位置定义常量 `pub const ETH_MAX_BATCH_SIZE: usize = 10;`。

### 3. 全成功或全失败的错误语义

- 校验分两阶段：先做一次同步校验（批量大小、空列表、每个 item.path 是否符合 BIP-32 派生格式、`to` 解析、chain id 解析、`sender` 非空），任何失败都在解锁 / 选择 applet 之前发生；之后才在循环中执行逐笔签名。
- 签名期间发生错误立即中止，并以 `"eth_batch_sign_tx failed at index {i}: {source}"` 形式包装。永远不返回部分 `EthBatchSignTxResult`。
- 错误返回路径与现有 `sign_tx` / `eth_batch_personal_sign` 完全一致——通过 `landingpad` + `LAST_ERROR` + `get_last_err_message()`（`tcx`）/ `imkey_get_last_err_message()`（`ikc`）抛出。host 通过同样的 API 拿到字符串，只需 parse `"failed at index (\d+)"` 即可定位失败下标。
- 该策略让 host SDK 的错误处理与今天的 `sign_tx` 一致（一次错误 → 一种失败模式），同时为定位提供精确诊断。

### 4. 批量上限

- **`tcx`：2048**。理由：软件签名没有设备瓶颈，2048 足以覆盖批量归集、链上分析等大批量场景；以 secp256k1 单次签名 ~30µs 估算，2048 笔签名核心耗时 ≈ 60ms，加上 RLP / proto 序列化也在亚秒级，FFI 一次走得动。
- **`ikc`：10**。理由：硬件路径每笔都要等用户在设备上按确认，BLE/USB 会话需要保持，从 UX 与稳定性出发不能太大；imToken 的 stake 流程需要 2 笔，10 给了 5x 余量来覆盖更复杂的 DeFi 流程。
- 上限只是每个引擎中的一行 `const`，并在解锁 / 选择 applet 之前就执行检查。错误尺寸的请求绝不会触发解锁或设备会话。

### 5. 向后兼容

- 纯增量。`sign_tx`、`EthTxInput`、`EthTxOutput`、`eth_batch_personal_sign` 全部保持不变。proto 字段编号不重新编排。
- `eth_batch_sign_tx` 是一个新的 dispatcher key，旧版 host SDK 仍可继续按旧方式调用 `sign_tx`。
- proto 改动在文件层面是 append-only，不会让既有生成的 Rust 类型字段编号发生变化。

### 6. 测试策略

- **等价性测试（`tcx-eth/src/signer.rs`）**：把当前文件中的每个 EIP-155 / EIP-1559 / access-list 用例分别按"单笔签"和"作为批量的一员签"两种方式跑一遍，断言 `signature` + `tx_hash` 逐字节一致。
- **per-item path 测试**：构造一批 3 笔交易，第 1、2 笔指定不同 item.path，第 3 笔留空回落外层 path；断言三笔解码后的 `from` 地址分别等于三个 path 派生出的地址。
- **原子性测试**：构造一个第二项（下标 1）`to` 字段非法的批量；断言错误信息含 `failed at index 1`，且未返回任何签名。
- **上限测试**：在 tcx 拒绝 2049 笔、在 ikc 拒绝 11 笔；用一个能感知解锁次数的 keystore 探针，断言未发生解锁副作用。
- **空批量测试**：拒绝 0 笔。
- **非法 item.path 测试**：item.path 不符合 BIP-32 时整批被拒，错误带下标。
- **端到端测试（`tcx/tests/sign_test.rs`）**：参考 `test_eth_batch_personal_sign`（约第 1415 行），但针对交易，调用 FFI dispatcher，覆盖 prepay + stake 这一对组合及错误密码反例，并加入一个 per-item path 的端到端用例。
- **imkey 测试（`imkey-core/ikc/src/ethereum_signer.rs`）**：把现有 fixture（`test_sign_eth_transaction_eip1559`、`..._legacy`、`..._multi_access_list`）封装成批量后再跑，断言每一笔结果一致；与该文件其余用例一样以 `bind_test()` 守护。
- **APDU 拆离单测**：抽出非 APDU 辅助函数（如 `Transaction::pack_apdu_payload`），添加一个不依赖绑定设备的单测，覆盖批量场景下的 TLV / RLP 打包逻辑。

### 7. 文档

- 在 `token-core/tcx-docs` 与 `imkey-core/ikc-docs` 增加新动作的说明：请求/响应形态、共享 path 与 per-item path 的两种用法、不同引擎的批量上限（2048 vs 10）、错误信息格式（`"eth_batch_sign_tx failed at index {i}: {source}"`）、以及 imKey 路径仍需逐笔确认的提示，避免 host UX 误以为只需一次确认。

## Risks / Trade-offs

- **硬件路径上的"半批" UX**。我们刻意不动固件，因此当 imKey 用户在第二次确认时拒绝，第一笔签名实际上已经在我们内存里产生——但 host 还没有拿到（我们会中止整批并丢弃部分结果）。钱包 UX 必须清楚提示"需要确认全部交易"，否则用户会困惑。我们之所以选择 all-or-nothing 而不是返回部分结果，是为了避免 host 只广播第 1 笔而没有第 2 笔——而这正是本提案要消除的故障模式。
- **批量过程中设备掉线（BLE/USB）**。同样的缓解：错误体里带 `index`（字符串中），host 可以以剩余尾段为新的批量、调整 nonce 后重发。
- **per-item path 增加复杂度**。每笔可独立 path 让 imkey 的批量循环不能纯粹合并 `get_xpub` 调用——同 path 时可复用缓存，不同 path 时必须重新派生。我们用"item 间 path 是否相同"作为是否复用 `get_xpub` 结果的判据，保证逻辑可读且开销可控。
- **`tcx` 上限 2048 的内存与时延**。2048 笔在内存中存放 raw + signed 两份字节切片估算 < 10MB，可接受；FFI 单次返回的 protobuf 序列化也在亚秒级。如果未来发现 host 在更小批量上就遇到性能问题，可以下调该常量而无需改协议。
- **错误下标走字符串**。host 需要 parse 字符串才能拿到下标。考虑到与既有 `sign_tx` / `eth_batch_personal_sign` 的错误模型必须保持一致，结构化错误会让此 API 成为整个 SDK 的孤例，反而造成更高的维护成本。我们用稳定的固定字符串模板（`"eth_batch_sign_tx failed at index {i}: ..."`）以正则可靠提取下标。
- **测试覆盖（硬件路径）**。imkey 大部分测试需要绑定测试设备才能运行。缓解：把 `batch_sign` 中非 APDU 部分（TLV 打包、顺序、错误包装）抽成 `pack_for_apdu(&item)` 等辅助函数，使其可在无设备环境下做单元测试。
- **proto 重新生成的扰动**。在 `tcx-proto` 与 `ikc-proto` 中新增消息会触发两个 crate 的 Rust 代码重新生成。缓解：本次改动是 append-only，diff 体量小、便于 review。
