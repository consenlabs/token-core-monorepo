## Why

驱动这次改动的最近一个具体场景是 ETH staking——它需要先发一笔 prepay（approve / deposit）再紧跟一笔 stake。但梳理过程中我们发现，"必须一组发出的多笔 ETH 交易"远不止 staking：

- **少量批次（个位数）**：staking 的 prepay + stake、合约批量 approve、Layer-2 桥跨链的 lock + claim 等。
- **中量批次（几十笔）**：dApp 一次性下发的多笔 meta-tx、复合 DeFi 策略一键执行。
- **大量批次（上百乃至上千笔）**：批量空投、批量归集出账、企业财务批处理、链上分析与回放工具等。

无论是哪一档，当前两个签名引擎（`token-core/tcx` 负责软件 keystore 签名，`imkey-core/ikc` 负责 imKey 硬件钱包签名）都只暴露单笔交易的 `sign_tx` 接口。host 钱包必须把 N 笔交易拆成 N 次完整的 SDK 调用：每一笔都要单独触发解锁 / 设备确认、单独走一次 FFI 往返、自己兜底 nonce 顺序与中途失败恢复。在最常见的 stake 两笔场景中，这表现为：

1. 第一次提示用户输入密码（或 BLE/USB 设备确认），构建并发送 prepay 交易；
2. 整套流程再走一遍：又一次密码弹窗 / 设备确认 / FFI 调用，才能发出 stake 交易。

结果是 N 次独立的鉴权时刻、N 倍的 FFI 流量，以及一个非原子的 UX 窗口——用户可以在任意两笔之间退出、丢失 nonce 顺序，或最终只广播了前缀的若干笔。host SDK 还要自行处理 nonce 排序、部分失败恢复、以及在中途重新提示用户。

本提案把"任意 N 笔 ETH 交易"放到**一次** `eth_batch_sign_tx` 调用中签名（N 由各引擎的批量上限约束：`tcx` 至 2048，`ikc` 至 10）。两个引擎各自的收益（以 N 笔为例）对照如下：

| 维度 | 现状（单笔 `sign_tx` × N） | 本提案后（`eth_batch_sign_tx` × 1） |
|---|---|---|
| FFI 调用次数 | N | **1** |
| `tcx`：keystore 解锁 / 密码弹窗 | N 次 | **1 次** |
| `ikc`：ETH applet `select_applet` | N 次 | **1 次** |
| `ikc`：用户在设备屏上的逐笔确认 | N 次 | N 次（**不变**，本提案不改固件，详见 design.md Non-Goals） |
| 失败原子性 | 第 k 笔成功、第 k+1 笔被取消时 host 已经把前 k 笔广播出去 | **all-or-nothing**：任何一笔失败则整批中止，不返回部分签名 |
| nonce 顺序 / 防交错 | host SDK 自行兜底 | SDK 边界保证逐笔有序签名 |

也就是说，**对 `tcx`：从 N 次密码输入降到 1 次**（无论 N 是 2 还是 200 都一样）；**对 `ikc`：FFI 与设备会话各从 N 次降到 1 次，但设备屏上的物理确认仍是逐笔的**——这是不修改固件这一前提下的物理上限，本提案明确不去改它。

`tcx` 中已有的 `eth_batch_personal_sign` 已经为"消息批量签名"验证了这一模式。本提案把同一模式扩展到 **ETH 交易**，并在 `ikc`（硬件）侧也实现一份对应能力。

## What Changes

- 新增 SDK 动作 `eth_batch_sign_tx`，通过现有的 `call_tcx_api` / `call_imkey_api` dispatcher 同时在两个引擎上暴露。
- 在 `token-core/tcx-proto/src/api.proto` 与 `imkey-core/ikc-proto/src/eth.proto` 中新增 protobuf 消息：
  - `tcx`：`EthBatchSignTxParam` / `EthBatchSignTxResult`，并引入 `EthBatchSignTxItem { EthTxInput tx; string path; }`，让每笔交易可选择性地覆盖外层共享 `path`。
  - `ikc`：`EthBatchTxInput` / `EthBatchTxItem` / `EthBatchTxOutput`，每个 item 与现有 `SignParam` 一一对应地携带 `payment` / `receiver` / `sender` / `fee` 显示字符串，并新增可选 `path` 字段以覆盖 `SignParam.path`。
- `tcx` 侧：在 `tcx_eth::signer` 实现 `batch_sign_transaction`，使用单次 `KeystoreGuard::unlock`，按 item 各自的有效 `path`（item.path 优先，回落到外层 `path`）调用 `keystore.secp256k1_ecdsa_sign_recoverable`；通过 `handler::eth_batch_sign_tx` 串起整条链路，并注册到 dispatcher。
- `ikc` 侧：在 `coin_ethereum::transaction::Transaction` 实现 `batch_sign`，整批只调用一次 ETH applet 的 `select_applet`，然后逐笔走 `prepare_sign` + `sign_digest` + `get_xpub`（不修改固件）。当 item 的有效 `path` 与上一笔相同时复用上一次 `get_xpub` 的结果，否则重新派生；通过 `ethereum_signer::sign_eth_batch_transaction` 与 `call_imkey_api` dispatcher 串接。
- 明确并文档化"全成功或全失败"语义（任何一笔失败则整批中止，错误信息形如 `"eth_batch_sign_tx failed at index {i}: {source}"`，与现有 `sign_tx` / `eth_batch_personal_sign` 走相同的字符串错误返回路径）。
- 设定不同的批量上限：**`tcx` 上限为 2048**（软件签名无设备瓶颈，给链上分析、批量归集等场景留足余量），**`ikc` 上限为 10**（避免硬件设备会话过长 / 超时）。两端各以单独命名常量定义。
- 在 `tcx-eth` 与 `imkey-core/ikc` 添加单元测试，并在 `token-core/tcx/tests/sign_test.rs` 添加端到端测试，覆盖：等价性（与逐笔 `sign_tx` byte-equal）、原子性（错误下标）、上限拒绝、空批量、共享 path 与 per-item path 覆盖。

明确不在本提案范围内的事项（在 design.md 的 Non-Goals 中再次强调）：imKey 设备端"一次确认 N 笔"的固件改造、EIP-712 批量签名、以及非以太坊链（TRON、Cosmos 等）的批量交易签名（如有需要可在后续独立提案中处理）。

## Capabilities

### New Capabilities

- `eth-batch-tx-signing`：单次 SDK 调用接受一个有序的 ETH 交易输入列表（每笔可选指定独立派生路径），对每一笔逐个签名（保留 nonce、chain id、tx 类型、EIP-1559 费率字段、access list 等所有原有字段），并按输入顺序返回对应的已签名交易。该能力同时覆盖软件 keystore 路径（`tcx`，上限 2048）与 imKey 硬件路径（`ikc`，上限 10）。

### Modified Capabilities

<!-- 当前 openspec/specs/ 下尚无既有的 capability spec，因此无需做 delta。 -->

## Impact

- **受影响的 crate / 模块**：
  - `token-core/tcx-proto/src/api.proto`（新增 `EthBatchSignTxParam` / `EthBatchSignTxItem` / `EthBatchSignTxResult`），重新生成 `token-core/tcx/src/api.rs`。
  - `token-core/tcx-eth/src/signer.rs`（新增 `batch_sign_transaction`，常量 `ETH_MAX_BATCH_SIZE: usize = 2048`）。
  - `token-core/tcx/src/handler.rs` 与 `token-core/tcx/src/lib.rs`（新增 handler + dispatcher 入口）。
  - `imkey-core/ikc-proto/src/eth.proto`（新增 `EthBatchTxInput` / `EthBatchTxItem` / `EthBatchTxOutput`，每个 item 含可选 `path`），重新生成 `imkey-core/ikc-wallet/coin-ethereum/src/ethapi.rs`。
  - `imkey-core/ikc-wallet/coin-ethereum/src/transaction.rs`（新增 `batch_sign`，常量 `ETH_MAX_BATCH_SIZE: usize = 10`）。
  - `imkey-core/ikc/src/ethereum_signer.rs`（新增 `sign_eth_batch_transaction`）。
  - `imkey-core/ikc/src/lib.rs`（新增 `eth_batch_sign_tx` dispatcher 分支）。
- **API 影响面**：纯增量。现有 `sign_tx` 的形态与行为完全不变，对当前调用方零破坏。
- **硬件影响（imKey）**：不修改固件。硬件路径下用户仍然需要逐笔在设备上确认；本提案带来的收益在于一次 FFI、一次 applet 选择、严格有序执行、原子错误反馈。文档会明确说明这一点，避免 host SDK / UX 误以为只需一次确认。
- **依赖**：无新增依赖。
- **测试**：在 `tcx-eth`、`coin-ethereum`、`ikc` 与 `tcx/tests/sign_test.rs` 增加正反用例。
- **文档**：更新 `token-core/tcx-docs` 与 `imkey-core/ikc-docs`，描述新动作的请求/响应、共享 path 与 per-item path 用法、错误语义、以及两端不同的批量上限。
