## Why

当前 `token-core` 与 `imkey-core` 的 TRON 交易签名只提供单笔 `sign_tx`：host 对 N 笔有序交易必须执行 N 次 FFI 调用，软件钱包要重复解锁，硬件钱包也缺少统一的顺序执行和整批错误边界。本轮工作在同一分支中为 ETH 和 TRON 首次共同引入链无关的 `sign_txs` 动作；本变更定义其中的 TRON 能力，使一组相关交易能在一次 SDK 调用中完成签名并按输入顺序返回。

## What Changes

- 与 ETH 批签共同新增链无关的 `sign_txs` dispatcher，第一批支持 `chainType = "ETHEREUM"` 与 `chainType = "TRON"`；现有单笔 `sign_tx` 行为不变。
- `token-core` 为 ETH/TRON 共同定义 `SignTxsParam` / `SignTxsItem` / `SignTxsResult`：TRON item 的 `input` 保存 protobuf 编码的 `transaction.TronTxInput`，并支持 item path 覆盖外层共享 path。
- `imkey-core` 在 `tronapi` 中新增 `SignTxsInput` / `SignTxsItem` / `SignTxsItemOutput` / `SignTxsOutput`；每个 item 携带交易、设备展示字段、期望 sender 和可选 path。
- 每笔输出包含单笔等价的 `signature`、由 `SHA256(raw_data)` 得到且不带 `0x` 的 TRON `txHash`，以及本次签名密钥对应的 Base58Check `fromAddress`。
- 采用有序、all-or-nothing 语义：任一 item 失败时整批中止、不返回部分签名，逐笔错误包含零基下标；空批量和超限属于批级错误，不带下标且两端文案统一。
- `token-core` 在一次 keystore 解锁内顺序签名，上限 2048；`imkey-core` 上限 100，并对每个 item 薄循环复用现有 `TronSigner::sign_transaction`，因此设备确认及现有 APDU 流程仍逐笔发生。
- 在解锁或设备交互前完成空批量、上限、输入编码、`raw_data`、sender 和 effective path 的静态校验。
- 批签一律拒绝空 effective path，这是相对 TRON 单笔签名的刻意收紧；私钥 keystore 请求因此也必须显式给出满足 TRON 约束的 path，需要在集成文档中说明。
- 增加对应的单元测试、dispatcher 端到端测试和集成文档任务。

## Capabilities

### New Capabilities

- `tron-batch-tx-signing`：在 token-core 软件 keystore 与 imkey-core 硬件钱包中，通过一次 `sign_txs` 调用有序地签署多笔 TRON 交易，支持共享或逐笔覆盖派生路径、可核验输出、批量上限与原子错误语义。

### Modified Capabilities

<!-- openspec/specs/ 当前没有需要修改的既有 capability spec。ETH 与 TRON 的 batch capability 在同一分支、同一轮交付中分别定义。 -->

## Impact

- **协同变更**：本提案与同一分支中的 `add-eth-batch-tx-signing` 共同组成 `sign_txs` 的首次交付；两份提案分别定义 TRON/ETH 的链专属行为，并共享 token-core 请求/响应信封和 dispatcher 命名，不存在先后依赖。
- **token-core**：后续实现将影响 `tcx-proto` 的通用批签注释、`tcx-tron` signer、`tcx` handler/dispatcher 以及 TRON 批签测试；现有 protobuf 字段保持兼容。
- **imkey-core**：后续实现将扩展 `ikc-proto/src/tron.proto`、生成 `coin-tron` Rust 类型，并修改 `ikc/src/tron_signer.rs` 与 `ikc/src/lib.rs` 的批签路由。
- **API 兼容性**：ETH/TRON 批签均为纯增量能力；没有字段重排或删除，既有 TRON `sign_tx` 与 TRON `sign_message` 不变。
- **硬件与依赖**：不修改 imKey 固件或 APDU 协议，不新增第三方依赖；每笔交易仍需要一次设备物理确认。
- **明确排除**：TRON 消息批签、多签聚合、广播、自动补充既有签名、设备会话缓存、移动端高级封装。
