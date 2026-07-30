## 1. 接口与协议

- [x] 1.1 扩展链无关动作 `sign_txs` 支持 `chainType = "TRON"`；token-core 继续复用现有 `SignTxsParam` / `SignTxsItem` / `SignTxsResult`，不修改字段编号和 ETH 调用结构。
- [x] 1.2 在 imkey-core 的 TRON protobuf 中新增 `SignTxsInput` / `SignTxsItem` / `SignTxsItemOutput` / `SignTxsOutput`，按设计保留 tag 5、使用 `path = 6`，并生成对应 Rust 类型。
- [x] 1.3 在 token-core 和 imkey-core dispatcher 中增加 TRON 路由，同时保持 ETHEREUM 路由和现有 TRON 单签/消息签名不变。

## 2. token-core 实现

- [x] 2.1 支持最多 2048 笔 TRON 交易：解锁前完成 protobuf、raw_data 和 effective path 整批预检，整批只解锁一次。
- [x] 2.2 顺序复用现有 TRON 单签，返回单签等价 signature、无 `0x` 的 SHA-256 txID 和 Base58Check fromAddress；任一失败返回带下标错误且不返回部分结果。
- [x] 2.3 保持单签允许空 path 的历史行为；批签要求非空且符合 TRON coin type `195'` 的 effective path，私钥 keystore 使用合法占位 path。

## 3. imkey-core 实现

- [x] 3.1 支持最多 100 笔 TRON 交易，在任何设备访问前完成空批量、超限、缺失 tx/sender、raw_data 和 effective path 校验。
- [x] 3.2 每笔构造独立 `SignParam` 并调用现有 `TronSigner::sign_transaction`，保留 applet、xpub、sender 校验、APDU 签名和物理确认流程。
- [x] 3.3 按输入顺序返回 `TronTxOutput`、txID 和设备校验后的 fromAddress；任一 item 失败立即中止且不返回前缀结果。

## 4. 测试与文档

- [x] 4.1 token-core 测试覆盖批量/单签等价、共享/覆盖 path、password / derivedKey、私钥 keystore、顺序、txID/fromAddress、2048/2049 边界和错误下标。
- [x] 4.2 imkey-core 单元测试覆盖无设备 preflight；`call_imkey_api` E2E 覆盖完整 dispatcher 调用链，硬件成功/拒绝场景以 `#[ignore]` 隔离。
- [x] 4.3 ETH/TRON `sign_txs` 及现有 TRON `sign_tx` / `sign_message` 回归通过；格式、clippy 和 strict OpenSpec 校验完成。
- [x] 4.4 更新 token-core 与 imkey-core 集成说明，记录请求结构、path 规则、上限、输出语义、N 次设备确认和 all-or-nothing 行为。

## 5. 签收

- [x] 5.1 代码与接口评审通过后归档 `add-tron-batch-tx-signing`。

> 本任务表只跟踪仓库内核心协议、实现、测试和必要集成说明。示例/SDK 生成绑定、移动端高级封装、固件/APDU 批量优化、真实设备发布签收和发布流程不作为本变更的完成门槛。
