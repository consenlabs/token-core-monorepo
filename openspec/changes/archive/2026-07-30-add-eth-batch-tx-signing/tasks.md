## 1. 接口与协议

- [x] 1.1 在 token-core 定义链无关的 `SignTxsParam` / `SignTxsItem` / `SignTxsResult`，保留 password / derivedKey、外层默认 path、逐 item path 和有序输出。
- [x] 1.2 在 imkey-core 的 ETH protobuf 中定义批量输入/输出；每笔包含交易、设备展示字段、sender 和可选 path，并生成对应 Rust 类型。
- [x] 1.3 注册公共动作 `sign_txs` 的 ETHEREUM 路由，保持现有 `sign_tx`、`eth_batch_personal_sign` 和 protobuf 字段编号不变。

## 2. 核心实现

- [x] 2.1 token-core 支持最多 2048 笔 ETH 交易：整批只解锁一次，合并 effective path，顺序复用单签，返回 signature / txHash / fromAddress，任一失败不返回部分结果。
- [x] 2.2 imkey-core 支持最多 100 笔 ETH 交易：设备访问前完成整批静态校验，逐笔复用现有 `Transaction::sign`，保留每笔 sender 校验和物理确认，不缓存设备会话。
- [x] 2.3 空批量、超限、空 effective path、缺失字段、非法交易和不支持链均返回稳定错误；item 错误包含 `sign_txs failed at index {i}`。

## 3. 测试与验证

- [x] 3.1 token-core 单元及 API 测试覆盖 legacy / EIP-1559、批量与单签等价、共享/覆盖 path、password / derivedKey、顺序、上限、fromAddress 和 all-or-nothing。
- [x] 3.2 imkey-core 测试覆盖无需设备的 preflight 分支，并保留由 `bind_test()` 守护的批量成功路径测试。
- [x] 3.3 ETH `sign_txs`、现有 ETH 单签及同分支 TRON 路由回归通过；格式检查和受影响 crate 的静态检查完成。

## 4. 文档与签收

- [x] 4.1 更新 token-core 与 imkey-core API 文档：覆盖请求/响应、共享与逐笔 path、批量上限、错误格式、fromAddress/sender 安全语义、host UX、stake 流程和硬件逐笔确认，并交叉链接 `eth_batch_personal_sign`。
- [x] 4.2 代码与接口评审通过后归档 `add-eth-batch-tx-signing`。

> 本任务表只跟踪仓库内核心协议、实现、测试和 API 文档。示例工程生成绑定、移动端高级封装、固件批量协议、真实设备发布签收和发布流程不作为本变更的完成门槛。
