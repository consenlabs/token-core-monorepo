## 1. Protobuf schema

- [ ] 1.1 在 `token-core/tcx-proto/src/api.proto` 新增 `EthBatchSignTxParam` / `EthBatchSignTxItem` / `EthBatchSignTxResult` 消息：`Param` 携带 `id`、`oneof key { password / derivedKey }`、`chainType`、外层默认 `path`、`network`、`segWit`、`repeated EthBatchSignTxItem items`；`Item` 携带 `transaction.EthTxInput tx` 与可选 `string path`（空字符串表示回落外层 path）；`Result` 携带 `repeated transaction.EthTxOutput outputs`。
- [ ] 1.2 在 `imkey-core/ikc-proto/src/eth.proto` 新增 `EthBatchTxInput` / `EthBatchTxItem` / `EthBatchTxOutput` 消息。每个 item 携带 `EthTxInput tx`，外加 `payment`、`receiver`、`sender`、`fee` 四个由 host 提供的设备展示字段，以及可选 `string path`（空字符串表示回落 `SignParam.path`），用于设备渲染逐笔提示与跨地址批量。
- [ ] 1.3 运行 `token-core/tcx-proto` 与 `imkey-core/ikc-proto` 既有的 proto 生成脚本，重新生成 `token-core/tcx/src/api.rs`、`token-core/tcx-eth/src/transaction.rs` 与 `imkey-core/ikc-wallet/coin-ethereum/src/ethapi.rs` 中的 Rust 类型。
- [ ] 1.4 把 proto 改动同步到示例工程（`token-core/tcx-examples/RN/...`、`token-core/tcx-examples/iOSExample/...`、`imkey-core/ikc-examples/...`、`imkey-core/mobile-sdk/android/...`），保持各端生成绑定一致。

## 2. token-core (tcx) 实现

- [ ] 2.1 在 `token-core/tcx-eth/src/signer.rs` 新增 `pub fn batch_sign_transaction(keystore: &mut Keystore, items: &[EthBatchSignTxItem], default_path: &str) -> Result<Vec<EthTxOutput>>`。循环内为每个 item 折叠出有效 path（`item.path` 非空则用 item.path，否则用 default_path），复用现有 `Transaction::try_from(&EthTxInput)` 与 `secp256k1_ecdsa_sign_recoverable`。
- [ ] 2.2 在签名循环内把每笔的错误用 `"batch_sign_tx failed at index {i}: {source}"` 包裹，保留失败位置；`{source}` 取底层 anyhow Error 的 Display 输出。
- [ ] 2.3 在新函数旁定义 `pub const ETH_MAX_BATCH_SIZE: usize = 2048;`。
- [ ] 2.4 在 `token-core/tcx/src/handler.rs` 新增 `pub(crate) fn batch_sign_tx(data: &[u8]) -> Result<Vec<u8>>`，参考现有 `eth_batch_personal_sign`（`token-core/tcx/src/handler.rs:1671`）。在解锁前先做 `items.is_empty()` 与 `items.len() <= ETH_MAX_BATCH_SIZE` 检查、外层 path 与每个 item.path（非空时）的 BIP-32 合法性检查；执行单次 `KeystoreGuard::unlock`；调用 `batch_sign_transaction`；编码 `EthBatchSignTxResult`。
- [ ] 2.5 添加 `impl_to_key!(crate::api::batch_sign_tx_param::Key);`，让新 param 的 `oneof key` 与 `tcx-crypto::Key` 对接。
- [ ] 2.6 在 `token-core/tcx/src/lib.rs` 注册 dispatcher 分支 `"batch_sign_tx" => landingpad(|| batch_sign_tx(&action.param.unwrap().value))`（紧邻 `"eth_batch_personal_sign"`，约第 131 行），并在 `use` 块（约第 27 行）引入新 handler。

## 3. imkey-core (ikc) 实现

核心约束：**`imkey-core/ikc-wallet/coin-ethereum/src/transaction.rs` 不动**——单笔 `Transaction::sign` 不重构、不抽 helper、不新增 `batch_sign`。批量层是 `imkey-core/ikc/src/ethereum_signer.rs` 内的薄循环，每笔 item 直接调用现有单笔 `Transaction::sign`，确保单笔路径零回归、所有现有用例无需重新校准。

- [ ] 3.1 在 `imkey-core/ikc/src/ethereum_signer.rs` 顶部定义 `pub const ETH_MAX_BATCH_SIZE: usize = 100;`。
- [ ] 3.2（可选重构，不修改语义）把现有 `sign_eth_transaction` 内部把 `EthTxInput` 解析为 `Transaction` + `chain_id` 的逻辑（`imkey-core/ikc/src/ethereum_signer.rs:14-89`）抽成私有 helper `fn build_eth_transaction(input: &EthTxInput) -> Result<(Transaction, u64)>`，让单笔与批量两条路径共用同一段解析。`sign_eth_transaction` 改为 `let (eth_tx, chain_id) = build_eth_transaction(&input)?; eth_tx.sign(Some(chain_id), ...)`，行为完全不变。
- [ ] 3.3 在 `imkey-core/ikc/src/ethereum_signer.rs` 新增 `pub fn sign_eth_batch_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>>`：
  1. 解码 `EthBatchTxInput`；做整批前置校验：`items.is_empty()` / `items.len() <= ETH_MAX_BATCH_SIZE` / 外层 `sign_param.path` 与每个 item.path（非空时）的 BIP-32 合法性（`check_path_validity`）/ 每个 item.sender 非空。任一失败 SHALL 在触达设备会话之前以 `"batch_sign_tx failed at index {i}: {source}"` 形式返回（整批级失败下标可置 0 或省略下标）。
  2. 顺序遍历 items，对每个 item：
     - 折叠出有效 path：`if item.path.is_empty() { sign_param.path } else { item.path }`。
     - 调用 `build_eth_transaction(&item.tx)?` 得到 `(eth_tx, chain_id)`。
     - 直接调用现有 `eth_tx.sign(Some(chain_id), &effective_path, &item.payment, &item.receiver, &item.sender, &item.fee)?` 拿到 `EthTxOutput`。
     - 把 `Result::Err` 用 `"batch_sign_tx failed at index {i}: {source}"` 包装后短路返回，**不**返回任何部分结果。
  3. 把所有 outputs 装进 `EthBatchTxOutput { outputs }` 并 `encode_message` 返回。
- [ ] 3.4 在 `imkey-core/ikc/src/lib.rs` 紧邻 `"sign_tx"` 处注册 dispatcher 分支 `"batch_sign_tx"`：解码 `SignParam`，按 `param.chain_type.as_str()` 做与 `sign_tx` 一致的 chain dispatch：仅 `"ETHEREUM"` 调用 `ethereum_signer::sign_eth_batch_transaction(&sign_param.input.as_ref().unwrap().value, &sign_param)`，其余一律返回 `Err(anyhow!("batch_sign_tx unsupported_chain"))`。动作名采用 chain-neutral 形式（`batch_sign_tx`，非 `eth_batch_sign_tx`）是为后续接入其他链的 batch 后端预留同一个 dispatcher 入口；host 误传非 ETH `chain_type` 直接被这一层拒绝，可观测性与 `sign_tx` 的 unsupported_chain 路径完全对齐。

## 4. 测试

- [ ] 4.1 在 `tcx-eth/src/signer.rs` 新增单元测试：
  - `test_batch_sign_eip155_and_eip1559_matches_single_call`：针对该文件中现有每个 fixture，分别按单笔与批量两种方式签名（item.path 留空），断言 `signature` + `tx_hash` 逐字节一致。
  - `test_batch_sign_access_list_preserved`：保证 access-list 字段往返不变。
  - `test_batch_sign_per_item_path`：构造 3 笔批量，第 1、2 笔的 item.path 分别为 `m/44'/60'/0'/0/0`、`m/44'/60'/0'/0/1`，第 3 笔留空回落外层 path；断言三笔解码后的 `from` 地址与三个 path 各自派生出的地址一致。
  - `test_batch_sign_aborts_on_bad_to_with_index`：第 1 笔合法、第 2 笔 `to` 非法；断言错误信息正则匹配 `failed at index 1`，且无任何部分输出。
  - `test_batch_sign_invalid_item_path_with_index`：某 item.path 不符合 BIP-32；断言错误信息匹配该 item 的下标。
  - `test_batch_sign_size_limit_2048`：2048 笔通过、2049 笔被拒（不需要真签，`std::iter::repeat` 同一个 fixture 即可，超限分支应在签名前返回）。
  - `test_batch_sign_empty_input_rejected`：空批量被拒。
- [ ] 4.2 在 `token-core/tcx/tests/sign_test.rs` 增加端到端测试，参考 `test_eth_batch_personal_sign`（约第 1415 行），通过 FFI dispatcher 用 `EthBatchSignTxParam` 覆盖：
  - 共享 path 的 prepay + stake 组合；
  - per-item path 的跨地址批量；
  - 错误密码反例。
- [ ] 4.3 在 `imkey-core/ikc/src/ethereum_signer.rs` 添加由 `bind_test()` 守护的批量端到端测试：复用现有 fixture（`test_sign_eth_transaction_eip1559`、`..._legacy`、`..._multi_access_list`）作为 item，分别构造 N=1 / N=2 / N=3（混合 legacy + EIP-1559 + access-list）的批量请求；对每个 item 同时跑一次现有单笔 `sign_eth_transaction`，断言批量 `outputs[i]` 与单笔输出 `signature` / `tx_hash` 逐字节相同。
- [ ] 4.4 在 `imkey-core/ikc/src/ethereum_signer.rs` 添加无设备依赖的批量 wrapper 单测（不需要 `bind_test()`，因为以下分支都在 `select_applet` 之前返回）：
  - 空批量：`items` 为空时返回错误，错误信息匹配 `invalid_param`。
  - 超限批量：101 笔（哑数据即可）时返回错误，错误信息含上限 100。
  - 非法 item.path：某个 item 的 path 不符合 BIP-32 时整批被拒，错误信息含 `failed at index N`。
  - 缺失 tx 字段：item.tx 为 `None` 时整批被拒，错误信息含失败下标。
  - sender 为空：item.sender 为空字符串时整批被拒（与单笔 `sign_tx` 在该字段缺失时的行为对齐），错误信息含失败下标。

## 5. 文档

- [ ] 5.1 更新 `token-core/tcx-docs`（markdown / mdbook）：新动作的请求/响应、共享 path 与 per-item path 用法、批量上限 2048、错误格式（`"batch_sign_tx failed at index {i}: {source}"`），以及 stake 流程的完整调用样例。
- [ ] 5.2 同步更新 `imkey-core/ikc-docs`：新动作的请求/响应、`EthBatchTxItem` 中 `payment` / `receiver` / `sender` / `fee` 由 host 提供的契约、共享 path 与 per-item path 用法、批量上限 100，并明确注明本次变更不修改固件——imKey 设备仍要求逐笔在物理键上确认（host UX 应据此提示用户准备按 N 次确认，并自行评估业务可接受的最大笔数）。
- [ ] 5.3 在既有 `eth_batch_personal_sign` 文档段落处交叉链接到新动作，便于调用方一并发现两类批量入口。

## 6. 校验与签收

- [ ] 6.1 运行 `openspec validate add-eth-batch-tx-signing --strict`，解决任何结构性问题。
- [ ] 6.2 运行 `cargo test -p tcx-eth`、`cargo test -p tcx`、`cargo test -p coin-ethereum`、`cargo test -p ikc`，确保所有套件通过（涉及硬件的 imkey 套件仍需绑定测试设备）。
- [ ] 6.3 运行 `cargo clippy --all-targets --workspace -- -D warnings`，确保未引入新的告警。
- [ ] 6.4 review 通过后用 `openspec archive add-eth-batch-tx-signing` 归档本次变更，新 spec 会被提升至 `openspec/specs/eth-batch-tx-signing/spec.md`。
