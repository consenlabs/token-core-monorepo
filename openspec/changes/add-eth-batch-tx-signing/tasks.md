## 1. Protobuf schema

- [x] 1.1 在 `token-core/tcx-proto/src/api.proto` 新增 `SignTxsParam` / `SignTxsItem` / `SignTxsResult` 消息：`Param` 携带 `id`、`oneof key { password / derivedKey }`、`chainType`、外层默认 `path`、`network`、`segWit`、`repeated SignTxsItem items`；`Item` 携带 `transaction.EthTxInput tx` 与可选 `string path`（空字符串表示回落外层 path）；`Result` 携带 `repeated SignTxsResult.Output outputs`，其中 `Output { string signature; string txHash; string fromAddress; }`（`fromAddress` 字段来自安全评审 H-3，由 SDK 在签名后基于 effective path 派生）。
- [x] 1.2 在 `imkey-core/ikc-proto/src/eth.proto` 新增 `SignTxsInput` / `SignTxsItem` / `SignTxsItemOutput` / `SignTxsOutput` 消息。每个 item 携带 `EthTxInput tx`，外加 `payment`、`receiver`、`sender`、`fee` 四个由 host 提供的设备展示字段，以及可选 `string path`（空字符串表示回落 `SignParam.path`）。批量输出包装为 `SignTxsItemOutput { EthTxOutput tx; string from_address; }`（`from_address` 由 `Transaction::sign` 内部的"设备派生地址 ≟ sender"校验担保等于 `SignTxsItem.sender`，来自安全评审 H-3）；`SignTxsOutput { repeated SignTxsItemOutput outputs; }`。
- [x] 1.3 运行 `token-core/tcx-proto` 与 `imkey-core/ikc-proto` 既有的 proto 生成脚本，重新生成 `token-core/tcx/src/api.rs` 与 `imkey-core/ikc-wallet/coin-ethereum/src/ethapi.rs` 中的 Rust 类型。
- [ ] 1.4 把 proto 改动同步到示例工程（`token-core/tcx-examples/RN/...`、`token-core/tcx-examples/iOSExample/...`、`imkey-core/ikc-examples/...`、`imkey-core/mobile-sdk/android/...`），保持各端生成绑定一致。

## 2. token-core (tcx) 实现

- [x] 2.1 在 `token-core/tcx-eth/src/signer.rs` 新增 `pub fn sign_txs(keystore: &mut Keystore, items: &[SignTxsItem]) -> Result<Vec<SignedTx>>`，其中 `SignedTx { EthTxOutput output, String from_address }`。循环内对每个 item：(a) 复用 `Keystore::sign_transaction` 完成签名；(b) 调用 `Keystore::get_public_key(SECP256k1, &item.path)` + `EthAddress::from_public_key` 派生 `from_address`；(c) 失败用 `"sign_txs failed at index {i}: {source}"` 包裹。`item.path` 在调用前已和 default path 折叠为生效 path，由 handler 负责。
- [x] 2.2 在签名循环内把每笔的错误用 `"sign_txs failed at index {i}: {source}"` 包裹，保留失败位置；`{source}` 取底层 anyhow Error 的 Display 输出。
- [x] 2.3 在新函数旁定义 `pub const ETH_MAX_BATCH_SIZE: usize = 2048;`。
- [x] 2.4 在 `token-core/tcx/src/handler.rs` 新增 `pub(crate) fn sign_txs(data: &[u8]) -> Result<Vec<u8>>`，参考现有 `eth_batch_personal_sign`。在解锁前依次做：`param.chain_type == "ETHEREUM"` 校验（安全评审 H-1）、`items.is_empty()`、`items.len() <= ETH_MAX_BATCH_SIZE`、外层 path 与每个 item.path（非空时）的 BIP-32 合法性检查、折叠后 `effective_path` 非空（安全评审 H-2，否则会回退到 BIP-32 master `m` 并签出 `from = master-key 地址` 的非预期交易）。然后执行单次 `KeystoreGuard::unlock`，调用 `tcx_eth::sign_txs`，把 `SignedTx` map 成 `sign_txs_result::Output { signature, tx_hash, from_address }` 并 `encode_message(SignTxsResult)`。
- [x] 2.5 添加 `impl_to_key!(crate::api::sign_txs_param::Key);`，让新 param 的 `oneof key` 与 `tcx-crypto::Key` 对接。
- [x] 2.6 在 `token-core/tcx/src/lib.rs` 注册 dispatcher 分支 `"sign_txs" => landingpad(|| sign_txs(&action.param.unwrap().value))`（紧邻 `"eth_batch_personal_sign"`），并在 `use` 块引入新 handler。

## 3. imkey-core (ikc) 实现

核心约束：**`imkey-core/ikc-wallet/coin-ethereum/src/transaction.rs` 不动**——单笔 `Transaction::sign` 不重构、不抽 helper、不新增 `batch_sign`。批量层是 `imkey-core/ikc/src/ethereum_signer.rs` 内的薄循环，每笔 item 直接调用现有单笔 `Transaction::sign`，确保单笔路径零回归、所有现有用例无需重新校准。

- [x] 3.1 在 `imkey-core/ikc/src/ethereum_signer.rs` 顶部定义 `pub const ETH_MAX_BATCH_SIZE: usize = 100;`。
- [x] 3.2 把 `sign_eth_transaction` 内部把 `EthTxInput` 解析为 `Transaction` + `chain_id` 的逻辑抽成私有 helper `fn build_eth_transaction(input: &EthTxInput) -> Result<(Transaction, u64)>`，让单笔与批量两条路径共用同一段解析；同时把原有 4 处 `.unwrap()`（`data` hex / `to` 地址 / `access_list` 地址 / `chain_id` hex）改为结构化 `Result::Err`，避免批量 `failed at index {i}` 包装因 panic 而被跳过。
- [x] 3.3 在 `imkey-core/ikc/src/ethereum_signer.rs` 新增 `pub fn sign_txs(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>>`：
  1. 解码 `SignTxsInput`；做整批前置校验：`items.is_empty()` / `items.len() <= ETH_MAX_BATCH_SIZE` / 外层 `sign_param.path` 与每个 item.path（非空时）的 BIP-32 合法性（`check_path_validity`）/ 每个 item.sender 非空 / 折叠出的 effective path 非空（安全评审 H-2，避免 `Transaction::sign` 在 `select_applet` 之后才拒绝空 path）。任一失败 SHALL 在触达设备会话之前以 `"sign_txs failed at index {i}: {source}"` 形式返回。
  2. 顺序遍历 items，对每个 item：
     - 折叠出有效 path：`if item.path.is_empty() { sign_param.path } else { item.path }`。
     - 调用 `build_eth_transaction(&item.tx)?` 得到 `(eth_tx, chain_id)`。
     - 直接调用现有 `eth_tx.sign(Some(chain_id), &effective_path, &item.payment, &item.receiver, &item.sender, &item.fee)?` 拿到 `EthTxOutput`。
     - 包装为 `SignTxsItemOutput { tx: Some(eth_tx_out), from_address: item.sender.clone() }`（安全评审 H-3：`Transaction::sign` 已校验设备派生地址 ≟ sender，所以这里回显的 sender 就是设备已确认的 from 地址）。
     - 把 `Result::Err` 用 `"sign_txs failed at index {i}: {source}"` 包装后短路返回，**不**返回任何部分结果。
  3. 把所有 outputs 装进 `SignTxsOutput { outputs }` 并 `encode_message` 返回。
- [x] 3.4 在 `imkey-core/ikc/src/lib.rs` 紧邻 `"sign_tx"` 处注册 dispatcher 分支 `"sign_txs"`：解码 `SignParam`，按 `param.chain_type.as_str()` 做与 `sign_tx` 一致的 chain dispatch：仅 `"ETHEREUM"` 调用 `ethereum_signer::sign_txs`，其余一律返回 `Err(anyhow!("sign_txs unsupported_chain"))`。动作名 `sign_txs` 采用 chain-neutral 形式，是为后续接入其他链的 batch 后端预留同一个 dispatcher 入口；host 误传非 ETH `chain_type` 直接被这一层拒绝（与安全评审 H-1 在 tcx 侧补的 chain_type 校验对称）。

## 4. 测试

- [x] 4.1 在 `tcx-eth/src/signer.rs` 新增单元测试：
  - `test_batch_sign_matches_single_call_legacy_and_eip1559`：单笔与批量两种方式签同一组 fixture，断言 `signature` + `tx_hash` 逐字节一致；同时断言每个 batch 输出携带形如 `0x...` 的 42 字符 `from_address`（H-3 结构性检查）。
  - `test_batch_sign_per_item_path`：构造 3 笔 HD 批量，三个 item.path 不同；断言三笔解码后的 `signature` / `tx_hash` 等于在同 path 上调一次单笔 `sign_transaction` 的输出、三笔的 `from_address` 两两不等、且 `batch[0].from_address` 等于通过 `Keystore::get_public_key` + `EthAddress::from_public_key` 临场派生的同一地址（H-3 等价性检查）。
  - `test_batch_sign_aborts_on_bad_to_with_index`：第 1 笔合法、第 2 笔 `to` 非法；断言错误信息匹配 `failed at index 1`，且无任何部分输出。
- [x] 4.2 在 `token-core/tcx/tests/sign_test.rs` 增加端到端测试，通过 FFI dispatcher 用 `SignTxsParam` 覆盖：
  - `test_sign_txs_basic` / `test_sign_txs_per_item_path`：等价性、共享 path、per-item path。
  - `test_sign_txs_empty_rejected` / `test_sign_txs_size_limit_rejected` / `test_sign_txs_aborts_on_bad_to_with_index` / `test_sign_txs_wrong_password_rejected`：原子性、上限、空批量、错误密码。
  - `test_sign_txs_unsupported_chain_rejected`（H-1）：`chain_type: "BITCOIN"` 必须返回 `unsupported_chain`，且 keystore 不被解锁。
  - `test_sign_txs_empty_effective_path_rejected`（H-2）：外层 `path: ""` + item.path: `""` 时整批被拒，错误信息含 `failed at index 0` + `empty derivation path`。
  - `test_sign_txs_from_address_populated`（H-3）：含 per-item path 的批量返回的每个 `Output.from_address` 都是 `0x` + 40 hex 字符；distinct effective path 产出 distinct from_address。
- [x] 4.3 在 `imkey-core/ikc/tests/sign_txs_test.rs` 添加由 `bind_test()` 守护的批量端到端测试：复用现有 fixture 作为 item，分别构造 N=1 / N=1 / N=3（混合 legacy + EIP-1559 + access-list）的批量请求；断言批量 `outputs[i].tx` 与单笔 `sign_eth_transaction` 输出逐字节相同，且 `outputs[i].from_address` 等于该 item 的 `sender`（H-3）。
- [x] 4.4 在 `imkey-core/ikc/tests/sign_txs_test.rs` 添加无设备依赖的批量 wrapper 单测（不需要 `bind_test()`，因为以下分支都在 `select_applet` 之前返回）：
  - 空批量：`items` 为空时返回错误，错误信息匹配 `invalid_param`。
  - 超限批量：101 笔（哑数据即可）时返回错误，错误信息含上限 100。
  - 非法 item.path：某个 item 的 path 不符合 BIP-32 时整批被拒，错误信息含 `failed at index N`。
  - 缺失 tx 字段：item.tx 为 `None` 时整批被拒，错误信息含失败下标。
  - sender 为空：item.sender 为空字符串时整批被拒（与单笔 `sign_tx` 在该字段缺失时的行为对齐），错误信息含失败下标。
  - 空 effective path（H-2）：外层 `sign_param.path: ""` + item.path: `""` 时整批被拒，错误信息含 `failed at index 0` + `empty derivation path`。

## 5. 文档

- [ ] 5.1 更新 `token-core/tcx-docs`（markdown / mdbook）：新动作的请求/响应、共享 path 与 per-item path 用法、批量上限 2048、错误格式（`"sign_txs failed at index {i}: {source}"`）、`Output.fromAddress` 字段的语义与 host UX 推荐做法（密码弹框前展示 `{path → from_address}` 集合），以及 stake 流程的完整调用样例。
- [ ] 5.2 同步更新 `imkey-core/ikc-docs`：新动作的请求/响应、`SignTxsItem` 中 `payment` / `receiver` / `sender` / `fee` 由 host 提供的契约、`SignTxsItemOutput.from_address` 与设备 sender-校验的强等价关系、共享 path 与 per-item path 用法、批量上限 100，并明确注明本次变更不修改固件——imKey 设备仍要求逐笔在物理键上确认（host UX 应据此提示用户准备按 N 次确认，并自行评估业务可接受的最大笔数）。
- [ ] 5.3 在既有 `eth_batch_personal_sign` 文档段落处交叉链接到新动作，便于调用方一并发现两类批量入口。

## 6. 校验与签收

- [ ] 6.1 运行 `openspec validate add-eth-batch-tx-signing --strict`，解决任何结构性问题。
- [x] 6.2 运行 `cargo test -p tcx-eth`（21 passed）、`cargo test -p tcx --test sign_test sign_txs`（9 passed）、`cargo test -p ikc --test sign_txs_test --skip e2e`（6 preflight passed，e2e 用例需绑定测试设备另外验证）。
- [x] 6.3 运行 `cargo fmt --all -- --check`，确保格式干净；`cargo clippy` 仅在 `ikc-transport` / `tonlib-core` 等本提案未触达的既有代码上有预存告警（详见 design.md 与提案的 Non-Goals）。
- [ ] 6.4 review 通过后用 `openspec archive add-eth-batch-tx-signing` 归档本次变更，新 spec 会被提升至 `openspec/specs/eth-batch-tx-signing/spec.md`。
