## 1. Protobuf schema

- [ ] 1.1 在 `token-core/tcx-proto/src/api.proto` 新增 `EthBatchSignTxParam` / `EthBatchSignTxItem` / `EthBatchSignTxResult` 消息：`Param` 携带 `id`、`oneof key { password / derivedKey }`、`chainType`、外层默认 `path`、`network`、`segWit`、`repeated EthBatchSignTxItem items`；`Item` 携带 `transaction.EthTxInput tx` 与可选 `string path`（空字符串表示回落外层 path）；`Result` 携带 `repeated transaction.EthTxOutput outputs`。
- [ ] 1.2 在 `imkey-core/ikc-proto/src/eth.proto` 新增 `EthBatchTxInput` / `EthBatchTxItem` / `EthBatchTxOutput` 消息。每个 item 携带 `EthTxInput tx`，外加 `payment`、`receiver`、`sender`、`fee` 四个由 host 提供的设备展示字段，以及可选 `string path`（空字符串表示回落 `SignParam.path`），用于设备渲染逐笔提示与跨地址批量。
- [ ] 1.3 运行 `token-core/tcx-proto` 与 `imkey-core/ikc-proto` 既有的 proto 生成脚本，重新生成 `token-core/tcx/src/api.rs`、`token-core/tcx-eth/src/transaction.rs` 与 `imkey-core/ikc-wallet/coin-ethereum/src/ethapi.rs` 中的 Rust 类型。
- [ ] 1.4 把 proto 改动同步到示例工程（`token-core/tcx-examples/RN/...`、`token-core/tcx-examples/iOSExample/...`、`imkey-core/ikc-examples/...`、`imkey-core/mobile-sdk/android/...`），保持各端生成绑定一致。

## 2. token-core (tcx) 实现

- [ ] 2.1 在 `token-core/tcx-eth/src/signer.rs` 新增 `pub fn batch_sign_transaction(keystore: &mut Keystore, items: &[EthBatchSignTxItem], default_path: &str) -> Result<Vec<EthTxOutput>>`。循环内为每个 item 折叠出有效 path（`item.path` 非空则用 item.path，否则用 default_path），复用现有 `Transaction::try_from(&EthTxInput)` 与 `secp256k1_ecdsa_sign_recoverable`。
- [ ] 2.2 在签名循环内把每笔的错误用 `"eth_batch_sign_tx failed at index {i}: {source}"` 包裹，保留失败位置；`{source}` 取底层 anyhow Error 的 Display 输出。
- [ ] 2.3 在新函数旁定义 `pub const ETH_MAX_BATCH_SIZE: usize = 2048;`。
- [ ] 2.4 在 `token-core/tcx/src/handler.rs` 新增 `pub(crate) fn eth_batch_sign_tx(data: &[u8]) -> Result<Vec<u8>>`，参考现有 `eth_batch_personal_sign`（`token-core/tcx/src/handler.rs:1671`）。在解锁前先做 `items.is_empty()` 与 `items.len() <= ETH_MAX_BATCH_SIZE` 检查、外层 path 与每个 item.path（非空时）的 BIP-32 合法性检查；执行单次 `KeystoreGuard::unlock`；调用 `batch_sign_transaction`；编码 `EthBatchSignTxResult`。
- [ ] 2.5 添加 `impl_to_key!(crate::api::eth_batch_sign_tx_param::Key);`，让新 param 的 `oneof key` 与 `tcx-crypto::Key` 对接。
- [ ] 2.6 在 `token-core/tcx/src/lib.rs` 注册 dispatcher 分支 `"eth_batch_sign_tx" => landingpad(|| eth_batch_sign_tx(&action.param.unwrap().value))`（紧邻 `"eth_batch_personal_sign"`，约第 131 行），并在 `use` 块（约第 27 行）引入新 handler。

## 3. imkey-core (ikc) 实现

- [ ] 3.1 在 `imkey-core/ikc-wallet/coin-ethereum/src/transaction.rs` 新增 `pub fn batch_sign(items: &[EthBatchTxItem], default_path: &str, chain_id: Option<u64>) -> EthResult<Vec<EthTxOutput>>`。重构 `Transaction::sign` 内部，让逐笔工作（折叠有效 path → TLV 打包 → `prepare_sign` → `get_xpub` 校验 sender → `sign_digest` → 拼装）成为可复用的 helper（建议命名 `sign_one_in_batch`）。
- [ ] 3.2 在 `batch_sign` 中对整批只调一次 `EthApdu::select_applet()`；用一个 `Option<(String, String)>`（path → checksummed address）做缓存：连续多笔使用同一有效 path 时复用上一次 `get_xpub` 结果，不同时则重新派生。每个 item 都断言 `address_checksummed == item.sender`（大小写不敏感比较）。
- [ ] 3.3 在新函数旁定义 `pub const ETH_MAX_BATCH_SIZE: usize = 10;`。
- [ ] 3.4 在 `imkey-core/ikc/src/ethereum_signer.rs` 新增 `pub fn sign_eth_batch_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>>`，结构对齐 `sign_eth_transaction`（`imkey-core/ikc/src/ethereum_signer.rs:14`）。解码 `EthBatchTxInput`，校验大小、空批量、每个 item.path（非空时）的 BIP-32 合法性、每个 item.sender 非空，构建逐笔 `Transaction`，调用 `Transaction::batch_sign(items, &sign_param.path, chain_id)`，编码 `EthBatchTxOutput`。
- [ ] 3.5 把每笔错误用 `"eth_batch_sign_tx failed at index {i}: {source}"` 包裹。
- [ ] 3.6 在 `imkey-core/ikc/src/lib.rs` 紧邻 `"sign_tx"` 处注册 dispatcher 分支 `"eth_batch_sign_tx"`：解码 `SignParam`，要求 `chain_type == "ETHEREUM"`，否则返回 `Err(anyhow!("eth_batch_sign_tx unsupported_chain"))`，然后调用 `ethereum_signer::sign_eth_batch_transaction`。

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
- [ ] 4.3 在 `imkey-core/ikc/src/ethereum_signer.rs` 添加由 `bind_test()` 守护的测试，复用既有 fixture（`test_sign_eth_transaction_eip1559`、`..._legacy`、`..._multi_access_list`）封装为批量，断言每个 item 的输出与单笔一致；并加 1 个 11 笔批量被拒的反例。
- [ ] 4.4 抽出非 APDU 的辅助函数（例如 `Transaction::pack_apdu_payload`），增加一个不依赖绑定设备就能跑的单元测试，覆盖批量场景下的 TLV / RLP 打包逻辑（含 per-item 不同 `payment` / `receiver` / `fee` 字符串）。

## 5. 文档

- [ ] 5.1 更新 `token-core/tcx-docs`（markdown / mdbook）：新动作的请求/响应、共享 path 与 per-item path 用法、批量上限 2048、错误格式（`"eth_batch_sign_tx failed at index {i}: {source}"`），以及 stake 流程的完整调用样例。
- [ ] 5.2 同步更新 `imkey-core/ikc-docs`：新动作的请求/响应、`EthBatchTxItem` 中 `payment` / `receiver` / `sender` / `fee` 由 host 提供的契约、共享 path 与 per-item path 用法、批量上限 10，并明确注明本次变更不修改固件——imKey 设备仍要求逐笔确认。
- [ ] 5.3 在既有 `eth_batch_personal_sign` 文档段落处交叉链接到新动作，便于调用方一并发现两类批量入口。

## 6. 校验与签收

- [ ] 6.1 运行 `openspec validate add-eth-batch-tx-signing --strict`，解决任何结构性问题。
- [ ] 6.2 运行 `cargo test -p tcx-eth`、`cargo test -p tcx`、`cargo test -p coin-ethereum`、`cargo test -p ikc`，确保所有套件通过（涉及硬件的 imkey 套件仍需绑定测试设备）。
- [ ] 6.3 运行 `cargo clippy --all-targets --workspace -- -D warnings`，确保未引入新的告警。
- [ ] 6.4 review 通过后用 `openspec archive add-eth-batch-tx-signing` 归档本次变更，新 spec 会被提升至 `openspec/specs/eth-batch-tx-signing/spec.md`。
