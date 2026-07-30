## 1. Protobuf 与生成类型

- [x] 1.1 更新 `token-core/tcx-proto/src/api.proto` 中 `SignTxsParam` / `SignTxsItem` / `SignTxsResult` 的注释：把 `chainType` 上的 `// must be "ETHEREUM"` 改为 `ETHEREUM` 与 `TRON`，说明 `input` 按链解释，并写明 `txHash` / `fromAddress` 的格式按链不同（ETH 为带 `0x` 的 keccak256 与 EIP-55 地址，TRON 为不带前缀的 SHA-256 txID 与 Base58Check 地址）；不得修改现有字段编号。
- [x] 1.2 在 `imkey-core/ikc-proto/src/tron.proto` 追加 `SignTxsInput`、`SignTxsItem`、`SignTxsItemOutput` 和 `SignTxsOutput`，字段严格按 design.md 定义：`SignTxsItem` 用 `reserved 5;` 跳过 ETH 的 `fee` 并把 `path` 放在 tag 6，`SignTxsItemOutput` 用 `tx = 1` / `from_address = 2` / `tx_hash = 3`，与 `ethapi` 的同名消息对齐公共字段编号。
- [x] 1.3 运行现有 proto 生成流程，更新 `token-core/tcx/src/api.rs` 的注释和 `imkey-core/ikc-wallet/coin-tron/src/tronapi.rs` 的 Rust 类型，并确认生成 diff 不重排既有字段。
- [ ] 1.4 将新增 TRON protobuf 消息同步到仓库中需要保持一致的示例/SDK 生成绑定；不新增移动端高级批签封装。

## 2. token-core TRON 批签

- [x] 2.1 将 `tcx-tron` 现有 TRON 签名 path 检查（至少 4 层且 coin type 为 `195'`）提取为返回 `Result` 的可复用 helper，保持单笔 `invalid_sign_path` 行为，并允许 handler 在解锁前执行相同校验。
- [x] 2.2 在 `tcx-tron` 定义 `TRON_MAX_BATCH_SIZE: usize = 2048`、已折叠 effective path 的内部 batch item 和包含 signature/txID/fromAddress 的内部结果类型。
- [x] 2.3 实现 `tcx_tron::sign_txs`：按输入顺序复用 `Keystore::sign_transaction`，断言每笔只产生一个签名，计算无 `0x` 的 SHA-256 txID，并用签名所用的同一 effective path 取公钥派生 `TronAddress`（私钥 keystore 下该地址由私钥决定，与 path 无关）。
- [x] 2.4 把 `tcx/src/handler.rs::sign_txs` 顶部现有的 `if param.chain_type != "ETHEREUM"` 硬校验改为 `ETHEREUM` / `TRON` 白名单，并按 `chain_type` 分派到两条批签路径，其他链继续返回 `sign_txs unsupported_chain`。
- [x] 2.5 在 TRON handler 分支中完成整批预检：空批量（`sign_txs batch is empty`）、2048 上限（`sign_txs batch exceeds max size of 2048`）、每个 `TronTxInput` 解码、raw_data hex、effective path 非空与 TRON path 约束；所有预检必须发生在 keystore 查找/解锁前。
- [x] 2.6 在一次 password/derivedKey 解锁内调用 TRON batch signer，将结果映射为现有 `SignTxsResult.Output`，并用 `sign_txs failed at index {i}: {source}` 包装逐笔错误且不返回部分结果。

## 3. imkey-core TRON 批签

- [x] 3.1 在 `ikc/src/tron_signer.rs` 定义 `TRON_MAX_BATCH_SIZE: usize = 100`，新增 `sign_txs(data, sign_param)` 并解码 `tronapi.SignTxsInput`。
- [x] 3.2 实现无设备整批预检：空批量（`sign_txs batch is empty`）、100 上限（`sign_txs batch exceeds max size of 100`）、缺失 tx、空 sender、raw_data hex、effective path 非空和 `check_path_validity`（只做层级校验，不新增 BIP-32 语法校验）；与 item 关联的失败必须带 item 下标，且全部发生在选择 TRON applet 前。
- [x] 3.3 为每个 item 构造继承外层通用字段、使用 item effective path/payment/receiver/sender 的临时 `SignParam`，顺序调用现有 `TronSigner::sign_transaction`，不得重构或缓存底层设备会话。
- [x] 3.4 将每笔单签结果、SHA-256 txID 和设备校验后的 sender 包装为 `SignTxsItemOutput`；任一错误立即中止并丢弃前缀结果。
- [x] 3.5 在 `ikc/src/lib.rs` 的 `"sign_txs"` dispatcher 中新增 `TRON` 分支并同时保留 `ETHEREUM`，其他链继续返回 `sign_txs unsupported_chain`；同步更新该分支上"目前只接入 ETHEREUM"的注释。

## 4. 测试

- [x] 4.1 在 `tcx-tron` 添加批量/逐笔等价测试，覆盖单笔与多笔、输入顺序、共享 path、逐 item path 覆盖、txID、Base58Check fromAddress 和单签数量不变量。
- [x] 4.2 在 `tcx-tron` 或 tcx handler 测试中覆盖空批量（断言 `sign_txs batch is empty`）、2049 笔超限（断言 `sign_txs batch exceeds max size of 2048`）、非法 protobuf、非法 raw_data、空/非法 path、失败下标与 all-or-nothing。
- [x] 4.3 在 `token-core/tcx/tests/sign_test.rs` 通过 `call_tcx_api("sign_txs")` 添加 TRON 端到端用例，覆盖 password、derivedKey、错误凭证、未支持 chain type 和与 `sign_tx` 的签名等价性。
- [x] 4.4 补一个私钥 keystore 的 TRON 批签用例：全空 path 时返回 `failed at index 0` + `empty derivation path`；改为 `m/44'/195'/0'/0/0` 后签名成功，且结果与该 keystore 的单笔 `sign_tx` 一致、每笔 `fromAddress` 相同。
- [x] 4.5 在 imkey-core 添加无需设备的 preflight 测试，覆盖空批量（`sign_txs batch is empty`）、101 笔超限（`sign_txs batch exceeds max size of 100`）、缺失 tx、空 sender、非法 raw_data、空/非法 path，并断言这些分支不发送 APDU。
- [x] 4.6 添加经过 `ImkeyAction -> call_imkey_api -> sign_txs dispatcher -> TRON signer` 完整调用链、并由绑定测试设备守护的 imkey-core E2E 测试，覆盖 N=1/N>1、批量/单笔签名等价、不同 path、sender 不匹配、txID/from_address 和中间 item 拒绝时不返回部分结果；无设备环境执行静态错误 E2E，硬件成功/拒绝用例使用 `#[ignore]` 显式隔离。
- [x] 4.7 联合运行同批交付的 ETH/TRON `sign_txs` 测试以及既有 TRON `sign_tx` / `sign_message` 回归，确认两条批签路由互不干扰且单笔行为不变。

## 5. 文档与集成说明

- [x] 5.1 更新 token-core TRON 集成文档，说明 `SignTxsParam` 构造、`TronTxInput` 编码、共享/逐 item path、2048 上限、txID/fromAddress 和错误格式。
- [x] 5.2 在同一份文档中写明空 path 的迁移要求：批签不接受空 effective path，历史上传 `path: ""` 的调用方（含私钥 keystore）必须改为显式传入满足 TRON 约束的 path，例如 `m/44'/195'/0'/0/0`。
- [x] 5.3 更新 imkey-core 集成文档，说明 `tronapi.SignTxsInput`、每笔 payment/receiver/sender、100 硬上限、N 次设备确认和 all-or-nothing 返回。
- [x] 5.4 增加 host 示例，展示如何按输出下标合并 signature、如何核对 txID/fromAddress，以及不得在批量成功前广播前缀交易。

## 6. 校验与签收

- [x] 6.1 运行 `cargo fmt --all -- --check` 和受影响 crate 的 clippy 检查，记录与本变更无关的既有告警。
- [x] 6.2 运行 `cargo test -p tcx-tron`、tcx 的 TRON/ETH `sign_txs` 定向测试、imkey-core 无设备 preflight 测试，以及 `cargo test -p ikc --test tron_sign_txs_test` 中无需设备的 `call_imkey_api` E2E 用例。
- [x] 6.3 使用绑定 imKey 设备运行硬件批签成功/拒绝/断连用例，并在发布说明中明确设备确认次数与已验证固件版本。
- [ ] 6.4 评审和实现全部完成后再归档 `add-tron-batch-tx-signing`；本提案创建阶段不得修改 `add-eth-batch-tx-signing` 的实现结论。
