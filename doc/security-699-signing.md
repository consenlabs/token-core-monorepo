# infrastructure#699：签名、派生路径与 Bitcoin 输入绑定

本修复直接基于 `main@eeda742a035ca0d74664956bf715b8c4c6574ffb`，保留 `nightly-2023-06-15`、bitcoin 0.29.2 和主分支依赖，不引入阶段七共享 crate 或异步接口。关联 [infrastructure#699](https://github.com/consenlabs/infrastructure/issues/699)。

## 核查与改动

- 未知 ETH `tx_type` 原先静默使用 Legacy；现在明确拒绝，保留历史空字符串和已支持类型编码。
- BLS withdrawal change 原先未绑定声明公钥；现在签名前比较实际派生公钥，声明不符拒绝。
- TRON HD 空路径原先回落根密钥，消息签名未统一校验；现在交易、消息共同验证完整 `44'/195'` 路径。单私钥导入继续允许空路径。
- Substrate HD 空路径原先回落根密钥；现在拒绝，合法自定义 junction 路径继续支持。junction 和 Ed25519 SLIP10 不套用 secp256k1 BIP44 格式。
- 软件与 imKey BTC/fork 验证完整路径的 coin type、账户、hardened/normal 结构，并将实际派生公钥绑定到输入脚本。HD UTXO 空、根、跨链和跨账户路径拒绝。允许同 coin/account 混合 44/49/84/86 输入。
- 测试网保留标准 `1'` 和既有链 coin type，例如 Litecoin 的历史测试网 `2'` 路径；主网只接受本链 coin type。BTC wrapper 正规化账户相对路径，避免原先 `to_uppercase()` 破坏根前缀。fork wrapper 的链和网络来自请求。
- BTC/Omni/fork 的总额、amount+fee、找零、PSBT 预览费用使用 checked arithmetic；APDU 金额固定为 8-byte little-endian。
- imKey fork 的显式找零地址必须与指定账户的设备派生地址一致。

BTC 消息签名保留原有三层账户路径接口：追加 `/0/0` 后校验完整路径，HD 空路径、根路径及跨币种账户在签名前拒绝；导入单私钥仍支持空路径。API 集成中曾期待 TRON HD 空路径签名的用例已改为拒绝断言，合法路径的原签名向量继续验证。

## PSBT 签名前必须满足的条件

1. `non_witness_utxo` 的 txid、vout 匹配 unsigned input；vout 使用 checked lookup。双 UTXO 字段存在时内容必须相同。
2. Legacy P2PKH 必须有完整 previous transaction，不能只信任未认证的输入金额。
3. 输入/输出合计不溢出，输出不超过输入。未知 sighash、未知输入模板、不能可靠展示的非零输出拒绝。
4. key origin 的公钥与实际派生公钥一致，公钥确实属于 prevout 的脚本。未压缩 P2PKH finalize 保留正确的公钥序列化形式。
5. Taproot key-path 验证 internal key、merkle root 和 output key 的承诺；script-path 验证 control block、prevout 和签名公钥。tuple leaf version 必须与 control block 一致，且本实现只接受 TapScript (`0xc0`)，拒绝 future leaf。

软件 PSBT 选择实际匹配的 origin；imKey 单密钥接口拒绝多个 origin 的歧义。缺少 origin 时只允许明确账户的 `/0/0` 回退，不允许 HD 根密钥。脚本签名使用 BIP371 `tap_script_sigs`；只有单公钥 CHECKSIG leaf 自动 finalize，其他脚本保留 partial fields 交给标准 finalizer。

imKey 在设备访问前检查路径、prevout、金额、sighash 和展示能力。内部 BIP322 零值虚拟消息交易保留受约束的特例：version/locktime/sequence、单输入/单输出和零值 OP_RETURN 的形状都必须符合要求；公开交易接口不能开启该特例。

签名输入与找零公钥读取请求 SE 证据，验证 `uncompressed pubkey (65 bytes) || chain code (32 bytes)` 的 SHA256 / DER ECDSA 签名，信任公钥来自已有绑定的 `KEY_MANAGER.se_pub_key`。短响应、缺签和篡改数据拒绝。此校验继承现有设备绑定的信任根，不替代固件或证书验收。

## 验证入口与兼容变化

软件相关包运行完整测试及 doc-tests；imKey 先编译全部测试目标，再列出测试名并用 `--exact` 执行纯逻辑测试。最终交付使用独立的 `target-main-699` 构建目录，避免不同修复分支复用测试可执行文件。

最终 `make test-tcx` 为 497 passed、0 failed、2 个调试测试 ignored；workspace 全部测试目标编译通过。常规 host 组为 77 passed，另有 12 个 Bitcoin/fork/消息精确 host 测试通过。移动桥接的 Java/Swift 主机所有权验证通过，真实设备与完整移动集成不计入这些结果。

```sh
MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 cargo test --locked \
  -p tcx-primitive -p tcx-btc-kin -p tcx-eth -p tcx-eth2 -p tcx-tron -p tcx-substrate
MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 cargo test --locked \
  -p coin-bitcoin -p coin-btc-fork --no-run
```

新回归覆盖有效签名验真、未压缩 P2PKH、Taproot merkle-root key-path、control/tuple leaf-version 单字段篡改与 future leaf、根/跨链/跨账户路径、金额溢出、伪造 prevout/origin、SE 签名缺失/篡改和找零地址不符。

旧硬件 PSBT fixture 中不绑定公钥/脚本或缺少完整 Legacy previous transaction 的案例改为预期拒绝，仍保留硬件测试性质。有效 no-script fixture 使用与其 testnet 路径和地址一致的网络。

真实设备回归尚需连接 imKey 后进行。本次主机验证不替代设备上的交易展示、签名授权和固件回归，也不能据此声称 TSM/设备信任整改已经上线。
