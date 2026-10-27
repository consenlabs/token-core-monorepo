# infrastructure#699：imKey 签名展示、路径与设备信任边界

本修复直接基于 `main@eeda742a035ca0d74664956bf715b8c4c6574ffb`，沿用主分支的 Rust toolchain、依赖和同步 API，不依赖尚未合并的开源质量改造。

## 从签名 payload 生成展示

ETH 的 `Transaction::signing_pack` 从交易生成规范展示：`payment` 为真实 value 的十进制整数加 `wei`；receiver 为真实目标地址；fee 为 `gas_limit * gas_price`，EIP-1559 使用 `gas_limit * max_fee_per_gas` 表示最高费用。乘法溢出、priority fee 超过 max fee、缺少 EIP-1559 字段均拒绝。

调用方展示字段为空时由核心生成；非空时只作为一致性断言，不一致返回 `imkey_transaction_display_mismatch`。当前 applet 的三个字段不能完整说明任意合约调用，也没有可信 token decimals/symbol 注册表，因此含 calldata 的交易和合约创建返回 `imkey_unsupported_transaction_display`，不会把调用方字符串当作交易解释。仅接受 Legacy / EIP-1559；未知 type 返回 `unsupported_transaction_type`，不再降级为 Legacy。

Cosmos 支持 Amino JSON SignDoc 和 ADR-020 Protobuf SignDoc 中的单一 `MsgSend` / `MsgDelegate`。核心提取实际 coin amount、base denomination、接收地址/validator 与 fee；委托目的字段加 `delegate:`。例如显示 `10000 uatom`，不接受 payload 没有提供的 `ATOM` ticker/精度。未知消息、多消息、扩展选项、fee payer/granter、未知 protobuf 字段和不支持的签名布局拒绝。JSON 严格校验字段，重复字段和未知消息外层字段拒绝；地址只接受 Bech32，不接受 Bech32m。

Cosmos Direct SignDoc 只接受单一 `SIGN_MODE_DIRECT=1` 的 secp256k1 SignerInfo；声明的压缩公钥必须与 SE 认证的派生公钥及 payload sender 一致。最终签名按真实 SignDoc hash 验证。ETH/Cosmos 的签名、公钥响应均先检查长度，再解析 hex、公钥和签名。

这些安全行为会拒绝历史上可接受的任意展示字符串。接入方应留空展示断言，或传入规范字段。历史测试中展示与 payload 不一致、sender 不属于设备派生公钥的请求应作为拒绝用例，不能继续作为成功签名验收。

## 严格派生路径和 TLV 长度

ETH、Cosmos、TRON 分别限制为五层 BIP44 叶路径，对应 coin type `60'`、`118'`、`195'`。空路径、根路径、相对路径、跨币种路径、错误 hardened 结构均在第一条 APDU 前拒绝。

Substrate 硬件入口使用全 hardened 的五层 BIP44；Polkadot coin type 为 `354'`，Kusama 为 `434'`。它与软件 Substrate 的 junction 派生规则分开。TLV 长度检查先于设备访问；现有单字节 TLV 无法表示恰好 256-byte 的原始 signing payload，明确拒绝；大于 256 bytes 仍按 Substrate 规则 hash 后签名。

TRON/Substrate 当前原始 payload 接口缺少完整可信 TRON 合约 schema / Substrate runtime metadata，不能证明任意“金额、收款人、手续费”描述。交易展示由核心生成 `Opaque signing` 和真实 payload hash；Substrate fee 显示 `Unverified`。非空字段只能断言规范值，不能伪造转账描述。TRON 当前协议不展示可信 fee，因此拒绝非空 fee 断言。

这保留明确标记的不透明签名能力，不等于完成这些链的完整交易语义解析。真实设备必须进一步确认标记和完整 hash 可见；后续需依据链 schema/runtime metadata 完成语义解析，不能把本 PR 描述为所有链展示已经闭环。

## TSM / 固件认证边界

| 边界 | main 中的实现与保证 |
| --- | --- |
| TSM 传输 | 固定 `constants::URL`，使用 `HttpsConnector` 的系统 CA 和主机名检查。本次补充 HTTPS/路径、HTTP 成功状态和 UTF-8 检查；不引入动态 endpoint 配置 |
| 客户端认证 | JSON POST 包含设备证书、SEID、SN、step 结果；未发现 mTLS、逐请求签名或 anti-replay nonce 校验 |
| 返回认证 | 读取 `ServiceResponse` 状态和 APDU 列表；未发现独立于 TLS 的响应签名验证或证书/SPKI pin |
| 初次绑定 | 将设备证书发到 TSM，根据 `verifyResult` 判断有效性，再提取 SE 公钥建立绑定；客户端依赖 TSM 的证书判断 |
| app/COS 管理 | 将 TSM APDU 发送设备，状态返回 TSM；客户端源码本身无法证明 SE/bootloader 的固件签名、版本、防回滚及目标设备绑定策略 |

整批 APDU 在发送第一条前检查非空、hex、偶数长度与 ISO APDU 长度上限。返回状态长度/hex、缺失 nextStepKey / verifyResult 等畸形响应返回错误，避免 panic 或重复空步骤。批次格式检查不构成 APDU 来源认证。

本次不臆造生产 pin、公钥或固件签名格式，也不修改设备安全通道协议。下列验收仍需实际协议和硬件证据，不能据此关闭 infrastructure#699 全部事项：

1. TSM owner 提供证书/密钥轮换、请求认证、响应签名、防重放及 SEID/session 绑定协议和测试向量，再决定 pin、签名校验或协议升级。
2. firmware owner 提供固件/app 签名、版本/防回滚和设备绑定证据，执行替换 APDU、错误签名、替换固件与错误设备的拒绝回归。
3. 真实 imKey 验证规范展示、opaque 标记和 hash、取消/确认、派生地址与签名，以及错误路径、sender、声明公钥和展示拒绝。本地纯测试不能替代设备屏幕与固件验证。

## 本地验证范围

定向测试覆盖 ETH 规范展示/不透明调用拒绝/溢出/畸形响应；Cosmos Amino/Direct 真向量、严格模式/公钥绑定、未知字段/重复字段/Bech32m 拒绝；TRON/Substrate 路径、展示及 TLV 边界；通用 APDU 响应、TSM batch/status 与 HTTPS 路径负例。只运行 host-safe 测试，没有连接或操作真实设备。

## 移动端字符串所有权与验证

Android 的 SDK 与示例保留 `RustApi.INSTANCE.call_imkey_api(String) -> String` 等上层接口，实际 JNA `NativeBindings` 使用 `Pointer` 接收 Rust 分配的结果，并在复制 UTF-8 后的 `finally` 中调用 `imkey_free_const_string`；错误读取和 APDU getter 使用同样规则。旧 Java 方法名 `clear_err` / `get_last_err_message` 映射到真实的 `imkey_*` C 符号。TokenCore Android 示例的结果桥接也改为对应的 Pointer/复制/释放模式。

Callback 请求是借用值，Android 不再释放其 Java String。`Sender.sendApdu` 的 Java 返回类型改为 `Pointer`，SDK 与示例持有固定大小的 JNA Memory 响应缓冲区；Adapter 同时保留当前 Sender 的强引用直到下次注册完成，避免 GC 提前回收 callback trampoline。自定义 Sender 实现需要同步更新。Swift 使用保留的固定缓冲区返回 callback 响应；所有 Rust-owned 结果先复制再释放。Rust 必须将 callback 串行锁保持到响应复制结束。三个 imKey C header 明确这些所有权规则，不得混用 Swift/JNA 与 Rust 分配器。

可用本地 JNA jar 重跑宿主验证：

```bash
JNA_COMPILE_JAR=/path/to/jna-5.4.0.jar \
JNA_JAR=/path/to/host-compatible-jna.jar \
bash imkey-core/mobile-sdk/tests/ffi-ownership.sh
```

本次用 JNA 5.4.0 编译 Java 7 兼容接口，使用支持 Apple Silicon 的 JNA 5.13.0 执行宿主 C mock。验证 owned 结果的分配/释放计数、空结果、每个 Android callback 连续 1000 次缓冲区复用、UTF-8 和长度边界；另执行真实 Swift helper 的复制/释放与缓冲区回归并解析三个完整 Swift 源文件。测试不加载生产钱包核心、不连接设备，也不替代完整 Android/iOS 工程构建或旧示例业务 API 的兼容验收。生产依赖版本未因宿主测试而修改。
