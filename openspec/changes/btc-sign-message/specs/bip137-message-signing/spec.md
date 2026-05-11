## 新增需求

### 需求：Legacy（P2PKH）地址的 BIP-137 消息签名
系统必须支持使用 BIP-137 标准为 Legacy（P2PKH，`1...`）地址签署任意 UTF-8 文本消息。签名流程必须：
1. 构造消息摘要：`SHA256(SHA256("\x18Bitcoin Signed Message:\n" + varint(消息长度) + 消息内容))`
2. 生成 secp256k1 ECDSA 可恢复签名
3. 输出 65 字节紧凑签名：`[标志字节, r(32字节), s(32字节)]`，其中 `标志字节 = 31 + recovery_id`（压缩公钥 P2PKH 范围）
4. 返回 Base64 编码的签名字符串

#### 场景：使用 Legacy P2PKH 地址签名消息
- **当** 收到签名请求，`seg_wit = "NONE"` 且 `signatureType = BIP137`
- **则** 系统生成标志字节在 31-34 范围的 65 字节紧凑 ECDSA 签名，Base64 编码输出

#### 场景：签名可被标准 BIP-137 验证器验证
- **当** 生成的签名与原始消息和 P2PKH 地址一起提交给 BIP-137 合规验证器
- **则** 验证器确认签名有效

### 需求：Nested SegWit（P2SH-P2WPKH）地址的 BIP-137 消息签名
系统必须支持使用 BIP-137 标准为 Nested SegWit（P2SH-P2WPKH，`3...`）地址签署任意 UTF-8 文本消息。签名流程与 Legacy P2PKH 完全相同，唯一区别是标志字节必须使用 `35 + recovery_id`（P2SH-P2WPKH 范围）。

#### 场景：使用 Nested SegWit 地址签名消息
- **当** 收到签名请求，`seg_wit = "P2WPKH"` 且 `signatureType = BIP137`
- **则** 系统生成标志字节在 35-38 范围的 65 字节紧凑 ECDSA 签名，Base64 编码输出

#### 场景：签名标志位正确标识 P2SH-P2WPKH 地址类型
- **当** 对生成的签名进行 Base64 解码
- **则** 第一个字节在 35-38 范围内，使验证器能从恢复的公钥重建 P2SH-P2WPKH 地址

### 需求：Standard（标准）格式消息签名
系统必须支持"标准"签名格式，该格式使用与 BIP-137 相同的消息摘要和 ECDSA 签名流程，但标志字节始终使用 P2PKH 压缩公钥范围（`31 + recovery_id`），无论实际地址类型如何。此格式提供与传统验证器的最大向后兼容性。

#### 场景：Nested SegWit 地址使用 Standard 格式
- **当** 收到签名请求，`seg_wit = "P2WPKH"` 且 `signatureType = STANDARD`
- **则** 系统生成标志字节在 31-34 范围的 65 字节紧凑签名（与 P2PKH 相同），Base64 编码输出

#### 场景：Legacy 地址使用 Standard 格式
- **当** 收到签名请求，`seg_wit = "NONE"` 且 `signatureType = STANDARD`
- **则** 行为与 Legacy 地址的 BIP-137 签名完全一致（标志字节 31-34）

### 需求：imKey 硬件钱包 BIP-137 和 Standard 签名
系统必须通过 imKey 硬件钱包路径支持 BIP-137 和 Standard 格式消息签名。签名过程必须在硬件设备上完成，遵循相同的标志字节约定，并通过 BTC applet 的消息签名指令完成 host 端 ECDSA 鉴权 + 设备端用户确认 + RFC-6979 ECDSA 签名 + BIP-62 low-S 归一化。

#### 场景：硬件钱包 Legacy BIP-137 签名
- **当** Legacy 地址的 `signatureType = BIP137` 签名请求通过 imKey 硬件钱包路由
- **则** 系统通过 APDU 与 imKey 设备通信，生成标志字节在 31-34 范围的有效 BIP-137 签名

#### 场景：硬件钱包 Nested SegWit BIP-137 签名
- **当** Nested SegWit 地址的 `signatureType = BIP137` 签名请求通过 imKey 硬件钱包路由
- **则** 系统生成标志字节在 35-38 范围的有效 BIP-137 签名

#### 场景：硬件钱包 Legacy Standard 签名
- **当** Legacy 地址的 `signatureType = STANDARD` 签名请求通过 imKey 硬件钱包路由
- **则** 系统生成标志字节在 31-34 范围的签名（与 BIP-137 Legacy 行为一致）

#### 场景：硬件钱包 Nested SegWit Standard 签名
- **当** Nested SegWit 地址的 `signatureType = STANDARD` 签名请求通过 imKey 硬件钱包路由
- **则** 系统生成标志字节在 31-34 范围的签名（使用 P2PKH 压缩公钥标志，而非 P2SH-P2WPKH 标志）

### 需求：imKey BTC applet 版本门控
当 imKey 路径上发起 `signatureType ∈ {STANDARD, BIP137}` 的签名请求时，系统必须先通过 `get_btc_apple_version()` 读取 BTC applet 版本，并在版本低于 `1.6.11` 时立即返回标准 `UpgradeApplet` 错误，不下发任何消息签名 APDU。

#### 场景：BTC applet 版本满足要求
- **当** BTC applet 版本 `>= 1.6.11`
- **则** 系统继续按 single-INS 消息签名协议组装 prepare TLV 并发送 APDU

#### 场景：BTC applet 版本不满足要求
- **当** BTC applet 版本 `< 1.6.11`
- **则** 系统返回 `UpgradeApplet` 错误并提示用户升级 applet；**不**发送任何 BTC 消息签名 APDU

### 需求：imKey BIP-137 / Standard host APDU 协议组装
系统对 imKey 发起 BIP-137 或 Standard 消息签名时，必须按 BTC applet `>=1.6.11` 的"单 INS（`BTC_MSG_SIGN = 0x51`）+ P2 分阶段"协议打包 prepare 数据并发送 APDU。host 端必须：

1. 在 Raw Data TLV 的 value 内顺序嵌套两段子 TLV：
   - `[PRE_TAG_TXHASH = 0xA6 | 0x20 | 32-byte BIP-137 digest]`
   - `[PRE_TAG_PATH   = 0xA7 | path_len | BIP32 path 字节串]`
   - 其中 BIP-137 digest = `SHA256(SHA256("\x18Bitcoin Signed Message:\n" + varint(len) + message))`
   - BIP32 path 来源为请求中的 account-level path 拼接 `/0/0`
2. 把上述 value 包成外层 Raw Data TLV `[tag=0x01 | len | value]`
3. 使用 app 私钥对完整 Raw Data TLV（含 tag 与 len 字节）做 secp256k1 ECDSA 签名，得到 DER 编码的 host 签名
4. 把 host 签名包成 Signature TLV `[tag=0x00 | len | DER_sig]`
5. 拼装最终 prepare 数据 = `Signature TLV || Raw Data TLV`，调用既有 `BtcApdu::btc_prepare(0x51, 0x00, prep_data)` 切分为一条或多条 APDU：所有中间块 `P1=0x00 / P2=0x00`，最后一块 `P1=0x00 / P2=0x80`
6. 最后一块 APDU 必须使用长超时（`TIMEOUT_LONG`，120s）发送，因为它在 applet 内部触发用户确认
7. host 必须从最后一块 APDU 的响应中直接解析 66 字节签名结果 `len | R(32) | S(32) | V(1) | SW(2)`；**不**发送任何独立的 sign APDU
8. host 必须对 `R || S` 执行 BIP-62 low-S 归一化（用 `secp256k1::ecdsa::Signature::normalize_s()`），若 S 被翻转则相应翻转 V（`final_v = 1 - v`）
9. host 根据 `signatureType` + `seg_wit` 计算 flag base：`STANDARD` 始终 31；`BIP137` 时 Legacy=31、Nested SegWit=35、Native SegWit=39；对 Taproot 直接返回 `Bip137NotSupportedForTaproot` 错误
10. 最终输出 `Base64([flag_base + final_v, R, S])`

#### 场景：单 APDU 完成 BIP-137 prepare
- **当** prepare 数据长度 `<=` `LC_MAX`（典型路径下约 127 字节，远低于 245）
- **则** 仅发送一条 `INS=0x51, P1=0x00, P2=0x80` APDU；applet 在该条 APDU 内完成 host 签名验证 → 内层 TLV 解析 → 用户确认 → RFC-6979 ECDSA 签名 → 返回 66 字节签名结果

#### 场景：多 APDU 完成 BIP-137 prepare
- **当** prepare 数据长度超过 `LC_MAX`
- **则** 按 `LC_MAX` 切分，前序块使用 `P2=0x00`（仅缓冲），最后一块使用 `P2=0x80`（触发完整流程）；签名结果仅在最后一块的响应中返回

#### 场景：BIP32 path 篡改被 host 签名验证阻断
- **当** 任何中间环节修改了内层 `PRE_TAG_PATH` 子 TLV 的 path 字节，但未重新计算 host 签名
- **则** applet 在 `msgDataSignVerify()` 阶段返回 `SW_SIGNATURE_VERIFY_FAILED`，host 端 `ApduCheck::check_response` 抛出错误，签名流程中止；不会触发用户确认 UI，也不会产生任何签名输出
