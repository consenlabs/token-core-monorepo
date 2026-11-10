# Keystore KDF 策略

TokenCoreX keystore 使用密码派生函数（KDF）从用户密码派生加密密钥，再用该密钥保护助记词、私钥和 identity 相关加密字段。

## 默认策略

新创建的 TokenCoreX keystore 默认使用 `argon2id`：

```json
{
  "kdf": "argon2id",
  "kdfparams": {
    "memoryCost": 19456,
    "timeCost": 2,
    "parallelism": 1,
    "dklen": 64,
    "salt": "<32-byte hex salt>"
  }
}
```

参数含义：

- `memoryCost`：Argon2id 内存成本，单位是 KiB。默认 `19456`，即 19 MiB。
- `timeCost`：迭代次数。默认 `2`。
- `parallelism`：并行度。默认 `1`，便于移动端和 wasm 场景保持稳定。
- `dklen`：实际派生密钥长度，接受 32 或 64 字节，新建 TokenCoreX 默认 64 字节。Argon2 将长度纳入计算，32 字节结果不是 64 字节结果的截断；读取时必须使用文件记录的长度。
- `salt`：随机盐，hex 编码。新建 keystore 使用 32 字节随机盐。

该参数组合参考 OWASP Password Storage Cheat Sheet 对 Argon2id 的最低建议，用于替代 PBKDF2 作为新建 keystore 的默认 KDF。

## KDF matrix

| 场景 | Legacy / current | Target | 处理结论 |
| --- | --- | --- | --- |
| 新建 `HdKeystore` / mnemonic keystore | 历史版本默认 `pbkdf2`，默认 rounds 曾为 `262144` | `argon2id`，`m=19456 KiB, t=2, p=1, dklen=64` | 已切换为新默认。 |
| 新建 private-key keystore | 历史版本默认 `pbkdf2`，默认 rounds 曾为 `262144` | `argon2id`，`m=19456 KiB, t=2, p=1, dklen=64` | 已切换为新默认。 |
| 显式 PBKDF2 fallback | `pbkdf2-hmac-sha256` | work factor `600000+` | `Pbkdf2Params::default()` 已提升到 `600000`；已有 JSON 仍按文件内 `c` 解锁。 |
| 显式 scrypt fallback | `SCryptParams::default()` 为 `N=2^18, r=8, p=1` | 至少 `N=2^17, r=8, p=1` | 已高于 OWASP fallback 建议。 |
| Ethereum V3 导出 | `version=3` 仅使用标准 V3 KDF | PBKDF2-HMAC-SHA256，`c=600000, dklen=32` | `LegacyKeystore::new_v3` 调用独立的 `Crypto::new_v3`，不继承 TokenCoreX 的 Argon2id 默认值。V3 导入继续支持 PBKDF2/scrypt。 |
| 导入 / 解锁旧 TokenCoreX keystore | JSON 中可能是 `pbkdf2` 或 `scrypt` | 继续可读 | 不自动改写；按原 `kdfparams` 解锁。 |
| migration / upgrade 生成的新 TokenCoreX keystore | 旧代码路径调用 `Crypto::new` 生成 PBKDF2 | 新生成结果使用 `argon2id` | 随 `Crypto::new` 切换；历史 fixture 不重写。 |
| Substrate / Polkadot.js keystore | `scrypt N=2^15, r=8, p=1`，编码在 PJS keystore 格式内 | 保持 PJS 兼容 | 不升级到 `2^17`，否则会破坏 Polkadot.js keystore 互通。 |

## 兼容策略

旧 keystore 不做破坏性迁移，仍按其 JSON 中的 `kdf` 字段解锁：

- `argon2id`：TokenCoreX 新默认格式，不作为 Ethereum V3 导出格式。
- `pbkdf2`：历史 TokenCoreX keystore 继续支持。
- `scrypt`：历史 V3 / 迁移来源 keystore 继续支持。

读取旧 keystore 时不会自动把 PBKDF2 或 scrypt 改写为 Argon2id。原因是 keystore 文件属于用户资产保护边界，自动重加密会改变持久化格式，并可能影响老客户端、备份恢复和跨版本回滚。

如后续需要迁移旧 keystore，应通过显式的“重加密/升级 keystore”流程完成，并满足：

- 用户已经完成密码校验或已持有合法 derived key。
- 新旧格式都能被测试覆盖。
- 迁移失败时旧文件可恢复。
- 移动端、wasm 和历史备份恢复路径均确认兼容。

当前结论是不增加 lazy upgrade：解锁旧 keystore 后只返回内存态明文或派生密钥，不隐式写回文件。后续如要支持升级，应新增显式 API 或迁移流程，并在持久化格式中记录可审计的升级结果。

### Argon2id 输入边界

处理不可信文件时，在分配 Argon2 工作内存之前校验：

- `dklen` 只能为 32 或 64；底层派生接口的输出缓冲区也必须匹配。
- `parallelism` 为 1–16，`timeCost` 为 1–10。
- `memoryCost` 至少为 `8 * parallelism`，最多为 262144 KiB（256 MiB）。这些是读取上限，不是新建默认值。
- `salt` 必须为有效 hex（允许 `0x` 前缀），解码后为 16–64 字节；解码前也限制字符串长度。

无效参数在读取、派生和显式可失败构造路径统一返回 `kdf_params_invalid`。`KdfParams::derive_key` 和新增的 `Crypto::try_new_with_kdf` 返回 `Result`，调用方必须处理错误。默认 `Crypto::new` 仅使用内部固定的有效 Argon2id 参数。公开 Rust 函数 `Crypto::new_with_kdf(...) -> Crypto` 保持旧签名，仅作为受信有效参数的兼容 wrapper，参数无效时仍会 panic；不可信参数必须使用 `try_new_with_kdf`，仓库中的默认构造、V3 导出和拒绝参数测试均不经过该 wrapper。

旧 PBKDF2/scrypt 的参数接受范围和派生行为不在本阶段收紧：仍派生并向缓存接口提供历史的 64 字节 credential，AES 和 MAC 使用前 32 字节。它们的前缀与派生长度无关，因此 `dklen=32` 的标准 V3 读取器也能解密导出文件。Argon2id 则严格按文件中的 `dklen` 派生并提供对应长度的 credential：`get_derived_key` 对 `dklen=32` 返回 64 个 hex 字符，对默认 `dklen=64` 返回 128 个 hex 字符，不补零、不扩展，也不截断其他长度的派生结果。API 的 `DerivedKey` 入参继续接受该真实长度，密码与派生密钥解锁使用相同 AES/MAC 语义。依赖固定 128 字符缓存长度的调用方应改为接受这两种长度。已有 64 字节 Argon2id 文件不变；不会尝试用 64 字节派生结果猜测性解锁标记为 32 字节的文件。

## PBKDF2 说明

PBKDF2 继续作为历史格式兼容能力和 Ethereum V3 导出默认保留，不再作为新创建 TokenCoreX keystore 的默认 KDF。已有 PBKDF2 keystore 的 `kdfparams` 不统一修改，保留历史派生行为。若调用方显式使用 PBKDF2 创建新加密体，默认 work factor 为 `600000`。

测试环境可通过 `KDF_ROUNDS=1` 降低 PBKDF2 测试耗时。该环境变量只影响 PBKDF2 默认参数和测试速度，不代表生产默认配置，也不影响 Argon2id 默认参数。

## 聚焦验证

```bash
CARGO_TARGET_DIR=/private/tmp/token-quality-target KDF_ROUNDS=1 make test-kdf
```

`test-kdf-core` 覆盖 crypto/keystore 的 default、`cache_dk` 和 V3 导出；`test-kdf-api` 对 API 的 default、`cache_dk`、`test_api`、`cache_dk,test_api` 四种组合先 `--no-run` 编译所有 API 测试目标，再运行契约测试，检查 TokenCoreX 默认 KDF、V3 导出 KDF、密码解锁、32/64 字节缓存密钥长度及 feature 路由边界，不执行故意 panic 的测试。CI 的 `kdf-features` matrix 同步执行四种组合的编译和契约检查；跨 crate 测试同时锁定 `new_with_kdf` 的公开 Rust 签名。

固定向量覆盖 Argon2id 的 32/64 字节派生值、密文、MAC、正确/错误密码、派生密钥解锁和 JSON 往返，以及旧 PBKDF2/scrypt 在 `dklen=32/64` 下的兼容行为。KDF/AES 向量由独立的 Python `cryptography`（OpenSSL）/`hashlib` 实现生成，不以 `Crypto::new` 的输出作为预期值。恶意参数测试覆盖资源上限、`memoryCost < 8p`、salt 编码/长度和输出长度不匹配，必须返回业务错误。

## profiling 数据

仓库提供 ignored 测试用于记录本机 KDF 耗时：

```bash
cargo test -p tcx-crypto test_kdf_profile -- --ignored --nocapture
```

在当前 macOS 开发机、debug test profile 下的一次结果：

| KDF | 参数 | 耗时 |
| --- | --- | --- |
| Argon2id | `m=19456 KiB, t=2, p=1` | 302 ms |
| scrypt | `N=2^17, r=8, p=1` | 12942 ms |
| PBKDF2-HMAC-SHA256 | `c=600000` | 8185 ms |

该数据只作为本地 profiling 基线，不代表所有移动端设备的 SLA。参数选择的实际结论是：Argon2id 满足 OWASP 最低建议，并且在当前测试环境中明显低于 scrypt / PBKDF2 fallback 的耗时；如未来提高 Argon2id 参数，应先补移动端 release 构建 profiling。
