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
- `dklen`：派生密钥长度。当前 TokenCoreX 使用 64 字节派生密钥。
- `salt`：随机盐，hex 编码。新建 keystore 使用 32 字节随机盐。

该参数组合参考 OWASP Password Storage Cheat Sheet 对 Argon2id 的最低建议，用于替代 PBKDF2 作为新建 keystore 的默认 KDF。

## KDF matrix

| 场景 | Legacy / current | Target | 处理结论 |
| --- | --- | --- | --- |
| 新建 `HdKeystore` / mnemonic keystore | 历史版本默认 `pbkdf2`，默认 rounds 曾为 `262144` | `argon2id`，`m=19456 KiB, t=2, p=1, dklen=64` | 已切换为新默认。 |
| 新建 private-key keystore | 历史版本默认 `pbkdf2`，默认 rounds 曾为 `262144` | `argon2id`，`m=19456 KiB, t=2, p=1, dklen=64` | 已切换为新默认。 |
| 显式 PBKDF2 fallback | `pbkdf2-hmac-sha256` | work factor `600000+` | `Pbkdf2Params::default()` 已提升到 `600000`；已有 JSON 仍按文件内 `c` 解锁。 |
| 显式 scrypt fallback | `SCryptParams::default()` 为 `N=2^18, r=8, p=1` | 至少 `N=2^17, r=8, p=1` | 已高于 OWASP fallback 建议。 |
| 导入 / 解锁旧 TokenCoreX keystore | JSON 中可能是 `pbkdf2` 或 `scrypt` | 继续可读 | 不自动改写；按原 `kdfparams` 解锁。 |
| migration / upgrade 生成的新 TokenCoreX keystore | 旧代码路径调用 `Crypto::new` 生成 PBKDF2 | 新生成结果使用 `argon2id` | 随 `Crypto::new` 切换；历史 fixture 不重写。 |
| Substrate / Polkadot.js keystore | `scrypt N=2^15, r=8, p=1`，编码在 PJS keystore 格式内 | 保持 PJS 兼容 | 不升级到 `2^17`，否则会破坏 Polkadot.js keystore 互通。 |

## 兼容策略

旧 keystore 不做破坏性迁移，仍按其 JSON 中的 `kdf` 字段解锁：

- `argon2id`：新默认格式。
- `pbkdf2`：历史 TokenCoreX keystore 继续支持。
- `scrypt`：历史 V3 / 迁移来源 keystore 继续支持。

读取旧 keystore 时不会自动把 PBKDF2 或 scrypt 改写为 Argon2id。原因是 keystore 文件属于用户资产保护边界，自动重加密会改变持久化格式，并可能影响老客户端、备份恢复和跨版本回滚。

如后续需要迁移旧 keystore，应通过显式的“重加密/升级 keystore”流程完成，并满足：

- 用户已经完成密码校验或已持有合法 derived key。
- 新旧格式都能被测试覆盖。
- 迁移失败时旧文件可恢复。
- 移动端、wasm 和历史备份恢复路径均确认兼容。

当前结论是不增加 lazy upgrade：解锁旧 keystore 后只返回内存态明文或派生密钥，不隐式写回文件。后续如要支持升级，应新增显式 API 或迁移流程，并在持久化格式中记录可审计的升级结果。

## PBKDF2 说明

PBKDF2 继续作为历史格式兼容能力保留，不再作为新创建 keystore 的默认 KDF。已有 PBKDF2 keystore 的 `kdfparams.c`、`prf`、`dklen`、`salt` 按文件内记录解释，不统一修改。若调用方显式使用 PBKDF2 创建新加密体，默认 work factor 为 `600000`。

测试环境可通过 `KDF_ROUNDS=1` 降低 PBKDF2 测试耗时。该环境变量只影响 PBKDF2 默认参数和测试速度，不代表生产默认配置，也不影响 Argon2id 默认参数。

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
