# infrastructure#699：旧 keystore 迁移与解析边界

复核基线为 `main@eeda742`。issue 评论中列出的 timestamp、缺失 address/meta、空 EOS key list、升级账户 curve 等输入仍可触发 `expect`、索引越界或显式 panic；本次将这些路径改为可传播的错误。

## 修复范围

- legacy metadata 的字符串时间戳检查解析、有限值和 i64 范围，保留历史小数时间戳截断规则；缺失 metadata、address、EOS 私钥对象或空列表返回错误。
- 11000/11001 升级先检查版本与对象结构；私钥钱包必须包含完整账户信息，未知 curve 返回 `unsupported_curve_name`。历史未知版本继续返回 `unknown_version_when_upgrade_keystore`。
- 迁移 API 的 Protobuf、缺失凭证、文件读写、账户查找均传播错误；扫描不再把目录作为 keystore 文件打开。
- 旧 Ethereum 地址在构造 H160 前检查恰好 20 bytes；扫描、密码重置与旧账户映射不再对来自 JSON 的必需字段调用 `expect`/`unwrap`。
- 不改变 fixture、链上签名规则或正常钱包的身份与导出内容。

## 验证

`tcx-migration` 的完整迁移/升级兼容性测试，以及 `tcx` 中的迁移扫描和畸形输入测试覆盖缺失字段、空列表、未知 curve、非数值/无穷时间戳、错误长度 Ethereum 地址、截断 Protobuf。负例使用 `catch_unwind` 断言解析过程返回错误且没有 panic；正常密码、derived key、各链原文恢复和地址断言继续保留。

此验证不意味着所有任意指针都能安全传入 FFI。C 调用方仍必须遵守有效 NUL 结尾字符串、有效生命周期和返回值恰好释放一次的 ABI 约定；本次将请求解析一并放入 `landingpad`，负责捕获 Rust unwind，不能捕获任意内存访问错误。

传输层 HID/APDU 长度与报文语法的加固单独由 infrastructure#690 的配套 PR 交付。真实 imKey 展示、签名及设备固件验收见 [imKey 边界记录](security-699-imkey.md)。


## C 字符串与移动桥接

`call_tcx_api` / `call_imkey_api` 的 null、UTF-8、hex 和 Protobuf 解析均在 unwind 边界内进行，错误消息与返回值使用原有 API 编码。内部 panic 返回 `internal_error`，不泄露 panic 内容。返回的 Rust CString 由对应的 free 函数恰好释放一次；调用方传入的字符串和 APDU callback 请求均为借用，不得交给 Rust 释放。

APDU callback 调用及响应复制持有同一串行锁；响应由宿主管理并至少存活到复制完成。Android JNA 以 Pointer 接收 Rust owned 结果，复制成 String 后在 finally 释放；上层 String 接口保留。Swift/Java callback 复用有边界的宿主响应 buffer，Java 保留 callback 强引用以防 GC 回收 trampoline。C header 明确所有权。直接以 String marshal 到 free 函数会跨分配器释放，因此旧桥接必须与本次 core 同步升级。

`imkey-core/mobile-sdk/tests/ffi-ownership.sh` 使用主机 C mock 验证 owned 返回值恰好释放一次、重复 callback/buffer/GC 和 Swift 生命周期；它不代表真实 Android/iOS 完整构建或设备集成已通过。历史示例中独立的业务 API 漂移不在本次重写范围。
