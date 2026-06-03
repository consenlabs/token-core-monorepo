# API
Token Core X （下称TCX) 提供了类似RPC的机制方便与 Java/Swift 等语言通讯。

## API 接口说明
TCX 提供了统一的 `Buffer call_tcx_api(Buffer buf);` C接口。参数和返回值为按照 Protobuf 序列化后的字节数组。 Buffer 为内部定义结构体，主要用来方便对字节数组的包装。
在实际使用中所有的方法都会被封装入统一的`Action API`:

```protobuf
message TcxAction {
    string method = 1;
    google.protobuf.Any param = 2;
}
```
`method`字段标明需要调用的方法。 param 为实际目标方法的请求参数，如导入助记词`method`为:`hd_store_import`，实际参数类型为`HdStoreImportParam`。`HdStoreImportParam`参数声明如下：

```protobuf
message HdStoreImportParam {
    string chainType = 1;
    string mnemonic = 2;
    string password = 3;
    string path = 4;
    string source = 5;
    string name = 6;
    string network = 7;
    string segWit = 8;
    string passwordHint = 9;
    bool overwrite = 10;
}
```
实际调用成功之后会返回 WalletResult 类型。完整的示例参见[handler.rs](../tcx/src/handler.rs)

## 开发说明
目前为了方便统一管理，所有proto文件全部放入`tcx-proto`项目内管理。目前常用的通讯参数如 api.proto, api_param.proto 已内置。    
对于链的开发者，因为每个链需要签名结构不同，需要自行编写 _chain_.proto 并且定义链相关的TransactionInput 和 TransactionOutput。    
TransactionInput 将作为SignTxParam中的input字段传入。如需要其他字段也可以放入其中。示例参见[btc-fork.proto](../tcx-proto/src/btc-fork.proto), [handler.rs#sign_tx](../tcx/src/handler.rs)。    
编写完成之后配置`tcx-proto`中`build.rs`文件，将新定义的结构编译到链所在的package中即可使用。    

## 安全敏感接口边界

以下接口不属于默认生产构建的公共 API：

- `get_derived_key`：用于 `cache_dk` 场景，返回可直接解锁 keystore 的派生密钥。默认不编译进 `tcx` 的 `call_tcx_api` method table；只有显式启用 `tcx` crate 的 `cache_dk` feature 时可用。
- `unlock_then_crash`：仅用于验证 panic 后 keystore 会重新锁定的测试入口。默认不编译进 `call_tcx_api` method table；只有显式启用 `test_api` feature 时可用。

默认构建中调用这些 method 会返回 `unsupported_method`。如确需验证这些入口，应使用显式 feature：

```bash
cargo test -p tcx --features cache_dk
cargo test -p tcx --features test_api -- --ignored
```

对外发布或普通集成构建不应启用 `test_api`。`cache_dk` 只应在移动端派生密钥缓存等明确场景中启用，并且需要由上层安全设计保证 derived key 的生命周期、存储介质和访问控制。

## 签名 API 命名约定

推荐新调用方使用语义更清晰的 method 名：

- `sign_transaction`：交易签名。兼容旧 method `sign_tx`。
- `sign_message`：消息签名。兼容旧 method `sign_msg`。
- `sign_raw_hashes`：对调用方已经确认语义的 digest/hash 做签名。兼容旧 method `sign_hashes`。
- `eth_batch_personal_sign`：ETH `personal_sign` 批量签名，语义已经明确，继续作为推荐 method。

旧 method 会继续保留以兼容已有 Java/Swift 调用方。新增代码应优先使用推荐 method，避免只看到 `sign_msg` 或 `ecSign` 时误判签名 payload 的安全语义。

ETH 消息签名里的 `SignatureType` 语义如下：

- `PersonalSign`：按 Ethereum `personal_sign` 规则加入前缀后签名，适用于普通用户可读消息。
- `EcSign`：对 `keccak256(message)` 做裸 secp256k1 签名，保留给历史调用方。除非上层协议已经明确 payload 域、编码和重放保护，否则不建议新场景直接使用。
