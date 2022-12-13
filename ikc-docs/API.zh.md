# API
ImKey Core 提供了类似RPC的机制方便与 Java/Swift 等语言通讯。

## API 接口说明
ImKey Core 提供了统一的 `Buffer call_imkey_api(Buffer buf);` C接口。参数和返回值为按照 Protobuf 序列化后的字节数组。 Buffer 为内部定义结构体，主要用来方便对字节数组的包装。
在实际使用中所有的方法都会被封装入统一的`Action API`:

```protobuf
message ImkeyAction {
    string method = 1;
    google.protobuf.Any param = 2;
}
```
`method`字段标明需要调用的方法。 param 为实际目标方法的请求参数，如btc地址获取`method`为:`btc_get_address`，实际参数类型为`BtcAddressReq`。`BtcAddressReq`参数声明如下：

```protobuf
message BtcAddressReq {
    string network = 1;
    string path = 2;
}
```
实际调用成功之后会返回 BtcAddressRes 类型。

## 开发说明
目前为了方便统一管理，所有proto文件全部放入`proto`项目内管理。目前常用的通讯参数如 api.proto。
对于链的开发者，因为每个链需要签名结构不同，需要自行编写 _chain_.proto 并且定义链相关的TransactionInput 和 TransactionOutput。
示例参见[btc.proto](../proto/src/btc.proto), [btc_signer.rs#sign_btc_transaction](../api/src/btc_signer.rs)。
编写完成之后配置`proto`中`build.rs`文件，将新定义的结构编译到链所在的package中即可使用。
