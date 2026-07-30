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

## ETH 批量交易签名

ETH 批量交易使用链无关动作 `sign_txs`。请求类型为
`SignTxsParam`，其中 `chainType` 必须设置为 `ETHEREUM`；每个
`SignTxsItem.input` 放置 protobuf 编码后的 `transaction.EthTxInput`。
调用方可以通过 `password` 或 `derivedKey` 解锁 keystore，整批最多
2048 笔，并且只解锁一次。

外层 `path` 是整批默认派生路径。item 的 `path` 非空时覆盖默认值，为空
时继承外层值；每一笔最终得到的 effective path 都必须非空。批量结果严格
保持输入顺序，任一笔失败都会终止整批且不返回部分结果，逐笔错误格式为
`sign_txs failed at index {i}: {source}`。

请求结构示例：

```text
method: "sign_txs"
param: SignTxsParam {
  id: "<keystore-id>"
  password: "<password>"              // 或 derivedKey
  chainType: "ETHEREUM"
  path: "m/44'/60'/0'/0/0"
  items: [
    {
      input: encode(EthTxInput { nonce: "7", ... })
      path: ""                         // 继承外层 path
    },
    {
      input: encode(EthTxInput { nonce: "8", ... })
      path: "m/44'/60'/0'/0/1"         // 覆盖外层 path
    }
  ]
}
```

响应为 `SignTxsResult`，每个 `Output` 包含：

- `signature`：与使用相同交易及 effective path 调用单笔 `sign_tx`
  得到的签名交易完全一致；
- `txHash`：签名交易的 `0x` 前缀 Keccak-256 哈希；
- `fromAddress`：effective path 对应的 EIP-55 地址。私钥 keystore
  场景下由私钥决定，与 path 无关。

Host 应在弹出密码输入框前，根据账户元数据预先展示本次涉及的
`{effective path → 预期 from address}` 去重集合，让用户确认签名账户；
整批成功后再使用 SDK 返回的 `fromAddress` 逐笔复核，不匹配时不得广播。

### Stake 调用流程

以需要先授权再 stake 的流程为例：

1. 使用同一账户构造 `approve` 和 `stake` 两笔 `EthTxInput`，nonce
   分别为当前 nonce 和当前 nonce + 1。
2. 将两笔输入分别编码到 `SignTxsItem.input`，两个 item 都继承同一个
   外层 path；如果业务确实使用不同账户，则为对应 item 指定覆盖 path。
3. 调用一次 `sign_txs`，等待整个批次成功。
4. 校验输出数量、顺序和每笔 `fromAddress`，再按 nonce 顺序广播
   `approve` 与 `stake`。不得在整个批次完成前广播前缀结果。

`sign_txs` 用于交易批签；消息批签请使用
[`eth_batch_personal_sign`](#eth-批量消息签名eth_batch_personal_sign)。

## ETH 批量消息签名（eth_batch_personal_sign）

`eth_batch_personal_sign` 接收 `EthBatchPersonalSignParam`：指定
keystore `id`、`password` 或 `derivedKey`、共享 `path`，并通过
`data` 按顺序传入待签消息；返回
`EthBatchPersonalSignResult.signatures`。它只签消息，不构造或签署交易。

需要批量签署 ETH 交易时，应改用
[`sign_txs`](#eth-批量交易签名)，以获得逐笔 path、`txHash`、
`fromAddress`、错误下标和 all-or-nothing 语义。
