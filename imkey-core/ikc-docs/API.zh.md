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

## ETH 批量交易签名

ETH 批量交易使用动作 `sign_txs`。外层仍使用 `common.SignParam`：
`chainType` 设置为 `ETHEREUM`，默认派生路径写入 `path`，`input`
放置 protobuf 编码后的 `ethapi.SignTxsInput`。

`SignTxsInput.items` 中每个 `SignTxsItem` 包含：

- `tx`：待签的 `EthTxInput`；
- `payment`、`receiver`、`fee`：由 host 根据交易内容提供，供设备展示；
- `sender`：由 host 提供的预期签名地址，不能为空；
- `path`：可选的逐笔派生路径，非空时覆盖外层默认 path，为空时继承
  外层 path。

所有 effective path 和必填展示字段都会在访问设备前校验。签名时设备按
effective path 派生地址并与 `sender` 比较，不一致则拒绝。因此成功响应中
`SignTxsItemOutput.from_address` 与经过设备核验的 `sender` 强等价；
`tx` 则是现有 `EthTxOutput`，包含签名交易和交易哈希。Host 仍应核对
输出数量、顺序及 `from_address` 后再广播。

硬件批量最多 100 笔。本次变更不修改固件或 APDU 批量协议，只是在一次
FFI 调用中按顺序复用现有单笔签名流程：每笔仍会执行 applet select、
xpub 获取、sender 校验、APDU 签名以及物理按键确认。N 笔交易需要用户
准备完成 N 次设备确认，host 应提前提示，并根据业务时长自行设置更小的
可接受笔数。

结果顺序与输入完全一致；任一 item 失败都会终止整批且不返回部分结果，
错误格式为 `sign_txs failed at index {i}: {source}`。Host 必须等待整个
批次成功后再广播，不能在后续 item 尚未确认时广播前缀交易。

token-core 的 ETH 消息批签动作 `eth_batch_personal_sign` 与这里的
交易批签用途不同；交易批签统一使用 `sign_txs`。

## TRON 批量交易签名

TRON 与 ETHEREUM 共用动作名 `sign_txs`。外层 `common.SignParam` 的
`chainType` 设置为 `TRON`，`input` 放置 protobuf 编码后的
`tronapi.SignTxsInput`。每个 item 包含 `TronTxInput tx`、设备展示用的
`payment` / `receiver`、用于设备地址核验的非空 `sender`，以及可选
`path`。item path 为空时继承外层 path，effective path 不允许为空。

```text
method: "sign_txs"
param: common.SignParam {
  chainType: "TRON"
  path: "m/44'/195'/0'/0/0"
  input: encode(tronapi.SignTxsInput {
    items: [
      {
        tx: TronTxInput { raw_data: "<hex>" }
        payment: "<device display amount>"
        receiver: "<device display receiver>"
        sender: "<expected Base58Check address>"
        path: ""                         // 继承外层 path
      },
      {
        tx: TronTxInput { raw_data: "<hex>" }
        payment: "<device display amount>"
        receiver: "<device display receiver>"
        sender: "<expected Base58Check address>"
        path: "m/44'/195'/0'/0/1"       // 覆盖外层 path
      }
    ]
  })
}
```

空批量、超过 100 笔、缺失 `tx` 或 `sender`、非法 `raw_data` hex、
空或非法 effective path 都会在选择 TRON applet、发送 APDU 或要求用户
确认之前完成整批预检。空批量和超限分别返回
`sign_txs batch is empty` 与
`sign_txs batch exceeds max size of 100`；item 错误使用下面的带下标
格式。

硬件批量最多 100 笔。该接口只是有序调用现有 TRON 单笔签名流程，不会
缓存 applet、xpub 或设备会话，因此 N 笔交易仍需要 N 次设备确认。任一
item 被设备拒绝、sender 与设备地址不匹配或签名失败时，整批立即失败并
且不返回前缀结果，错误格式为
`sign_txs failed at index {i}: {source}`。

成功结果为 `tronapi.SignTxsOutput`。调用方应按相同下标将
`outputs[i].tx.signature` 合并回原交易，并核对：

- `tx_hash` 等于原始 `raw_data` 的 SHA-256 txID（小写、不带 `0x`）；
- `from_address` 等于已由设备核验的 item sender；
- 输出数量及顺序与输入完全一致。

只有整个请求成功后才能开始广播，不能在后续 item 尚未确认前广播前缀
交易。
