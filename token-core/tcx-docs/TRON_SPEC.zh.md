# TRON Spec

## 交易

### 使用 tronweb 发送交易

```javascript
const TronWeb = require('tronweb');
const HttpProvider = TronWeb.providers.HttpProvider;

const url = "https://api.shasta.trongrid.io";

const fullNode = new HttpProvider(url);
const solidityNode = new HttpProvider(url);
const eventServer = url;

const privateKey = '1111111111111311111111111111111111111111111111111111111111111111';
const privateKey1 = '1111111111111411111111111111111111111111111111111111111111111111';

const tronWeb = new TronWeb(
 fullNode,
 solidityNode,
 eventServer,
 privateKey
);

const address = 'TQjHpeTEscirkvpjxGDCYu7xS2yeD9U9VB';
const address1 = 'TAzfL5gZtmuhNs2VaS1PmmGj4tZST9ToXU';

tronWeb.transactionBuilder.sendTrx(address1, 100, address).then( resp => {
   tronWeb.trx.sign(resp, privateKey).then(signed => {
      tronWeb.trx.sendRawTransaction(signed).then( result => {
          console.log(result);
      });
   });
});

//signed transaction
{
  "result": true,
  "transaction": {
    "visible": false,
    "txID": "14ae7b62395cc7de3e9cf9cd189721677c653ef98def1425b6ae17d260e2d210",
    "raw_data": {
      "contract": [
        {
          "parameter": {
            "value": {
              "amount": 100,
              "owner_address": "41a1e81654258bf14f63feb2e8d1380075d45b0dac",
              "to_address": "410b3e84ec677b3e63c99affcadb91a6b4e086798f"
            },
            "type_url": "type.googleapis.com/protocol.TransferContract"
          },
          "type": "TransferContract"
        }
      ],
      "ref_block_bytes": "36b9",
      "ref_block_hash": "fb44f236fbf8d358",
      "expiration": 1563344625000,
      "timestamp": 1563344567482
    },
    "raw_data_hex": "0a0236b92208fb44f236fbf8d35840e8bae7f4bf2d5a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541a1e81654258bf14f63feb2e8d1380075d45b0dac1215410b3e84ec677b3e63c99affcadb91a6b4e086798f186470baf9e3f4bf2d",
    "signature": [
      "0264069fc649b7d4ab172d85f8c4bdb9d6974509a11ae36e2cc8577c878d94313b5703ed65b5959753467211ee0808ad69f30152b8a9bdd923663349002b6dc500"
    ]
  }
}
```

- *ref_block_hash*  引用块的 hash[9,15] 8个字节 
- *ref_block_bytes*  引用块的块高 Longs.toBytes(height) [7,8] 最后的两个字节
- *raw_data_hex* protobuf 协议序列化 raw_data
- *txID* sha256(raw_data_hex)
- *signature* row_data 中的 contract 对应， 每个 contract 都会有一个独立的 signature。 一个 Transaction 中可以包括多个合约调用。 signature 内容是 DER-encoded, 总长度`64*2+2=130` bytes

注：TRON 的 txID 并不包括签名信息

### 批量签名

token-core 通过链无关动作 `sign_txs` 批量签署 TRON 交易。外层使用
`SignTxsParam`，其中 `chainType` 为 `TRON`；每个 `SignTxsItem.input`
是 protobuf 编码后的 `TronTxInput`。调用方使用 `password` 或
`derivedKey` 鉴权，整批只解锁 keystore 一次。

```text
SignTxsParam {
  id: wallet_id,
  key: password 或 derivedKey,
  chainType: "TRON",
  path: "m/44'/195'/0'/0/0",
  items: [
    { input: encode(TronTxInput { rawData }), path: "" },
    { input: encode(TronTxInput { rawData }), path: "m/44'/195'/0'/0/1" }
  ]
}
```

item 的 `path` 非空时覆盖外层 path，否则继承外层 path。批签要求每笔
effective path 都非空且符合 TRON coin type `195'` 的约束；历史单签中
允许 `path: ""` 的调用方（包括私钥 keystore）迁移到批签时，也必须显式
提供合法占位 path，例如 `m/44'/195'/0'/0/0`。私钥 keystore 不使用该
path 派生密钥，但仍执行相同的批签输入校验。

一次请求最多包含 2048 笔交易。结果严格保持输入顺序：

- `signature` 与相同输入、path 的 `sign_tx` 结果一致；
- `txHash` 是 `SHA256(raw_data)` 的 64 位小写十六进制 txID，不带 `0x`；
- `fromAddress` 是签名 key 对应的 Base58Check TRON 地址。

任一 item 失败时整批不返回部分结果，错误格式为
`sign_txs failed at index {i}: {source}`。调用方应按输出下标把签名写回
对应交易，并在整个批量成功、核对 txID 与 fromAddress 后再广播；不得
提前广播已处理的前缀交易。

空批量和超限属于批级错误，分别返回 `sign_txs batch is empty` 和
`sign_txs batch exceeds max size of 2048`，不附带 item 下标。非法
protobuf、非法 `raw_data` hex、空或非法 effective path 会在查找或解锁
keystore 之前完成整批预检。

### 发送交易流程

- tronWeb.transactionBuilder.sendTx 创建一个未签名的交易
- tronWeb.trx.sign(tx, privateKey) 交易签名
- tronWeb.trx.sendRawTransaction(signedTx) 向节点发送交易

## 地址

### 生成算法

- 获取未压缩的公钥
- 使用 Keccak256 算法计算公钥的 Hash
- 保留最后的20个字节
- 增加 41 在最后的20个字节前面
- 转换为 Base58check 格式 <https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki[bip-13]>

### 通过助记词
TRON 采用 m/44'/195'/0' 路径生成符合 BIP-44 规范的地址。 m/44'/195'/0'/0/0 为第一个地址。 195’ 为 SLIP-44 为 TRON 定义。

## token-core 实现

### tron package

创建 tron library 来实现所有的与 tron 相关的实现。 预计会引用 crypto、chain、wallet、common 包

### rust 支持 protobuf 

* 引入 rust-protobuf 包
* 拷贝 tron 的 protobuf 文件到 tron/src/protos 目录
* 生成 rust 代码

### 新增 Address 实现

```rust
pub struct Address {
    //...
}

impl Address {
  fn from_public_key(pubkey: PublicKey) -> Result<Self, Error> {
    // ...
  }

  fn from_string(address: &'a str) -> Result<Self, Error> {
    // ...
  }

  fn into_bytes(&self) -> Vec<u8> {
    // ...
  }

  fn as_string(&self) -> &'a str {
    // ...    
  }
}

impl PartialEq for Address {
  fn eq(&self, other: &Self) -> bool {
    // ...
  }
}
```

### 新增 Transaction 实现

```rust
pub struct Transaction {
   //...
}

pub struct SignedTransaction {
    raw_transaction: Transaction
    // ...
}

impl SignedTransaction {
  fn from_bytes(bytes: &'a Vec<u8>) -> SignedTransaction {
     // ...
  }
 
  // 得到 transaction 的 raw data
  fn into_bytes(&self) -> Vec<u8> {
    // ...
  }
}

pub trait TransactionSigner {
  fn sign_tx(tx: RawTransaction) -> SignedTransaction {
    // ...
  }
}

impl TransactionSigner for PrivateKey {

}

impl TransactionSigner for Wallet {

}
```
