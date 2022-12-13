# imkey-android-sdk

#### 一、下载项目，把imkeylibrary导入项目中

#### 二、 配置权限

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" />
<uses-permission android:name="android.permission.BLUETOOTH" />
<uses-permission android:name="android.permission.WAKE_LOCK" />
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATIO"/>
```

Android 6.0 以上需要动态申请权限

#### 三、蓝牙连接 imkey

首先要打开蓝牙，参考demo

###### 1. 初始化

```java
Ble.getInstance(mContext).initialize();
```

###### 2. 搜索蓝牙设备

```java
Ble.getInstance(mContext).startScan(20, new ScanCallback() {
    @Override
    public void onScanStarted() {
        Log.d(TAG, "scan start...");
    }

    @Override
    public void onScanDevice(BleDevice bleDevice) {
        devices.add(bleDevice);
        deviceInfos.add(bleDevice.toString());
        adapter.notifyDataSetChanged();
    }

    @Override
    public void onScanStopped() {
        Log.d(TAG, "scan stop");
    }

    @Override
    public void onScanFail(ErrorCode errorCode) {
        Toast.makeText(mContext, errorCode.get_desc(), Toast.LENGTH_SHORT).show();
    }
});
```

从onScanDevice 方法得到 BleDevice 对象，连接和发送数据时要用到

###### 3. 连接设备

```java
Ble.getInstance(mContext).connect(bleDevice, 30, new ConnectCallback() {
    @Override
    public void onConnecting(BleDevice bleDevice) {
        Log.d(TAG, "onConnecting... " + bleDevice.toString());
        pd.setMessage("正在连接...");
        pd.show();
    }

    @Override
    public void onConnected(BleDevice bleDevice) {
        mDevice = bleDevice;
        Log.d(TAG, "onConnected... " + bleDevice.toString());
        mTxtState.setText(bleDevice.toString());
        pd.dismiss();
        mManager = new Manager(mContext, mDevice);
        mBtc = new Btc(mContext, bleDevice, BTC_AID);
    }

    @Override
    public void onDisconnected(BleDevice bleDevice) {
        Log.d(TAG, "onDisconnected... " + bleDevice.toString());
        mTxtState.setText("");
    }

    @Override
    public void onConnectFail(ErrorCode errorCode) {
        Log.d(TAG, "onConnectFail... " + errorCode.toString() + errorCode.get_desc());
        pd.dismiss();
        Toast.makeText(mContext, errorCode.get_desc(), Toast.LENGTH_SHORT).show();
    }
});
```

###### 4. 其他方法

```java
Ble.getInstance(mContext).stopScan();//停止扫描
Ble.getInstance(mContext).disconnect(mDevice);//断开连接
Ble.getInstance(mContext).finalize();//析构
```

要确保蓝牙执行下一个动作前，结束之前动作。搜索同时不能连接

#### 四、比特币

###### 1.  创建Btc对象

```java
mBtc = new Btc(mContext, bleDevice, BTC_AID);
```

###### 2. 获取XPub

```java
xpub = mBtc.getXpub(BTC_PATH);
```

###### 3. 获取地址

```
address = mBtc.getAddress(BTC_PATH);
```

###### 4. 消息签名

```java
sign = mBtc.signMessage(BTC_PATH, data);
```

###### 5. 交易签名

先构建 BitcoinTransaction 对象

```java
private static BitcoinTransaction createMultiUXTOOnTestnet() {
    ArrayList<BitcoinTransaction.UTXO> utxo = new ArrayList<>();

    utxo.add(new BitcoinTransaction.UTXO(
            "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a", 0,
            200000000, "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC",
            "76a914118c3123196e030a8a607c22bafc1577af61497d88ac",
            "0/22"));
    utxo.add(new BitcoinTransaction.UTXO(
            "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531", 1,
            200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
            "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
            "0/0"));
    utxo.add(new BitcoinTransaction.UTXO(
            "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9", 0,
            200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
            "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
            "0/0"));
    utxo.add(new BitcoinTransaction.UTXO(
            "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9", 1,
            200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
            "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
            "0/0"));

    BitcoinTransaction tran = new BitcoinTransaction("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3", 53,
            new Address(TestNet3Params.get(), "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3"), 750000000, 502130, utxo);

    return tran;
}
```

然后调用 signTransaction获取签名结果

```
TransactionSignedResult result = transaction.signTransaction(Path.BTC_PATH_PREFIX);
```

调用signSegWitTransaction方法获取带隔离见证签名结果

```
TransactionSignedResult signedResult = createSegWitMultiUXTOOnTestnet().signSegWitTransaction(Path.BTC_PATH_PREFIX);
```



#### 五、以太坊

###### 1.  创建Btc对象

```java
mEth = new Eth(mContext, bleDevice, ETH_AID);
```

###### 2. 获取XPub

```java
xpub = mEth.getXpub(ETH_PATH);
```

###### 3. 获取地址

```
address = mEth.getAddress(ETH_PATH);
```

###### 4. 消息签名

```java
sign = mEth.signMessage(ETH_PATH, data);
```

###### 5. 交易签名

先构建 EthereumTransaction 对象

```
EthereumTransaction ethTx = new EthereumTransaction(BigInteger.valueOf(8L), BigInteger.valueOf(20000000008L),
    BigInteger.valueOf(189000L), "0x3535353535353535353535353535353535353535", BigInteger.valueOf(512), "");
```

然后调用 signTransaction 获取签名结果

```
TransactionSignedResult result = transaction.signTransaction("0",path);
```

#### 六、应用管理

###### 1. 创建 mananger 对象

```
mManager = new Manager(mContext, mDevice);
```

###### 2. 激活设备

```
response = mManager.activeDevice();
```

###### 3. 验证设备

```
response = mManager.checkDevice();
```

###### 4. 检查更新

```
response = mManager.checkUpdate();
```

###### 5. 下载应用

```
response = mManager.download(Applet.BTC_NAME);
```

###### 6. 删除应用 

```
response = mManager.delete(Applet.BTC_NAME);
```

###### 7. 更新应用

```
response = mManager.update(Applet.BTC_NAME);
```
