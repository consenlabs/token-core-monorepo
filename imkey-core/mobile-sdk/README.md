# Mobile-SDK
Mobile SDK 对 imkey-core 做了封装，可以在android 和 ios 平台方便地接入 imkey-core。
## Android

1. 初始化蓝牙 

   ```java
   Ble.getInstance().initialize(mContext,new Locale("en"));
   ```

2. 搜索imkey

   ```java
   Ble.getInstance().startScan(20, new ScanCallback() {...
   ```

3. 连接imkey

   ```java
   Ble.getInstance().connect(bleDevice, 30, new ConnectCallback() {...
   ```

4. 连接成功后可以调用业务接口，例如更新applet：

   ```java
   DeviceApi.updateApplet(appletName);
   ```

5. 绑定设备（资产相关接口需要先绑定设备)

   1. 检查绑定状态

      ```java
      String status = DeviceApi.bindCheck();
      ```

   2. 如果是首次绑定需要调用显示绑定码接口

      ```java
      DeviceApi.displayBindCode();
      ```

   3. 绑定设备，传入imkey显示的绑定码（首次绑定）或用户输入的绑定码（非首次绑定）

      ```java
      String status = DeviceApi.bindAcquire(bindCode);
      ```

6. 绑定成功即可调用资产相关接口例如：

   1. 获取以太坊地址

      ```java
      EthApi.getAddress(Path.ETH_LEDGER);
      ```

   2. 以太坊交易签名

      ```java
      ethapi.Eth.EthTxReq ethTxReq = ethapi.Eth.EthTxReq.newBuilder()
              .setPath(Path.ETH_LEDGER)
              .setChainId("28")
              .setNonce("8")
              .setGasPrice("20000000008")
              .setGasLimit("189000")
              .setTo("0x3535353535353535353535353535353535353535")
              .setValue("512")
              .setData("")
              .setPayment("0.01 ETH")
              .setReceiver("0xE6F4142dfFA574D1d9f18770BF73814df07931F3")
              .setSender("0x6031564e7b2F5cc33737807b2E58DaFF870B590b")
              .setFee("0.0032 ether")
              .build();
      Eth.EthTxRes res = null;
      try {
          res = EthApi.signTx(ethTxReq);
      } catch (Exception e) {
          e.printStackTrace();
      }
      ```

## iOS

1. 初始化蓝牙 

   ```swift
   let initRes = BLE.shared().initialize()
   ```

2. 搜索imkey

   ```swift
   let res:Int = BLE.shared().startScan()
   ```

3. 连接imkey

   ```swift
   let result = try BLE.shared().connect(address: device.address,timeout: 12*1000)
   ```

4. 连接成功后可以调用业务接口，例如更新applet：

   ```swift
   try DeviceAPI.updateApp(appletName: appletName)
   ```

5. 绑定设备（资产相关接口需要先绑定设备)

   1. 检查绑定状态

      ```swift
      let status = try DeviceAPI.bindCheck()
      ```

   2. 如果是首次绑定需要调用显示绑定码接口

      ```swift
      try DeviceAPI.displayBindCode()
      ```

   3. 绑定设备，传入imkey显示的绑定码（首次绑定）或用户输入的绑定码（非首次绑定）

      ```swift
      let bindResult = try DeviceAPI.bindAcquire(bindCode: bindCode!)
      ```

6. 绑定成功即可调用资产相关接口例如：

   1. 获取以太坊地址

      ```swift
      let address = try EthApi.getAddress(path: BIP44.eth)
      ```

   2. 以太坊交易签名

      ```swift
      var ethInput = Ethapi_EthTxReq()
        ethInput.nonce = "8"
        ethInput.gasPrice = "20000000008"
        ethInput.gasLimit = "189000"
        ethInput.to = "0x3535353535353535353535353535353535353535"
        ethInput.value = "512"
        ethInput.data = ""
        ethInput.payment = "0.01 ETH"
        ethInput.receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3"
        ethInput.sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b"
        ethInput.fee = "0.0032 ether"
        ethInput.path = "m/44'/60'/0'/0/0"
        ethInput.chainID = "28"
        let output = try! EthApi.signTX(ethInput: ethInput)
      ```

