//
//  API.swift
//  imKeyConnector
//
//  Created by joe on 12/9/18.
//

import Foundation
import SwiftProtobuf
import imKeyBleLib

public class API{
  public class func startMessageDeamon(){
    DispatchQueue.global().async {
        while true{
          Log.d("start while...")
          
          //get apdu
          var apdu = ""
          while true{
            apdu = String(cString:get_apdu())
            if apdu != ""{
              let count = "".utf8CString.count
              let result: UnsafeMutableBufferPointer<Int8> = UnsafeMutableBufferPointer<Int8>.allocate(capacity: count)
              _ = result.initialize(from: "".utf8CString)
              let p = UnsafePointer(result.baseAddress!)
              set_apdu(p)
              break
            }
            sleep(1)
          }
          
          //send apdu
          let res = try! BLE.shared().sendApdu(apdu: apdu)
          
          //set return
          var apduRet = ""
          while true{
            apduRet = String(cString:get_apdu_return())
            if apduRet == ""{
              let count = res.utf8CString.count
              let result: UnsafeMutableBufferPointer<Int8> = UnsafeMutableBufferPointer<Int8>.allocate(capacity: count)
              _ = result.initialize(from: res.utf8CString)
              let p = UnsafePointer(result.baseAddress!)
              set_apdu_return(p)
              break
            }
            sleep(1)
          }
        }
      }
    }
  
//  let swiftCallback : @convention(c) (UnsafePointer<Int8>?,Int32) -> UnsafePointer<Int8>? = {
//    (apdu,timeout) -> UnsafePointer<Int8>? in
//    print("callback miaomiao v v timeout\(timeout)")
//    let swiftApdu = String(cString:apdu!)
//    
//    var response = "";
//    do {
//      response = try BLE.shared().sendApdu(apdu: swiftApdu,timeout: UInt32(timeout * 1000))
//    }catch let e as ImkeyError {
//      response = "communication_error_" + e.message
//    }catch{
//      Log.d(error)
//    }
//    let count = response.utf8CString.count
//    let result: UnsafeMutableBufferPointer<Int8> = UnsafeMutableBufferPointer<Int8>.allocate(capacity: count)
//    _ = result.initialize(from: response.utf8CString)
//    let p = UnsafePointer(result.baseAddress!)
//    return p
//  }
//  
//  public class func setCallback(){
//
//    set_callback(swiftCallback)
//  }
  
  public class func getSEID() ->String{
    var action = Api_ImkeyAction()
    action.method = "get_seid"
    action.param = Google_Protobuf_Any()
    action.param.value = try! action.serializedData()
    let paramHex = try! action.serializedData().toHexString()
    call_imkey_api(paramHex)
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Deviceapi_GetSeidRes(serializedData: dataRes)
    return ouput.seid
  }
  
  public class func getBleVersion() ->String{
    var action = Api_ImkeyAction()
    action.method = "get_ble_version"
    action.param = Google_Protobuf_Any()
    action.param.value = try! action.serializedData()
    let paramHex = try! action.serializedData().toHexString()
    call_imkey_api(paramHex)
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Deviceapi_GetSeidRes(serializedData: dataRes)
    return ouput.seid
  }
  
  public class func getRamSize() ->String{
    var action = Api_ImkeyAction()
    action.method = "get_ram_size"
    action.param = Google_Protobuf_Any()
    action.param.value = try! action.serializedData()
    let paramHex = try! action.serializedData().toHexString()
    call_imkey_api(paramHex)
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Deviceapi_GetSeidRes(serializedData: dataRes)
    return ouput.seid
  }
  
  public class func getBatteryPower() ->String{
    var action = Api_ImkeyAction()
    action.method = "get_battery_power"
    action.param = Google_Protobuf_Any()
    action.param.value = try! action.serializedData()
    let paramHex = try! action.serializedData().toHexString()
    call_imkey_api(paramHex)
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Deviceapi_GetSeidRes(serializedData: dataRes)
    return ouput.seid
  }
  
  public class func getLifeTime() ->String{
    var action = Api_ImkeyAction()
    action.method = "get_life_time"
    action.param = Google_Protobuf_Any()
    action.param.value = try! action.serializedData()
    let paramHex = try! action.serializedData().toHexString()
    call_imkey_api(paramHex)
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Deviceapi_GetSeidRes(serializedData: dataRes)
    return ouput.seid
  }
  
  public class func checkDevice(){
//    Log.d("check device ......")
//    var deviceParam = Api_DeviceParam()
//    deviceParam.action = "se_secure_check"
//    deviceParam.param = Google_Protobuf_Any()
//
//    var action = Api_TcxAction()
//    action.method = "device_manage"
//    action.param = Google_Protobuf_Any()
//    action.param.value = try! deviceParam.serializedData()
//
//    let paramHex = try! action.serializedData().toHexString()
//    call_imkey_api(paramHex)
  }
  
  public class func activeDevice(){
//    var deviceParam = Api_DeviceParam()
//    deviceParam.action = "se_activate"
//    deviceParam.param = Google_Protobuf_Any()
//
//    var action = Api_TcxAction()
//    action.method = "device_manage"
//    action.param = Google_Protobuf_Any()
//    action.param.value = try! deviceParam.serializedData()
//
//    let paramHex = try! action.serializedData().toHexString()
//    call_tcx_api(paramHex)
  }
  
  public class func checkUpdate(){
//    var deviceParam = Api_DeviceParam()
//    deviceParam.action = "se_query"
//    deviceParam.param = Google_Protobuf_Any()
//
//    var action = Api_TcxAction()
//    action.method = "device_manage"
//    action.param = Google_Protobuf_Any()
//    action.param.value = try! deviceParam.serializedData()
//
//    let paramHex = try! action.serializedData().toHexString()
//    call_tcx_api(paramHex)
  }
  
  public class func downloadApp(appletName:String){
    var param = Deviceapi_AppDownloadReq()
    param.appName = appletName
    
    var action = Api_ImkeyAction()
    action.method = "app_download"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    call_imkey_api(paramHex)
  }
  
  public class func updateApp(appletName:String){
    var param = Deviceapi_AppDownloadReq()
    param.appName = appletName
    
    var action = Api_ImkeyAction()
    action.method = "app_update"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    call_imkey_api(paramHex)
  }
  
  public class func deleteApp(appletName:String){
    var param = Deviceapi_AppDownloadReq()
    param.appName = appletName
    
    var action = Api_ImkeyAction()
    action.method = "app_delete"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    call_imkey_api(paramHex)
  }
  
//  public class func getAddress(){
//    return get_address()
//  }
//  
//  public class func signTransaction(){
//    return sign_transaction()
//  }
  
  public class func ethSignTx(ethInput:Ethapi_EthTxInput) -> Ethapi_EthTxOutput{
    var action = Api_ImkeyAction()
    action.method = "eth_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! ethInput.serializedData()

    let paramHex = try! action.serializedData().toHexString()
    
    Log.d("eth param ready..")
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Ethapi_EthTxOutput(serializedData: dataRes)
    return ouput
  }
  
  public class func ethSignMessage(input:Ethapi_EthMessageInput) -> Ethapi_EthMessageOutput{
    var action = Api_ImkeyAction()
    action.method = "eth_message_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! input.serializedData()

    let paramHex = try! action.serializedData().toHexString()
    
    imkey_clear_err()
    Log.d("eth param ready..")
    let res = call_imkey_api(paramHex)
    
    //error
    let error = imkey_get_last_err_message()
    if error != nil{
      let dataError = String(cString:error!).key_dataFromHexString()!
      let response = try! Api_ErrorResponse(serializedData: dataError)
      if !response.isSuccess {
        print(response.error)
      }
    }
    
    //success
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Ethapi_EthMessageOutput(serializedData: dataRes)
    return ouput
  }
  
  public class func eosSignMessage(input:Eosapi_EosMessageInput) -> Eosapi_EosMessageOutput{
    var action = Api_ImkeyAction()
    action.method = "eos_message_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! input.serializedData()

    let paramHex = try! action.serializedData().toHexString()
    
    Log.d("eth param ready..")
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Eosapi_EosMessageOutput(serializedData: dataRes)
    return ouput
  }
  
  public class func eosSignTx(eosInput:Eosapi_EosTxInput) -> Eosapi_EosTxOutput{
    var action = Api_ImkeyAction()
    action.method = "eos_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! eosInput.serializedData()

    let paramHex = try! action.serializedData().toHexString()
    
    Log.d("eos param ready..")
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosOutput = try! Eosapi_EosTxOutput(serializedData: dataRes)
    return eosOutput
  }
  
  public class func cosmosSignTx(cosmosInput:Cosmosapi_CosmosTxInput) -> Cosmosapi_CosmosTxOutput{
    var action = Api_ImkeyAction()
    action.method = "cosmos_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! cosmosInput.serializedData()
    let paramHex = try! action.serializedData().toHexString()
    
    //response
    Log.d("cosmos param ready..")
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let cosmosOutput = try! Cosmosapi_CosmosTxOutput(serializedData: dataRes)
    return cosmosOutput
  }
  
  public class func eosPubkey(path:String) -> String{
    var req = Api_PubKeyParam()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eos_get_pubkey"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosPubkeyResponse = try! Api_EosWallet(serializedData: dataRes)
    return eosPubkeyResponse.publicKeys[0].publicKey
  }
  
  public class func eosReginPubkey(path:String) -> String{
    var req = Api_PubKeyParam()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eos_register_pubkey"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosPubkeyResponse = try! Api_EosWallet(serializedData: dataRes)
    return eosPubkeyResponse.publicKeys[0].publicKey
  }
  
  public class func cosmosAddress(path:String) -> String{
    var req = Api_AddressParam()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "cosmos_get_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosPubkeyResponse = try! Api_AddressResult(serializedData: dataRes)
    return eosPubkeyResponse.address
  }
  
  public class func cosmosReginAddress(path:String) -> String{
    var req = Api_AddressParam()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "cosmos_register_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosPubkeyResponse = try! Api_AddressResult(serializedData: dataRes)
    return eosPubkeyResponse.address
  }
  
  public class func ethAddress(path:String) -> String{
    var req = Api_AddressParam()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eth_get_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ethAddressResponse = try! Api_AddressResult(serializedData: dataRes)
    return ethAddressResponse.address
  }
  
  public class func ethReginAddress(path:String) -> String{
    var req = Api_AddressParam()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eth_register_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ethAddressResponse = try! Api_AddressResult(serializedData: dataRes)
    return ethAddressResponse.address
  }
  
  public class func initImkeyCoreX(xpubKey: String, xpubIv: String, dir: String) throws {
    #if DEBUG
    let isDebug = true
    #else
    let isDebug = false
    #endif
    
    var param = Api_InitImKeyCoreXParam()
    param.fileDir = dir
    param.xpubCommonKey = xpubKey
    param.xpubCommonIv = xpubIv
    param.system = "ios"
    
    var action = Api_ImkeyAction()
    action.method = "init_imkey_core_x"
    action.param.typeURL = "tcx.init_imkey_core_x"
    action.param.value = try param.serializedData()
    
    let actionBytes = try action.serializedData()
    let hex = actionBytes.toHexString()
    _ = call_imkey_api(hex)
  }
  
  public class func bindCheck() -> String{
    let path = "\(NSHomeDirectory())/Documents/wallets/imkey/keys"
    var walletsDirectory = URL(fileURLWithPath: path)
    print(path)
    do {
      if !FileManager.default.fileExists(atPath: path) {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try walletsDirectory.setResourceValues(resourceValues)
      }
    } catch let err {
      Log.d(err)
    }
    
    try! initImkeyCoreX(xpubKey: "String", xpubIv: "String", dir: path)
    
    var action = Api_ImkeyAction()
    action.method = "bind_check"
    
    imkey_clear_err()
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
    let error = imkey_get_last_err_message()
    print(error!)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let bindResponse = try! Deviceapi_BindCheckRes(serializedData: dataRes)
    return bindResponse.bindStatus
  }
  
  public class func bindAcquire(bindCode:String) -> String{
    var bindAcquireParam = Deviceapi_BindAcquireReq()
    bindAcquireParam.bindCode = bindCode
    
    var action = Api_ImkeyAction()
    action.method = "bind_acquire"
    action.param = Google_Protobuf_Any()
    action.param.value = try! bindAcquireParam.serializedData()
    
    //    imkey_clear_err()
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
    //    let error = imkey_get_last_err_message()
    //    print(error)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let bindResponse = try! Deviceapi_BindAcquireRes(serializedData: dataRes)
    return bindResponse.bindResult
  }
  
  public class func substrateSignTX(){
    var input = Substrateapi_SubstrateRawTxIn()
    input.rawData = "0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7"
    var signParam = Common_SignParam()
    signParam.chainType = "POLKADOT"
    signParam.path = BIP44.polkadot
    signParam.payment = "25 DOT"
    signParam.receiver = "12pWV6LvG4iAfNpFNTvvkWy3H9H8wtCkjiXupAzo2BCmPViM"
    signParam.sender = "147mvrDYhFpZzvFASKBDNVcxoyz8XCVNyyFKSZcpbQxN33TT"
    signParam.fee = "15.4000 milli DOT"
    signParam.input.value = try! input.serializedData()
    
    var action = Api_ImkeyAction()
    action.param.value = try! signParam.serializedData()
    action.method = "sign_tx"
    
    let paramHex = try! action.serializedData().toHexString()
    let res = call_imkey_api(paramHex)
//    let hexRes = String(cString:res!).toHexString()
//    Log.d(hexRes)
  }
  
  public class func btcSignTX(){
    Log.d("btc sign ...")
    var btcInput = Btcapi_BtcTxInput()
    btcInput.amount = Int64(799988000)
    btcInput.to = "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3"
    btcInput.fee = Int64(10000)
//    btcInput.payment = "0.0001 BT"
//    btcInput.toDis = "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt"
//    btcInput.from = "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy"
//    btcInput.feeDis = "0.00007945 BTC"
//    btcInput.pathPrefix = "btccpath.."
//    btcInput.changeAddressIndex = 1
//    btcInput.network = "TESTNET"
    
    let utxos = [
    [
      "txHash": "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a",
      "vout": "0",
      "amount": "200000000",
      "address": "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC",
      "scriptPubKey": "76a914118c3123196e030a8a607c22bafc1577af61497d88ac",
      "derivedPath": "0/22"
    ],
    [
      "txHash": "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531",
      "vout": "1",
      "amount": "200000000",
      "address": "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
      "scriptPubKey": "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
      "derivedPath": "0/0"
    ],
    [
      "txHash": "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9",
      "vout": "0",
      "amount": "200000000",
      "address": "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
      "scriptPubKey": "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
      "derivedPath": "0/0"
    ],
    [
      "txHash": "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9",
      "vout": "1",
      "amount": "200000000",
      "address": "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
      "scriptPubKey": "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
      "derivedPath": "0/0"
    ]
      ].map { _ in Btcapi_Utxo() }
    btcInput.unspents = utxos

    var action = Api_ImkeyAction()
    action.method = "btc_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! btcInput.serializedData()

    let paramHex = try! action.serializedData().toHexString()
    
    Log.d("eos param ready..")
    let res = call_imkey_api(paramHex)
//    let hexRes = String(cString:res!).toHexString()
//    Log.d(hexRes)
  }
  
//  public class func cosmosSignxTX() -> TransactionSignedResult{
//    Cosmosapi_CosmosTxInput
//  }
}
