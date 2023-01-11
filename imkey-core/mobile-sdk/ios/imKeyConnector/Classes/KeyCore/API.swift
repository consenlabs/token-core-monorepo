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
  static let _shareManager = API()
  
  public class func shared() -> API {
    return _shareManager
  }
  
  private init() {
    Log.d("api init...")
    set_callback(swiftCallback)
  }
  
  let swiftCallback : @convention(c) (UnsafePointer<Int8>?,Int32) -> UnsafePointer<Int8>? = {
    (apdu,timeout) -> UnsafePointer<Int8>? in
    print("callback miaomiao v v timeout\(timeout)")
    let swiftApdu = String(cString:apdu!)
    
    var response = "";
    do {
      response = try BLE.shared().sendApdu(apdu: swiftApdu,timeout: UInt32(timeout * 1000))
    }catch let e as ImkeyError {
      response = "communication_error_" + e.message
    }catch{
      Log.d(error)
    }
    let count = response.utf8CString.count
    let result: UnsafeMutableBufferPointer<Int8> = UnsafeMutableBufferPointer<Int8>.allocate(capacity: count)
    _ = result.initialize(from: response.utf8CString)
    let p = UnsafePointer(result.baseAddress!)
    return p
  }
  
  public class func getSEID() ->String{
    var action = Api_ImkeyAction()
    action.method = "get_seid"
    action.param = Google_Protobuf_Any()
    action.param.value = try! action.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    call_imkey_api(paramHex)
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Deviceapi_GetSeidRes(serializedData: dataRes)
    return ouput.seid
  }
  
  public class func checkDevice(){
    Log.d("check device ......")
    
    var action = Api_ImkeyAction()
    action.method = "device_secure_check"
    //    action.param.value = try! deviceParam.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    call_imkey_api(paramHex)
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
    //    let paramHex = try! action.serializedData().key_toHexString()
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
    //    let paramHex = try! action.serializedData().key_toHexString()
    //    call_tcx_api(paramHex)
  }
  
  public class func downloadApp(){
    var param = Deviceapi_AppDownloadReq()
    param.appName = "BTC"
    
    var action = Api_ImkeyAction()
    action.method = "app_download"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    call_imkey_api(paramHex)
  }
  
  public class func updateApp(){
    var param = Deviceapi_AppDownloadReq()
    param.appName = "BTC"
    
    var action = Api_ImkeyAction()
    action.method = "app_update"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    call_imkey_api(paramHex)
  }
  
  public class func deleteApp(){
    var param = Deviceapi_AppDownloadReq()
    param.appName = "BTC"
    
    var action = Api_ImkeyAction()
    action.method = "app_delete"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    call_imkey_api(paramHex)
  }
  
  //  public class func getAddress(){
  //    return get_address()
  //  }
  //
  //  public class func signTransaction(){
  //    return sign_transaction()
  //  }
  
  public class func ethSignTx(ethInput:Ethapi_EthTxReq) -> Ethapi_EthTxRes{
    var action = Api_ImkeyAction()
    action.method = "eth_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! ethInput.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    
    Log.d("eth param ready..")
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Ethapi_EthTxRes(serializedData: dataRes)
    return ouput
  }
  
  public class func ethSignMessage(input:Ethapi_EthMessageSignReq) -> Ethapi_EthMessageSignRes{
    var action = Api_ImkeyAction()
    action.method = "eth_message_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! input.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    
    clear_err()
    Log.d("eth param ready..")
    let res = call_imkey_api(paramHex)
    
    //error
    let error = get_last_err_message()
    if error != nil{
      let dataError = String(cString:error!).key_dataFromHexString()!
      let response = try! Api_Response(serializedData: dataError)
      if !response.isSuccess {
        print(response.error)
      }
    }
    
    //success
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Ethapi_EthMessageSignRes(serializedData: dataRes)
    return ouput
  }
  
  public class func eosSignMessage(input:Eosapi_EosMessageSignReq) -> Eosapi_EosMessageSignRes{
    var action = Api_ImkeyAction()
    action.method = "eos_message_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! input.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    
    Log.d("eth param ready..")
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ouput = try! Eosapi_EosMessageSignRes(serializedData: dataRes)
    return ouput
  }
  
  public class func eosSignTx(eosInput:Eosapi_EosTxReq) -> Eosapi_EosTxRes{
    var action = Api_ImkeyAction()
    action.method = "eos_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! eosInput.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    
    Log.d("eos param ready..")
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosOutput = try! Eosapi_EosTxRes(serializedData: dataRes)
    return eosOutput
  }
  
  public class func cosmosSignTx(cosmosInput:Cosmosapi_CosmosTxReq) -> Cosmosapi_CosmosTxRes{
    var action = Api_ImkeyAction()
    action.method = "cosmos_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! cosmosInput.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    //response
    Log.d("cosmos param ready..")
    let res = call_imkey_api(paramHex)
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let cosmosOutput = try! Cosmosapi_CosmosTxRes(serializedData: dataRes)
    return cosmosOutput
  }
  
  public class func eosPubkey(path:String) -> String{
    var req = Eosapi_EosPubkeyReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eos_get_pubkey"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosPubkeyResponse = try! Eosapi_EosPubkeyRes(serializedData: dataRes)
    return eosPubkeyResponse.pubkey
  }
  
  public class func eosReginPubkey(path:String) -> String{
    var req = Eosapi_EosPubkeyReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eos_register_pubkey"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosPubkeyResponse = try! Eosapi_EosPubkeyRes(serializedData: dataRes)
    return eosPubkeyResponse.pubkey
  }
  
  public class func cosmosAddress(path:String) -> String{
    var req = Cosmosapi_CosmosAddressReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "cosmos_get_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosPubkeyResponse = try! Cosmosapi_CosmosAddressRes(serializedData: dataRes)
    return eosPubkeyResponse.address
  }
  
  public class func cosmosReginAddress(path:String) -> String{
    var req = Cosmosapi_CosmosAddressReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "cosmos_register_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let eosPubkeyResponse = try! Cosmosapi_CosmosAddressRes(serializedData: dataRes)
    return eosPubkeyResponse.address
  }
  
  public class func ethAddress(path:String) -> String{
    var req = Ethapi_EthAddressReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eth_get_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ethAddressResponse = try! Ethapi_EthAddressRes(serializedData: dataRes)
    return ethAddressResponse.address
  }
  
  public class func ethReginAddress(path:String) -> String{
    var req = Ethapi_EthAddressReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eth_register_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    let res = call_imkey_api(paramHex)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let ethAddressResponse = try! Ethapi_EthAddressRes(serializedData: dataRes)
    return ethAddressResponse.address
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
    
    var bindCheckParam = Deviceapi_BindCheckReq()
    bindCheckParam.filePath = path
    
    var action = Api_ImkeyAction()
    action.method = "bind_check"
    action.param = Google_Protobuf_Any()
    action.param.value = try! bindCheckParam.serializedData()
    
    //    clear_err()
    let paramHex = try! action.serializedData().key_toHexString()
    let res = call_imkey_api(paramHex)
    //    let error = get_last_err_message()
    //    print(error)
    
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
    
    //    clear_err()
    let paramHex = try! action.serializedData().key_toHexString()
    let res = call_imkey_api(paramHex)
    //    let error = get_last_err_message()
    //    print(error)
    
    let strRes = String(cString:res!)
    let dataRes = strRes.key_dataFromHexString()!
    let bindResponse = try! Deviceapi_BindAcquireRes(serializedData: dataRes)
    return bindResponse.bindResult
  }
  
  public class func btcSignTX(){
    Log.d("btc sign ...")
    var btcInput = Btcapi_BtcTxReq()
    btcInput.amount = Int64(799988000)
    btcInput.to = "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3"
    btcInput.fee = Int64(10000)
    //    btcInput.payment = "0.0001 BT"
    //    btcInput.toDis = "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt"
    //    btcInput.from = "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy"
    //    btcInput.feeDis = "0.00007945 BTC"
    btcInput.pathPrefix = "m/44'/0'/0'"
    btcInput.changeAddressIndex = 1
    btcInput.network = "TESTNET"
    
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
    
    let paramHex = try! action.serializedData().key_toHexString()
    
    Log.d("eos param ready..")
    let res = call_imkey_api(paramHex)
    let hexRes = String(cString:res!).key_toHexString()
    Log.d(hexRes)
  }
  
  //  public class func cosmosSignxTX() -> TransactionSignedResult{
  //    Cosmosapi_CosmosTxInput
  //  }
  
  @discardableResult
  public func callApi(paramHex:String)throws ->String{
    clear_err()
    let res = call_imkey_api(paramHex)
    
    let error = get_last_err_message()
    let errorRes = String(cString:error!)
    if errorRes.count > 0{
      let dataError = errorRes.key_dataFromHexString()!
      let response = try! Api_Response(serializedData: dataError)
      if !response.isSuccess {
        print(response.error)
        throw response.error
      }
    }
    
    let strRes = String(cString:res!)
    return strRes
  }
}
