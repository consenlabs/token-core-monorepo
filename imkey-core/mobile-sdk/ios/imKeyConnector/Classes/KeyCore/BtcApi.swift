//
//  BtcApi.swift
//  imKeyConnector
//
//  Created by joe on 6/4/20.
//

import Foundation
import SwiftProtobuf

public class BtcApi{
  public static let network_mainet = "MAINNET"
  public static let network_testnet = "TESTNET"
  
  public class func getAddress(network:String, path:String)throws -> String{
    var req = Btcapi_BtcAddressReq()
    req.path = path
    req.network = network
    
    var action = Api_ImkeyAction()
    action.method = "btc_get_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcAddressRes(serializedData: dataRes)
    return result.address
  }
  
  public class func displayAddress(network:String, path:String)throws -> String{
    var req = Btcapi_BtcAddressReq()
    req.path = path
    req.network = network
    
    var action = Api_ImkeyAction()
    action.method = "btc_register_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcAddressRes(serializedData: dataRes)
    return result.address
  }
  
  public class func getSegwitAddress(network:String, path:String)throws -> String{
    var req = Btcapi_BtcAddressReq()
    req.path = path
    req.network = network
    
    
    var action = Api_ImkeyAction()
    action.method = "btc_get_setwit_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcAddressRes(serializedData: dataRes)
    return result.address
  }
  
  public class func displaySegwitAddress(network:String, path:String)throws -> String{
    var req = Btcapi_BtcAddressReq()
    req.path = path
    req.network = network
    
    var action = Api_ImkeyAction()
    action.method = "btc_register_segwit_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcAddressRes(serializedData: dataRes)
    return result.address
  }
  
  public class func getXpub(network:String, path:String)throws -> String{
    var req = Btcapi_BtcXpubReq()
    req.path = path
    req.network = network
    
    var action = Api_ImkeyAction()
    action.method = "btc_get_xpub"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcXpubRes(serializedData: dataRes)
    return result.xpub
  }
  
  public class func signTX(req:Btcapi_BtcTxReq)throws -> Btcapi_BtcTxRes{
    var action = Api_ImkeyAction()
    action.method = "btc_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcTxRes(serializedData: dataRes)
    return result
  }
  
  public class func signSegwitTX(req:Btcapi_BtcSegwitTxReq)throws -> Btcapi_BtcSegwitTxRes{
    var action = Api_ImkeyAction()
    action.method = "btc_segwit_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcSegwitTxRes(serializedData: dataRes)
    return result
  }
  
  public class func signUsdtTX(req:Btcapi_BtcTxReq)throws -> Btcapi_BtcTxRes{
    var action = Api_ImkeyAction()
    action.method = "btc_usdt_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcTxRes(serializedData: dataRes)
    return result
  }
  
  public class func signUsdtSegwitTX(req:Btcapi_BtcSegwitTxReq)throws -> Btcapi_BtcSegwitTxRes{
    var action = Api_ImkeyAction()
    action.method = "btc_usdt_segwit_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Btcapi_BtcSegwitTxRes(serializedData: dataRes)
    return result
  }
}
