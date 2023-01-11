//
//  EthApi.swift
//  imKeyConnector
//
//  Created by joe on 6/5/20.
//

import Foundation
import SwiftProtobuf

public class EthApi{
  public class func getAddress(path:String)throws -> String{
    var req = Ethapi_EthAddressReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eth_get_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Ethapi_EthAddressRes(serializedData: dataRes)
    return result.address
  }
  
  public class func displayAddress(path:String)throws -> String{
    var req = Ethapi_EthAddressReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eth_register_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Ethapi_EthAddressRes(serializedData: dataRes)
    return result.address
  }
  
  public class func signTX(ethInput:Ethapi_EthTxReq)throws -> Ethapi_EthTxRes{
    var action = Api_ImkeyAction()
    action.method = "eth_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! ethInput.serializedData()
    let paramHex = try action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let ouput = try! Ethapi_EthTxRes(serializedData: dataRes)
    return ouput
  }
  
  public class func ethSignMessage(input:Ethapi_EthMessageSignReq)throws -> Ethapi_EthMessageSignRes{
    var action = Api_ImkeyAction()
    action.method = "eth_message_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! input.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let ouput = try! Ethapi_EthMessageSignRes(serializedData: dataRes)
    return ouput
  }
}
