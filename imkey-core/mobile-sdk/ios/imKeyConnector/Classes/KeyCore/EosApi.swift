//
//  EosApi.swift
//  imKeyConnector
//
//  Created by joe on 6/5/20.
//

import Foundation
import SwiftProtobuf

public class EosApi{
  public class func getPubkey(path:String)throws -> String{
    var req = Eosapi_EosPubkeyReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eos_get_pubkey"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Eosapi_EosPubkeyRes(serializedData: dataRes)
    return result.pubkey
  }
  
  public class func displayPubkey(path:String)throws -> String{
    var req = Eosapi_EosPubkeyReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "eos_register_pubkey"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Eosapi_EosPubkeyRes(serializedData: dataRes)
    return result.pubkey
  }
  
  public class func signMessage(input:Eosapi_EosMessageSignReq)throws -> Eosapi_EosMessageSignRes{
    var action = Api_ImkeyAction()
    action.method = "eos_message_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! input.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let ouput = try! Eosapi_EosMessageSignRes(serializedData: dataRes)
    return ouput
  }
  
  public class func signTX(eosInput:Eosapi_EosTxReq)throws -> Eosapi_EosTxRes{
    var action = Api_ImkeyAction()
    action.method = "eos_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! eosInput.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let eosOutput = try! Eosapi_EosTxRes(serializedData: dataRes)
    return eosOutput
  }
}
