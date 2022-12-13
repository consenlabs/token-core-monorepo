//
//  CosmosApi.swift
//  imKeyConnector
//
//  Created by joe on 6/6/20.
//

import Foundation
import SwiftProtobuf

public class CosmosApi{
  public class func getAddress(path:String)throws -> String{
    var req = Cosmosapi_CosmosAddressReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "cosmos_get_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let eosPubkeyResponse = try! Cosmosapi_CosmosAddressRes(serializedData: dataRes)
    return eosPubkeyResponse.address
  }
  
  public class func displayAddress(path:String)throws -> String{
    var req = Cosmosapi_CosmosAddressReq()
    req.path = path
    
    var action = Api_ImkeyAction()
    action.method = "cosmos_register_address"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let eosPubkeyResponse = try! Cosmosapi_CosmosAddressRes(serializedData: dataRes)
    return eosPubkeyResponse.address
  }
  
  public class func signTX(cosmosInput:Cosmosapi_CosmosTxReq)throws -> Cosmosapi_CosmosTxRes{
    var action = Api_ImkeyAction()
    action.method = "cosmos_tx_sign"
    action.param = Google_Protobuf_Any()
    action.param.value = try! cosmosInput.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let cosmosOutput = try! Cosmosapi_CosmosTxRes(serializedData: dataRes)
    return cosmosOutput
  }
}
