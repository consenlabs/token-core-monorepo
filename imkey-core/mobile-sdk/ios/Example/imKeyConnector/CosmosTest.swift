//
//  CosmosTest.swift
//  imKeyConnector_Example
//
//  Created by joe on 7/17/19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation
import imKeyConnector

class CosmosTest:FeatTest{
  class func testCosmosSign(handle:UInt) -> TestResult{
    var sucessCount = 0
    var failCount = 0
    var failCaseInfo = [String]()
    let jsonRoot = readJson(resource: "cosmostransactiontest.json")
    for (key, value) in jsonRoot {
      if let dict = value as? [String: Any],let preview = dict["preview"] as? [String: Any],
        let sigs = dict["signatures"] as? [[String: Any]]{
        let raw = createCosmosRaw(dict: dict)
        print(raw)
        
        
        for i in 0...0{
          do {
            //fee
            let sourceFee = dict["fee"] as! [String: Any]
            let sourceFeeAmount = sourceFee["amount"] as![[String: Any]]
            var feeAmount = [Cosmosapi_Coin]()
            for item in sourceFeeAmount{
                var msgCoin = Cosmosapi_Coin()
                msgCoin.amount = item["amount"] as! String
                msgCoin.denom = item["denom"] as! String
              feeAmount.append(msgCoin)
            }
            
            var fee = Cosmosapi_StdFee()
            fee.gas = sourceFee["gas"] as! String
            fee.amount = feeAmount
            
            //msgs
            var msgs = [Cosmosapi_Msg]()
            let sourceMsg = dict["msg"] as! [[String: Any]]
            for item in sourceMsg{
              let type = item["type"] as! String
              let value = item["value"] as! [String: Any]
              let amount = value["amount"] as![[String: Any]]
              var msgAmount = [Cosmosapi_Coin]()
              for item in amount{
                var msgCoin = Cosmosapi_Coin()
//                let num = item["amount"] as! NSNumber
//                msgCoin.amount = num.stringValue
                msgCoin.amount = item["amount"] as! String
                msgCoin.denom = item["denom"] as! String
                msgAmount.append(msgCoin)
              }
              
              var msgValue = Cosmosapi_MsgValue()
              msgValue.amount = msgAmount
              if type == "cosmos-sdk/MsgSend" {
                msgValue.addresses = ["from_address":value["from_address"] as! String,
                "to_address":value["to_address"] as! String]
              }else{
                msgValue.addresses = ["delegator_address":value["delegator_address"] as! String,
                                      "validator_address":value["validator_address"] as! String]
              }
              
              var msg = Cosmosapi_Msg()
              msg.type = type
              msg.value = msgValue
              msgs.append(msg)
            }
            
            //signData
            var signData = Cosmosapi_SignData()
            signData.accountNumber = dict["accountNumber"] as! String
            signData.chainID = dict["chainId"] as! String
            signData.fee = fee
            signData.memo = dict["memo"] as! String
            signData.msgs = msgs
            signData.sequence = dict["sequence"] as! String
            
            //cosmosInput
            var cosmosInput = Cosmosapi_CosmosTxReq()
            cosmosInput.signData = signData
            cosmosInput.path = BIP44.cosmos
            cosmosInput.paymentDis = preview["payment"] as! String
            cosmosInput.toDis = preview["receiver"] as! String
            cosmosInput.feeDis = preview["fee"] as! String
            let comsosOutput = API.cosmosSignTx(cosmosInput: cosmosInput)

            
//            let cosmosSigner = try CosmosTransaction(raw: raw)
//            let signResult = try cosmosSigner.sign(handle: handle, path: BIP44.cosmos, paymentDis: preview["payment"] as? String, toDis: preview["receiver"] as! String, feeDis: preview["fee"] as! String)
            
            let data = comsosOutput.txData.data(using: .utf8)!
            let jsonObject = try! JSONSerialization.jsonObject(with: data, options : .allowFragments) as? Dictionary<String,Any>
            
            let expSig = sigs[0]["signature"] as! String
            let sigTx = jsonObject as!  [String: Any]
            let resSigs = sigTx["signatures"] as! [[String: Any]]
            let resSig = resSigs[0]["signature"] as! String
            
            print("expSig:" + expSig)
            print("actual:" + resSig)
            
            if expSig == resSig{
              sucessCount += 1
              break
            }else{
              failCount += 1
              failCaseInfo.append("\(key)  \(i) time: Assert fail")
            }
          } catch let e as ImkeyError {
            failCount += 1
            failCaseInfo.append("\(key)  \(i) time: \(e.message)")
          }catch{
            failCount += 1
            failCaseInfo.append("\(key)  \(i) time: \(error)")
          }
        }
      }
    }
    return TestResult(totalCaseCount: jsonRoot.count, successCaseCount: sucessCount, failCaseCount: failCount, failCaseInfo: failCaseInfo)
  }
  
  class func createCosmosRaw(dict:[String: Any]) -> [String: Any]{
    let cosmosTx: [String: Any] = [
      "accountNumber": dict["accountNumber"]!,
      "sequence": dict["sequence"]!,
      "chainId": dict["chainId"]!,
      "msgs":dict["msg"]!,
      "fee":dict["fee"]!,
      "memo":dict["memo"]!
    ]
    return cosmosTx
  }
}
