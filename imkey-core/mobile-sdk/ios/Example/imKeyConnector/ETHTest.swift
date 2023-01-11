//
//  ETHTest.swift
//  imKeyConnector_Example
//
//  Created by joe on 7/17/19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation
import imKeyConnector

class ETHTest: FeatTest {
  class func testETHSign(handle:UInt) -> TestResult{
    var sucessCount = 0
    var failCount = 0
    var failCaseInfo = [String]()
    let jsonRoot = readJson(resource: "ethtransactiontest.json")
    for (key, value) in jsonRoot {
      if let jsonObject = value as? [String: Any], let tx = jsonObject["transaction"] as? [String: Any], let preview = jsonObject["preview"] as? [String: Any]{
        let txHash = jsonObject["txHash"] as! String
        let v = tx["v"] as! String
        let gasPrice = tx["gasPrice"] as! UInt64
        let gasLimit = tx["gasLimit"] as! UInt64
        let nonce = tx["nonce"] as! UInt64
        let value = tx["value"] as! UInt64
        
        
        let payment = preview["payment"] as! String
        let receiver = preview["receiver"] as! String
        let sender = preview["sender"] as! String
        let fee = preview["fee"] as! String

        
        
        
        for i in 0...3{
          do {
//            let sign = try Wallet.ethSignTransaction(
//              handle: handle,
//              raw:[        "nonce":        String(nonce),
//                           "gasPrice":     String(gasPrice),
//                           "gasLimit":     String(gasLimit),
//                           "to":           tx["to"] as! String,
//                           "value":        String(value),
//                           "data":         tx["data"] as! String,
//                           "preview":preview
//              ],chainID:Int(v)!,path: BIP44.eth)
            
            var ethInput = Ethapi_EthTxReq()
            ethInput.nonce = String(nonce)
            ethInput.gasPrice = String(gasPrice)
            ethInput.gasLimit = String(gasLimit)
            ethInput.to = tx["to"] as! String
            ethInput.value = String(value)
            ethInput.data = tx["data"] as! String
            ethInput.payment = payment
            ethInput.receiver = receiver
            ethInput.sender = sender
            ethInput.fee = fee
            ethInput.path = BIP44.eth
            ethInput.chainID = v
            let output = API.ethSignTx(ethInput: ethInput)
            
            Log.d("expect txHash:" + txHash)
            Log.d("actual txHash:" + output.txHash)
            
            if output.txHash == txHash{
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
}
