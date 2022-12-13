//
//  EOSTest.swift
//  imKeyConnector_Example
//
//  Created by joe on 7/17/19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation
import imKeyBleLib

class EOSTest: FeatTest {
  class func testEOSign(handle:UInt) -> TestResult{
//    var sucessCount = 0
//    var failCount = 0
//    var failCaseInfo = [String]()
//    let jsonRoot = readJson(resource: "eostransactiontest.json")
//    for (key, value) in jsonRoot {
//      if let jsonObject = value as? [String: Any], let preview = jsonObject["preview"] as? [String: Any],
//        let publicKeys = jsonObject["publicKeys"] as? [[String: Any]]{
//        let txHash = jsonObject["txHash"] as! String
//        let txHex = jsonObject["txHex"] as! String
//        let chainId = jsonObject["chainId"] as! String
//
//        var pks = [String]()
//        for item in publicKeys{
//          pks.append(item["publicKey"] as! String)
//        }
//
//        let txs = [
//          EOSTransaction(
//            data: txHex,
//            publicKeys: pks,
//            chainID: chainId,
//            to: preview["receiver"] as! String,
//            from: preview["sender"] as! String,
//            payment: preview["payment"] as? String
//          )
//        ]
//
//        for i in 0...3{
//          do {
//            let sign = try EOSTransactionSigner(txs: txs, handle: handle,path:BIP44.EOS_LEDGER).sign()
//
//            if sign[0].hash == txHash{
//              sucessCount += 1
//              break
//            }else{
//              failCount += 1
//              failCaseInfo.append("\(key)  \(i) time: Assert fail")
//            }
//          } catch let e as ImkeyError {
//            failCount += 1
//            failCaseInfo.append("\(key)  \(i) time: \(e.message)")
//          }catch{
//            failCount += 1
//            failCaseInfo.append("\(key)  \(i) time: \(error)")
//          }
//        }
//      }
//    }
//    return TestResult(totalCaseCount: jsonRoot.count, successCaseCount: sucessCount, failCaseCount: failCount, failCaseInfo: failCaseInfo)
    
            return TestResult(totalCaseCount: 0, successCaseCount: 0, failCaseCount: 0, failCaseInfo: ["failCaseInfo"])
  }
}
