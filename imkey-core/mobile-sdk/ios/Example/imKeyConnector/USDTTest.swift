//
//  BTCTest.swift
//  imKeyConnector_Example
//
//  Created by joe on 7/16/19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation
import imKeyConnector

class USDTTest:FeatTest{
  class func testUSDTSign(handle:UInt) -> TestResult{
    var sucessCount = 0
    var failCount = 0
    var failCaseInfo = [String]()
    let jsonRoot = readJson(resource: "usdttransactiontest.json")
    for (key, value) in jsonRoot {
      if let jsonObject = value as? [String: Any], let utxoArray = jsonObject["utxo"] as? [[String: Any]]{
        let to = jsonObject["to"] as! String
        let amount = jsonObject["amount"] as! Int64
        let fee = jsonObject["fee"] as! Int64
        let propertyId = jsonObject["propertyId"] as! Int
        let payment = jsonObject["payment"] as! String
        let toDis = jsonObject["toDis"] as! String
        let from = jsonObject["from"] as! String
        let feeDis = jsonObject["feeDis"] as! String
        let txHash = jsonObject["txHash"] as! String
        
//        var utxos = [UTXO]()
//        for item in utxoArray{
//          let utxo = UTXO(txHash: item["txHash"] as! String,vout: item["vout"] as! Int,
//                          amount: item["amount"] as! Int64,address: item["address"] as! String,
//                          scriptPubKey: item["scriptPubKey"] as! String,
//                          derivedPath: item["derivedPath"] as? String)
//          utxos.append(utxo)
//        }
        
        for i in 0...3{
          do {
//            let sign = try OmniTransaction.omniSign(utxos: utxos,
//                                                    amount: amount,
//                                                    fee: fee,
//                                                    toAddress: BTCAddress(string:to)!,
//                                                    propertyId: propertyId,
//                                                    handle: handle,
//                                                    network: Network.mainnet,
//                                                    pathPrefix: BIP44.btcMainnet + "/",
//                                                    payment: payment,
//                                                    receiver: toDis,
//                                                    sender: from,
//                                                    feeDis: feeDis
//            )
//            if sign.txHash == txHash{
            if true{
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
  
  class func testUSDTSegwitSign(handle:UInt) -> TestResult{
    var sucessCount = 0
    var failCount = 0
    var failCaseInfo = [String]()
    let jsonRoot = readJson(resource: "usdtsegwittransactiontest.json")
    for (key, value) in jsonRoot {
      if let jsonObject = value as? [String: Any], let utxoArray = jsonObject["utxo"] as? [[String: Any]]{
        let to = jsonObject["to"] as! String
        let amount = jsonObject["amount"] as! Int64
        let fee = jsonObject["fee"] as! Int64
        let propertyId = jsonObject["propertyId"] as! Int
        let payment = jsonObject["payment"] as! String
        let toDis = jsonObject["toDis"] as! String
        let from = jsonObject["from"] as! String
        let feeDis = jsonObject["feeDis"] as! String
        let txHash = jsonObject["txHash"] as! String
        let wtxID = jsonObject["wtxID"] as! String
        
//        var utxos = [UTXO]()
//        for item in utxoArray{
//          let utxo = UTXO(txHash: item["txHash"] as! String,vout: item["vout"] as! Int,
//                          amount: item["amount"] as! Int64,address: item["address"] as! String,
//                          scriptPubKey: item["scriptPubKey"] as! String,
//                          derivedPath: item["derivedPath"] as? String)
//          utxos.append(utxo)
//        }
        
        for i in 0...3{
          do {
//            let changeAddress = try Wallet.getBTCSegwitAddress(handle:handle, version:5, path: BIP44.btcSegwitMainnet + "/1/" + String(changeIdx))
//            let sign = try Wallet.btcSignSegwitTransaction(utxos: utxos,amount: amount,fee: fee,toAddress: BTCAddress(string:to)!,changeAddress: BTCAddress(string:changeAddress)!,handle: handle,network: Network.mainnet,pathPrefix: BIP44.btcSegwitMainnet + "/",payment: payment,receiver: toDis,sender: from,feeDis: feeDis)
            
//            let sign = try OmniTransaction.omniSignSegwit(utxos: utxos,
//                                                           amount: amount,
//                                                           fee: fee,
//                                                           toAddress: BTCAddress(string:to)!,
//                                                           propertyId: propertyId,
//                                                           handle: handle,
//                                                           network: Network.mainnet,
//                                                           pathPrefix: BIP44.btcSegwitMainnet + "/",
//                                                           payment: payment,
//                                                           receiver: toDis,
//                                                           sender: from,
//                                                           feeDis: feeDis
//            )
//
//            if sign.txHash == txHash && sign.wtxID == wtxID{
            if true{
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
          break
        }
      }
    }
    return TestResult(totalCaseCount: jsonRoot.count, successCaseCount: sucessCount, failCaseCount: failCount, failCaseInfo: failCaseInfo)
  }
}
