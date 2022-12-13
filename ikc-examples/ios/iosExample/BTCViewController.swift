//
//  BTCViewController.swift
//  imKeyConnector_Example
//
//  Created by joe on 7/11/19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import UIKit
import imKeyBleLib

class BTCViewController: UIViewController {
  
  var handle:UInt = 0
  override func viewDidLoad() {
    super.viewDidLoad()
  }
  @IBOutlet weak var txtResult: UITextView!
  
  
  @IBAction func backClick(_ sender: Any) {
    self.dismiss(animated: true, completion: nil)
  }
  
  @IBAction func btcAddrBtnClick(_ sender: Any) {
//    do {
//      txtResult.text = ""
//      let address = try Wallet.getBTCAddress(handle:handle, version:0, path: BIP44.btcMainnet)
//      Log.d(address!)
//      txtResult.text = address
//    } catch let e as ImkeyError {
//      Log.d("!!!error:\(e.message)")
//      toastMsg(message: e.message)
//    }catch{
//      Log.d(error)
//    }
  }
  
  @IBAction func btcSegwitAddrClick(_ sender: Any) {
//    do {
//      txtResult.text = ""
//      let segwitPath = "m/49'/1'/0'/"
//      let segwitAddr = try Wallet.getBTCSegwitAddress(handle:handle, version:196 , path: segwitPath)
//      Log.d(segwitAddr!)
//      txtResult.text = segwitAddr
//    } catch let e as ImkeyError {
//      Log.d("!!!error:\(e.message)")
//      toastMsg(message: e.message)
//    }catch{
//      Log.d(error)
//    }
  }
  
  @IBAction func btcRegAddr(_ sender: Any) {
//    do {
//      let path = BIP44.btcMainnet + "/" + "0/0"
//      let address = try Wallet.displayBTCddress(handle:handle, version:0, path: path)
//      txtResult.text = "btc main address： \n \(address)"
//      Log.d(address)
//    } catch let e as ImkeyError {
//      Log.d("!!!error:\(e.message)")
//      toastMsg(message: e.message)
//    }catch{
//      Log.d(error)
//    }
  }
  
  
  @IBAction func btcRegSegwitAddr(_ sender: Any) {
//    do {
//      let path = BIP44.btcSegwitMainnet + "/" + "0/0"
//      let address = try Wallet.displayBTCSegwitAddress(handle:handle, version:5, path: path)
//      txtResult.text = "btc main segwit address： \n \(address)"
//      Log.d(address)
//    } catch let e as ImkeyError {
//      Log.d("!!!error:\(e.message)")
//      toastMsg(message: e.message)
//    }catch{
//      Log.d(error)
//    }
  }
  
  
  @IBAction func btcSignBtnClick(_ sender: Any) {
    txtResult.text = ""
//    let pathPrefix = BIP44.btcTestnet + "/"
//    let utxos = [
//      [
//        "txHash": "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a",
//        "vout": 0,
//        "amount": "200000000",
//        "address": "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC",
//        "scriptPubKey": "76a914118c3123196e030a8a607c22bafc1577af61497d88ac",
//        "derivedPath": "0/22"
//      ],
//      [
//        "txHash": "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531",
//        "vout": 1,
//        "amount": "200000000",
//        "address": "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
//        "scriptPubKey": "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
//        "derivedPath": "0/0"
//      ],
//      [
//        "txHash": "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9",
//        "vout": 0,
//        "amount": "200000000",
//        "address": "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
//        "scriptPubKey": "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
//        "derivedPath": "0/0"
//      ],
//      [
//        "txHash": "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9",
//        "vout": 1,
//        "amount": "200000000",
//        "address": "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
//        "scriptPubKey": "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
//        "derivedPath": "0/0"
//      ]
//      ].map { UTXO(raw: $0)! }
//    let extra: [String: Any] = ["opReturn": "0x0200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa99385"]
//
//    let sign = try! Wallet.btcSignTransaction(utxos: utxos,
//                                              amount: Int64(799988000),
//                                              fee: Int64(10000),
//                                              toAddress: BTCAddress(string:"moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3")!,
//                                              changeAddress: BTCAddress(string:"mhDEjaa2hWDZ6yptx83DuwtLGrUBJF2kQW")!,
//                                              extra:extra,
//      handle: handle,
//      network: Network.testnet,
//      pathPrefix: pathPrefix,
//      payment: "0.0001 BT",
//      receiver: "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt",
//      sender: "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy",
//      feeDis: "0.00007945 BTC"
//    )
//    appendResult(msg: "btc sign transaction： \n \(sign)")
//    Log.d(sign)
    API.btcSignTX()
  }
  
  @IBAction func btcSegwitSignBtnClick(_ sender: Any) {
//    txtResult.text = ""
//    let pathPrefix = BIP44.btcSegwitTestnet + "/"
//
//    let changeAddress = try! Wallet.getBTCSegwitAddress(handle:handle, version:196, path: pathPrefix + "1/1")
//    let utxos = [
//      [
//        "txHash": "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f",
//        "vout": 0,
//        "amount": "50000",
//        "address": "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB",
//        "scriptPubKey": "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987",
//        "derivedPath": "0/0"
//      ],
//      [
//        "txHash": "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74",
//        "vout": 0,
//        "amount": "50000",
//        "address": "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf",
//        "scriptPubKey": "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787",
//        "derivedPath": "0/1"
//      ]
//      ].map { UTXO(raw: $0)! }
//    let extra: [String: Any] = ["opReturn": "0x1234"]
//
//    let sign = try! Wallet.btcSignSegwitTransaction(utxos: utxos,
//                                                    amount: Int64(88000),
//                                                    fee: Int64(10000),
//                                                    toAddress: BTCAddress(string:"2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp")!,
//                                                    changeAddress: BTCAddress(string:"2N3wqj1hfobkc7tNazut4dZH8KgWbVH4sJc")!,
//                                                    extra: extra,
//                                                    handle: handle,
//                                                    network: Network.testnet,
//                                                    pathPrefix: pathPrefix,
//                                                    payment: "0.0001 BT",
//                                                    receiver: "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt",
//                                                    sender: "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy",
//                                                    feeDis: "0.00007945 BT"
//    )
//    appendResult(msg: "btc sign segwit transaction： \n \(sign)")
//    Log.d(sign)
  }
  
  @IBAction func usdtSignClick(_ sender: Any) {
//    txtResult.text = ""
//    let pathPrefix = "m/44'/1'/0'/"
//    let utxos = [
//      [
//        "txHash": "0dd195c815c5086c5995f43a0c67d28344ae5fa130739a5e03ef40fea54f2031",
//        "vout": 0,
//        "amount": "14824854",
//        "address": "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
//        "scriptPubKey": "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
//        "derivedPath": "0/0"
//      ]
//      ].map { UTXO(raw: $0)! }
//
//    let sign = try! OmniTransaction.omniSign(utxos: utxos,
//                                             amount: Int64(10000000000),
//                                             fee: Int64(4000),
//                                             toAddress: BTCAddress(string:"moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3")!,
//                                             propertyId: 31,
//                                             handle: handle,
//                                             network: Network.testnet,
//                                             pathPrefix: pathPrefix,
//                                             payment: "100 USDT",
//                                             receiver: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3",
//                                             sender: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB",
//                                             feeDis: "0.0004 BTC"
//    )
//    appendResult(msg: "usdt sign transaction： \n \(sign)")
//    Log.d(sign)
  }
  
  @IBAction func usdtSegwitSignClick(_ sender: Any) {
//    txtResult.text = ""
//    let pathPrefix = "m/49'/1'/0'/"
//    let utxos = [
//      [
//        "txHash": "9baf6fd0e560f9f199f4879c23cb73b9c4affb54a1cfdbacb85687efa89f4c78",
//        "vout": 1,
//        "amount": "21863396",
//        "address": "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB",
//        "scriptPubKey": "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987",
//        "derivedPath": "0/0"
//      ]
//      ].map { UTXO(raw: $0)! }
//    
//    let sign = try! OmniTransaction.omniSignSegwit(utxos: utxos,
//                                                   amount: Int64(10000000000),
//                                                   fee: Int64(4000),
//                                                   toAddress: BTCAddress(string:"moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3")!,
//                                                   propertyId: 31,
//                                                   handle: handle,
//                                                   network: Network.testnet,
//                                                   pathPrefix: pathPrefix,
//                                                   payment: "100 USDT",
//                                                   receiver: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3",
//                                                   sender: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB",
//                                                   feeDis: "0.0004 BTC"
//    )
//    appendResult(msg: "usdt segwit sign transaction： \n \(sign)")
//    Log.d(sign)
  }
  
  @IBAction func btcAutoSignTestClick(_ sender: Any) {
    txtResult.text = ""
    DispatchQueue.global().async {
      let result = BTCTest.testBitcoinSign(handle: self.handle)
      Log.d(result)
      self.appendResult(msg: result.description)
    }
  }
  
  @IBAction func btcAutoSegwitSignClick(_ sender: Any) {
    txtResult.text = ""
    DispatchQueue.global().async {
      let result = BTCTest.testBitcoinSegwitSign(handle: self.handle)
      Log.d(result)
      self.appendResult(msg: result.description)
    }
  }
  
  @IBAction func usdtAutoSignBtnClick(_ sender: Any) {
    txtResult.text = ""
    DispatchQueue.global().async {
      let result = USDTTest.testUSDTSign(handle: self.handle)
      Log.d(result)
      self.appendResult(msg: result.description)
    }
  }
  
  @IBAction func usdtSegwitAutoSignBtnClick(_ sender: Any) {
    txtResult.text = ""
    DispatchQueue.global().async {
      let result = USDTTest.testUSDTSegwitSign(handle: self.handle)
      Log.d(result)
      self.appendResult(msg: result.description)
    }
  }
  
  
  @IBAction func btcOPReturnBtnClick(_ sender: Any) {
    txtResult.text = ""
    DispatchQueue.global().async {
      let result = BTCTest.testBitcoinSignOPReturn(handle: self.handle)
      Log.d(result)
      self.appendResult(msg: result.description)
    }
  }
  
  
  @IBAction func segwitOPReturnBtnClick(_ sender: Any) {
    txtResult.text = ""
    DispatchQueue.global().async {
      let result = BTCTest.testBitcoinSegwitSignOPReturn(handle: self.handle)
      Log.d(result)
      self.appendResult(msg: result.description)
    }
  }
  
  func appendResult(msg:String){
    DispatchQueue.main.async {
      self.txtResult.text += msg
      let bottom = NSMakeRange(self.txtResult.text.count - 1, 1)
      self.txtResult.scrollRangeToVisible(bottom)
    }
  }
}


