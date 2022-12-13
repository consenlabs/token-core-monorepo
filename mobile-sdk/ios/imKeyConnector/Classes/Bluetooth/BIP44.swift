//
//  BIP44.swift
//  token
//
//  Created by Kai Chen on 17/11/2017.
//  Copyright © 2017 ConsenLabs. All rights reserved.
//

import Foundation

public struct BIP44 {
  public static let eth = "m/44'/60'/0'/0/0"
  public static let ipfs = "m/44'/99'/0'"
  public static let btcMainnet = "m/44'/0'/0'"
  public static let btcTestnet = "m/44'/1'/0'"
  public static let btcSegwitMainnet = "m/49'/0'/0'"
  public static let btcSegwitTestnet = "m/49'/1'/0'"
  public static let eos = "m/44'/194'"
  public static let EOS_LEDGER = "m/44'/194'/0'/0/0"
  public static let cosmos = "m/44'/118'/0'/0/0"
  
  public static func checkPath(path:String)throws{
    let depth = path.split(separator: "/").count - 1
    if (depth<2 || depth>10){
      throw SDKError.pathIllegal
    }
    
    if path.count > 100{
      throw SDKError.pathIllegal
    }
    
    let pattern = "^m/[0-9'/]+$";
    let regex = try NSRegularExpression(pattern: pattern)
    let matchNumber = regex.numberOfMatches(in: path, range: NSMakeRange(0, path.utf8.count))
    if matchNumber != 1 {
      throw SDKError.pathIllegal
    }
  }
}
