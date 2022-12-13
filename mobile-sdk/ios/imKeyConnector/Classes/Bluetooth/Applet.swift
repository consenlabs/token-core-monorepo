//
//  Applet.swift
//  ImkeyLibrary
//
//  Created by joe on 2018/9/5.
//  Copyright © 2018年 joe. All rights reserved.
//

import Foundation

public class Applet{
  public static let btcAID = "695F627463"
  public static let ethAID = "695F657468"
  public static let eosAID = "695F656F73"
  public static let sioAID = "695F696D6B"
  public static let cosmosAID = "695F636F736D6F73"
  
  public static let btcName = "BTC"
  public static let ethName = "ETH"
  public static let eosName = "EOS"
  public static let sioName = "IMK"
  public static let cosmosName = "COSMOS"
  
  public class func aid2AppletName(aid:String) -> String{
    switch aid {
    case btcAID:
      return btcName
    case ethAID:
      return ethName
    case eosAID:
      return eosName
    case sioAID:
      return sioName
    case cosmosAID:
      return cosmosName
    default:
      return ""
    }
  }
  
  public class func appletName2Aid(appletName:String) -> String{
    switch appletName {
    case btcName:
      return btcAID
    case ethName:
      return ethAID
    case eosName:
      return eosAID
    case sioName:
      return sioAID
    case cosmosName:
      return cosmosAID
    default:
      return ""
    }
  }
}
