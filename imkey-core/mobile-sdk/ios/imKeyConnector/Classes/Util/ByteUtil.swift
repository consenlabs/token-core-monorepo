//
//  ByteUtil.swift
//  Demo
//
//  Created by joe on 2018/7/4.
//  Copyright © 2018年 joe. All rights reserved.
//

import Foundation

public class ByteUtil{
  public class func hexString2Uint8Array(data:String) -> [UInt8]? {
    if(data.count == 0 || (data.count%2) != 0){
      return nil
    }
    let len = data.count/2
    var temp:String
    var result:[UInt8] = []
    for i in 0..<len{
      let lowerBounds = String.Index(encodedOffset: i*2)
      let upperBounds = String.Index(encodedOffset: (i+1)*2)
      temp = String(data[lowerBounds..<upperBounds])
      let byte:UInt8 = UInt8(temp,radix:16)!
      result.append(byte)
    }
    return result
  }
  
  public class func uint8Array2HexString(data:[UInt8]) -> String{
    var res:String = ""
    for i in 0..<data.count{
      //            res += String(data[i],radix:16)
      res += String(format: "%02X", data[i])
    }
    return res
  }
  
  public class func reserve(hexString:String) ->String{
    let array = hexString2Uint8Array(data: hexString)
    let newArray = [UInt8](array!.reversed())
    return uint8Array2HexString(data: newArray)
  }
  
//  public class func bytes2String(bytes:[UInt8]) -> String?{
//    return String(bytes: bytes, encoding: .utf8)
//  }
//  
//  public class func string2Bytes(str:String) -> [UInt8]{
//    return [UInt8](str.utf8)
//  }
}
