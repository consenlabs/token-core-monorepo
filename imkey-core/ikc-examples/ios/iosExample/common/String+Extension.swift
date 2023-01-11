//
//  String+Extension.swift
//  token
//
//  Created by James Chen on 2016/10/05.
//  Copyright © 2016 imToken PTE. LTD. All rights reserved.
//

import Foundation

public typealias JSONObject = [String: Any]


public extension String {
  var key_isDigits: Bool {
    let regex = "^[0-9]+$"
    let predicate = NSPredicate(format: "SELF MATCHES %@", regex)
    return predicate.evaluate(with: self)
  }
  
  func key_substring(from: Int) -> String {
    return String(dropFirst(from))
  }
  
  func key_substring(to: Int) -> String {
    return String(dropLast(count - to))
  }
  
  func key_lpad(width: Int, with: String) -> String {
    let len = lengthOfBytes(using: .utf8)
    
    if len >= width {
      return self
    } else {
      return "".padding(toLength: (width - len), withPad: with, startingAt: 0) + self
    }
  }
  
  func ik_add0xIfNeeded() -> String {
    return Hex.addPrefix(self)
  }
  
  func ik_removePrefix0xIfNeeded() -> String {
    return Hex.removePrefix(self)
  }
  
  func ik_fromBase64() -> String? {
    guard let data = Data(base64Encoded: self, options: Data.Base64DecodingOptions(rawValue: 0)) else {
      return nil
    }
    
    return String(data: data as Data, encoding: String.Encoding.utf8)
  }
  
  func ik_toBase64() -> String? {
    guard let data = self.data(using: String.Encoding.utf8) else {
      return nil
    }
    
    return data.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0))
  }

}
