//
//  Utils.swift
//  iOSExample
//
//  Created by xyz on 2019/10/24.
//  Copyright © 2019 consenlabs. All rights reserved.
//

import Foundation

typealias JSONObject = [AnyHashable: Any]

func prettyPrintJSON(_ obj: JSONObject) -> String  {
    // fail fast in demo
    let encoded = try! JSONSerialization.data(withJSONObject: obj, options: .prettyPrinted)
    return String(data: encoded, encoding: .utf8)!
}

func parseJSONObject(_ str: String) -> JSONObject {
  let data = str.data(using: .utf8)!
  return try! JSONSerialization.jsonObject(with: data, options: .allowFragments) as! JSONObject;
}

func dataWithHexString(_ hex: String) -> Data {
    var hex = hex
    var data = Data()
    while(hex.count > 0) {
        let subIndex = hex.index(hex.startIndex, offsetBy: 2)
        let c = String(hex[..<subIndex])
        hex = String(hex[subIndex...])
        var ch: UInt32 = 0
        Scanner(string: c).scanHexInt32(&ch)
        var char = UInt8(ch)
        data.append(&char, count: 1)
    }
    return data
}
