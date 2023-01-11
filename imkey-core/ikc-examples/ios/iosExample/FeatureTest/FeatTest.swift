//
//  FeatTest.swift
//  imKeyConnector_Example
//
//  Created by joe on 7/16/19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation

struct TestResult:CustomStringConvertible {
  let totalCaseCount:Int
  let successCaseCount:Int
  let failCaseCount:Int
  let failCaseInfo:[String]
  
  var description: String {
        return "totalCaseCount:\(totalCaseCount)\nsuccessCaseCount:\(successCaseCount)\nfailCaseCount:\(failCaseCount)\nfailCaseInfo:\(failCaseInfo)"
  }
}

class FeatTest{
  class func readJson(resource:String) -> [String: Any]{
    guard let fileURL = Bundle.main.url(forResource: resource, withExtension: nil),
      let data = try? Data.init(contentsOf: fileURL) else{
        fatalError("`JSON File Fetch Failed`")
    }
    let jsonRoot = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    return jsonRoot
  }
}
