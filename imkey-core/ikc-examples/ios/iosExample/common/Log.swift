//
//  File.swift
//  imKeyConnector
//
//  Created by joe on 1/24/19.
//

import Foundation
public class Log{
  public class func d(_ items:Any){
    #if DEBUG
    print(items)
    #endif
  }
}
