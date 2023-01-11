//
//  BleProtocol.swift
//  ImkeyLibrary
//
//  Created by joe on 2018/8/27.
//  Copyright © 2018年 joe. All rights reserved.
//

import Foundation

public protocol BLEDelegate {
  func deviceDidFind(deviceName: String!, address: String!)
  func deviceDidConnect(address: String!, errorCode: Int)
  func deviceDidDisconnect(address: String!, errorCode: Int)
}
