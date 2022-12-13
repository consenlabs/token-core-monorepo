//
//  Ble.swift
//  ImkeyLibrary
//
//  Created by joe on 2018/8/25.
//  Copyright © 2018年 joe. All rights reserved.
//

import Foundation

public class BLE:NSObject,FTBLEDelegate{
  public static let sendAPDUTimeout:UInt32 = 20 * 1000
//  public static let sendSignPreAPDUTimeout:UInt32 = 120 * 1000
  
  public func fTdidTheDeviceDisconnected(_ uuid: String!, error Error: Int) {
    LogBle.d("fTdidTheDeviceDisconnected...")
    _bleDelegate?.deviceDidDisconnect(address:uuid, errorCode: Error)
  }
  
  public func ftDidFindBLEDevice(_ deviceName: String!, uuid: String!) {
    _bleDelegate?.deviceDidFind(deviceName: deviceName, address: uuid)
  }
  
  public func fTdidTheDeviceConnected(_ uuid: String!, handler: Int, errorCode Error: Int) {
    LogBle.d("fTdidTheDeviceConnected...")
    _bleDelegate?.deviceDidConnect(address:uuid, errorCode: Error)
  }
  private override init(){
    LogBle.d("init...")
  }
  static let _shareManager = BLE()
  var _bleDelegate: BLEDelegate?
  
  public class func shared() -> BLE {
    return _shareManager
  }
  
  public func initialize() -> Int{
    LogBle.d("initialize...")
    return BLEKeyInterface.sharedInstance().initialize()
  }
  
  public func finalize() -> Int{
    LogBle.d("fialize...")
    return BLEKeyInterface.sharedInstance().finalize()
  }
  
  public func startScan() -> Int{
    return BLEKeyInterface.sharedInstance().startScan()
  }
  
  public func stopScan() -> Int{
    return BLEKeyInterface.sharedInstance().stopScan()
  }
  
  var handle:UInt = 0
  public func connect(address:String,timeout:UInt)throws -> Int{
    let result =  BLEKeyInterface.sharedInstance().connect(address, handle: &handle, timeout: timeout)
    LogBle.d("result：\(result)")
    
    if result == 0 {
      LogBle.d("send keep connect apdu...")
      do {
        let apduResponse = try sendApdu(apdu: BleApdu.battery(),timeout: 3 * 1000)
        try BleApdu.checkResponse(res: apduResponse)
        LogBle.d("keep connect sucess...")
      } catch let e as ImkeyBleError {
        LogBle.d("original error:\(e.message)")
        throw BleSDKError.connectFail
      }
    }
    return result
  }
  
  public func disConnect() -> Int{
    LogBle.d("disconnect handle:\(handle)")
    return BLEKeyInterface.sharedInstance().disconnect(handle)
  }
  
  public func sendApdu(apdu:String,timeout:UInt32 = sendAPDUTimeout)throws ->String{
    LogBle.d("\nble >>>> \(apdu)")
    let apduData = BleByteUtil.hex2Bytes(data: apdu)
    let apduLen = apdu.count/2
    var rcvData:[UInt8] = [UInt8](repeating: 0, count: 260)
    var len:UInt32 = 260 // apdu max length is 256
    let resCode = BLEKeyInterface.sharedInstance().sendData(handle, data: apduData, length: UInt32(apduLen), rcvData: &rcvData, rcvDataLen: &len, timeout: timeout)
    if(resCode != 0){
//      throw BLEError.fromCode(code: Int64(resCode))
      throw BleDeviceError(rawValue: Int64(resCode))!
    }
    
    let resApdu = BleByteUtil.bytes2Hex(data: rcvData)
    let bound = resApdu.index(resApdu.startIndex,offsetBy: String.IndexDistance(len*2))
    let trimApdu = String(resApdu[..<bound])
    LogBle.d("ble <<<< \(trimApdu)")
    if trimApdu == "F000"{
      throw BleApduError.walletNotCreated
    }
    if trimApdu == "F080"{
      throw BleApduError.inMenuPage
    }
    if trimApdu == "F081"{
      throw BleApduError.pinNotVerified
    }
    if trimApdu == "6F01"{
      throw BleApduError.bluetoothChannelError
    }
    if trimApdu == "6D00"{
      throw BleApduError.appletFunctionNotSupported
    }
    return trimApdu
  }
  
  public func setDelegate(bleDelegate:BLEDelegate){
    BLEKeyInterface.sharedInstance().setDelegate(self)
    _bleDelegate = bleDelegate
  }
  
  public func removeDelegate(){
    _bleDelegate = nil
    BLEKeyInterface.sharedInstance().removeDelegate()
  }
}
