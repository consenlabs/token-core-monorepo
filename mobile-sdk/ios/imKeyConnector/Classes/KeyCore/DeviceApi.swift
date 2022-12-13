//
//  DeviceApi.swift
//  imKeyConnector
//
//  Created by joe on 6/3/20.
//

import Foundation
import SwiftProtobuf

public class DeviceAPI{
  public class func checkUpdate()throws -> Deviceapi_CheckUpdateRes{
    var action = Api_ImkeyAction()
    action.method = "check_update"
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let ouput = try! Deviceapi_CheckUpdateRes(serializedData: dataRes)
    return ouput
  }
  
  public class func checkDevice()throws {
    var action = Api_ImkeyAction()
    action.method = "device_secure_check"
    let paramHex = try! action.serializedData().key_toHexString()
    try API.shared().callApi(paramHex:paramHex)
  }
  
  public class func activeDevice()throws {
    var action = Api_ImkeyAction()
    action.method = "device_activate"
    let paramHex = try! action.serializedData().key_toHexString()
    try API.shared().callApi(paramHex:paramHex)
  }
  
  public class func downloadApp(appletName:String)throws{
    var param = Deviceapi_AppDownloadReq()
    param.appName = appletName
    
    var action = Api_ImkeyAction()
    action.method = "app_download"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    try API.shared().callApi(paramHex:paramHex)
  }
  
  public class func updateApp(appletName:String)throws{
    var param = Deviceapi_AppUpdateReq()
    param.appName = appletName
    
    var action = Api_ImkeyAction()
    action.method = "app_update"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    try API.shared().callApi(paramHex:paramHex)
  }
  
  public class func deleteApp(appletName:String)throws{
    var param = Deviceapi_AppDeleteReq()
    param.appName = appletName
    
    var action = Api_ImkeyAction()
    action.method = "app_delete"
    action.param = Google_Protobuf_Any()
    action.param.value = try! param.serializedData()
    
    let paramHex = try! action.serializedData().key_toHexString()
    try API.shared().callApi(paramHex:paramHex)
  }
  
  public class func bindCheck()throws ->String{
    let path = "\(NSHomeDirectory())/Documents/wallets/imkey/keys"
    var walletsDirectory = URL(fileURLWithPath: path)
    print(path)
    do {
      if !FileManager.default.fileExists(atPath: path) {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try walletsDirectory.setResourceValues(resourceValues)
      }
    } catch let err {
      throw err.localizedDescription
    }
    
    var bindCheckParam = Deviceapi_BindCheckReq()
    bindCheckParam.filePath = path
    
    var action = Api_ImkeyAction()
    action.method = "bind_check"
    action.param = Google_Protobuf_Any()
    action.param.value = try! bindCheckParam.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let checkRes = try! Deviceapi_BindCheckRes(serializedData: dataRes)
    return checkRes.bindStatus
  }
  
  public class func displayBindCode()throws {
    var action = Api_ImkeyAction()
    action.method = "bind_display_code"
    let paramHex = try! action.serializedData().key_toHexString()
    try API.shared().callApi(paramHex:paramHex)
  }
  
  public class func bindAcquire(bindCode:String)throws -> String{
    var bindAcquireParam = Deviceapi_BindAcquireReq()
    bindAcquireParam.bindCode = bindCode
    
    var action = Api_ImkeyAction()
    action.method = "bind_acquire"
    action.param = Google_Protobuf_Any()
    action.param.value = try! bindAcquireParam.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let bindRes = try! Deviceapi_BindAcquireRes(serializedData: dataRes)
    return bindRes.bindResult
  }
  
  public class func getSEID()throws -> String{
    var action = Api_ImkeyAction()
    action.method = "get_seid"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetSeidRes(serializedData: dataRes)
    return result.seid
  }
  
  public class func getSN()throws -> String{
    var action = Api_ImkeyAction()
    action.method = "get_sn"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetSnRes(serializedData: dataRes)
    return result.sn
  }
  
  public class func getRamSize()throws -> String{
    var action = Api_ImkeyAction()
    action.method = "get_ram_size"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetRamSizeRes(serializedData: dataRes)
    return result.ramSize
  }
  
  public class func getFirmwareVersion()throws -> String{
    var action = Api_ImkeyAction()
    action.method = "get_firmware_version"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetFirmwareVersionRes(serializedData: dataRes)
    return result.firmwareVersion
  }
  
  public class func getBatteryPower()throws -> String{
    var action = Api_ImkeyAction()
    action.method = "get_battery_power"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetBatteryPowerRes(serializedData: dataRes)
    return result.batteryPower
  }
  
  public class func getLifeTime()throws -> String{
    var action = Api_ImkeyAction()
    action.method = "get_life_time"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetLifeTimeRes(serializedData: dataRes)
    return result.lifeTime
  }
  
  public class func getBleName()throws -> String{
    var action = Api_ImkeyAction()
    action.method = "get_ble_name"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetBleNameRes(serializedData: dataRes)
    return result.bleName
  }
  
  public class func setBleName(bleName:String)throws {
    var req = Deviceapi_SetBleNameReq()
    req.bleName = bleName
    
    var action = Api_ImkeyAction()
    action.method = "set_ble_name"
    action.param = Google_Protobuf_Any()
    action.param.value = try! req.serializedData()
    let paramHex = try! action.serializedData().key_toHexString()
    try API.shared().callApi(paramHex:paramHex)
  }
  
  public class func getBleVersion()throws -> String{
    var action = Api_ImkeyAction()
    action.method = "get_ble_version"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetBleNameRes(serializedData: dataRes)
    return result.bleName
  }
  
  public class func getSdkInfo()throws -> Deviceapi_GetSdkInfoRes{
    var action = Api_ImkeyAction()
    action.method = "get_sdk_info"
    let paramHex = try! action.serializedData().key_toHexString()
    let dataRes = try API.shared().callApi(paramHex:paramHex).key_dataFromHexString()!
    let result = try! Deviceapi_GetSdkInfoRes(serializedData: dataRes)
    return result
  }
}
