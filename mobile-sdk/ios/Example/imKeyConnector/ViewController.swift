//
//  ViewController.swift
//  imKeyConnector
//
//  Created by Neal Xu on 09/17/2018.
//  Copyright (c) 2018 Neal Xu. All rights reserved.
//

import UIKit
import imKeyConnector
import imKeyBleLib


class ViewController: UIViewController,BLEDelegate {
  var handle:UInt = 0
  
  // bind ble devices 
  struct Device {
    var name:String = ""
    var address:String = ""
  }
  
  var devices:[Device] = [Device]()
  var currentDevice:Device? = nil
  
  // bluetooth delegate method
  func deviceDidFind(deviceName: String!, address: String!) {
    Log.d("deviceName:\(deviceName) address:\(address)")
    var device = Device.init()
    device.name = deviceName
    device.address = address
    let isContain = devices.contains(where: { (value) -> Bool in
      return value.address == device.address
    })
    if !isContain {
      devices.append(device)
    }
    DispatchQueue.main.sync() {
      tbDevices.reloadData()
    }
  }
  
  func deviceDidConnect(address: String!, errorCode: Int) {
    Log.d("deviceDidConnect.. \(String(describing: address)) \(errorCode)")
  }
  
  func deviceDidDisconnect(address: String!, errorCode: Int) {
    Log.d("deviceDidDisconnect.. \(String(describing: address)) \(errorCode)")
  }
  
  
  @IBOutlet weak var btnScan: UIButton!
  @IBOutlet weak var tbDevices: UITableView!
  @IBOutlet weak var btnDisconnect: UIButton!
  @IBOutlet weak var tvDeviceInfo: UITextView!
  @IBOutlet weak var indictorDeviceInfo: UIActivityIndicatorView!
  
  
  override func viewDidLoad() {
    super.viewDidLoad()
    // Do any additional setup after loading the view, typically from a nib.
    let initRes = BLE.shared().initialize()
    Log.d("initRes \(initRes)")
    BLE.shared().setDelegate(bleDelegate: self)
    tbDevices.dataSource = self
    tbDevices.delegate = self
    
    self.hideKeyboardWhenTappedAround()
    
    //hello rust
    //    Log.test_ffi()
    //    API.setCallback()
    //    API.startMessageDeamon()
  }
  
  override func didReceiveMemoryWarning() {
    super.didReceiveMemoryWarning()
    // Dispose of any resources that can be recreated.
  }
  
  
  @IBAction func scan(_ sender: Any) {
    let res:Int = BLE.shared().startScan()
    if res != 0 {
      toastMsg(message: "搜索设备失败 \(res)")
    }
    
    //        HTTPS().test()
  }
  
  @IBAction func stopScan(_ sender: Any) {
    let res = BLE.shared().stopScan()
    if res != 0 {
      toastMsg(message: "停止失败 \(res)")
    }
    devices.removeAll()
    tbDevices.reloadData()
  }
  
  @IBAction func disconnect(_ sender: Any) {
    let res = BLE.shared().disConnect()
    if(res != 0){
      let err = DeviceError(rawValue: Int64(res))!
      toastMsg(message: "断开连接失败\(err.message)")
    }
  }
  
  @IBAction func DeviceInfo(_ sender: Any) {
    showDeviceInfo(name: currentDevice!.name,mac: currentDevice!.address)
  }
  
  
  func showDeviceInfo(name:String,mac:String){
    tvDeviceInfo.text = ""
    tvDeviceInfo.text += "蓝牙名称：" + name
    tvDeviceInfo.text += "\n蓝牙地址：" + mac
    indictorDeviceInfo.startAnimating()
    
    DispatchQueue.global().async {//并行、异步
      do {
        let bleVersion = try DeviceAPI.getBleVersion()
        let seid = try DeviceAPI.getSEID()
        let ramSize = try DeviceAPI.getRamSize()
        let battery = try DeviceAPI.getBatteryPower()
        let lifeTime = try DeviceAPI.getLifeTime()
        
        DispatchQueue.main.async {//串行、异步
          self.indictorDeviceInfo.stopAnimating()
          self.tvDeviceInfo.text += "\n蓝牙版本：" + bleVersion
          self.tvDeviceInfo.text += "\nseid：" + seid
          self.tvDeviceInfo.text += "\n剩余空间：" + ramSize
          self.tvDeviceInfo.text += "\n剩余电量：" + battery
          self.tvDeviceInfo.text += "\n生命周期：" + lifeTime
          Log.d(self.tvDeviceInfo.text)
        }
      }catch let e as ImkeyError {
        Log.d("!!!error:\(e.message)")
        self.toastMsg(message: e.message)
      }catch{
        Log.d(error)
      }
    }
    
    
  }
  
  let userDefaults = UserDefaults.standard
  @IBAction func bindCheck(_ sender: Any) {
    DispatchQueue.global().async {
      do {
        var bindCode = self.userDefaults.string(forKey: self.currentDevice!.address)
        if bindCode != nil{
          Log.d("bindcode...............\(bindCode!)")
        }
        
        let status = try DeviceAPI.bindCheck()
        if status == "unbound"{
          try DeviceAPI.displayBindCode()
          self.bindDevice(status: "未绑定过的设备，请输入绑定码", deviceMac: self.currentDevice!.address)
        }else if status == "bound_other"{
          bindCode = "YDSGQPKX"//imKey-gpqv
          if bindCode != nil{
            self.toastMsg(message: "已绑定其他设备,重新绑定..")
            let bindResult = try DeviceAPI.bindAcquire(bindCode: bindCode!)
            if bindResult == "success"{
              self.toastMsg(message: "绑定成功")
            }else{
              self.bindDevice(status: "绑定码错误，请重新输入绑定码", deviceMac: self.currentDevice!.address)
            }
          }else{
            self.bindDevice(status: "未绑定过的设备，请先绑定", deviceMac: self.currentDevice!.address)
          }
        }else{
          self.toastMsg(message: "已绑定")
        }
        
        Log.d(status)
        self.toastMsg(message: status)
      }catch let e as ImkeyError {
        Log.d("!!!error:\(e.message)")
        self.toastMsg(message: e.message)
      }catch{
        Log.d(error)
      }
    }
  }
  
  func bindDevice(status:String,deviceMac:String){
    DispatchQueue.main.async {
      let alertController = UIAlertController(title: "绑定",
                                              message: status, preferredStyle: .alert)
      alertController.addTextField {
        (textField: UITextField!) -> Void in
        textField.placeholder = "bind code"
      }
      let okAction = UIAlertAction(title: "OK", style: .default, handler: {
        action in
        let textFields = alertController.textFields!.first!
        print("bindCode：\(textFields.text)")
        //        let bindResult = try! KeyManager.shared().bindAcquire(handle: self.handle, authCode: textFields.text!)
        //        self.toastMsg(message: bindResult)
        //        if bindResult == KeyManager.result_success{
        //          self.userDefaults.set(textFields.text, forKey: self.currentDevice!.address)
        //        }
      })
      let cancelAction = UIAlertAction(title: "cancel", style: .cancel, handler: nil)
      alertController.addAction(cancelAction)
      alertController.addAction(okAction)
      self.present(alertController, animated: true, completion: nil)
    }
  }
  
  
  @IBAction func deviceManageClick(_ sender: Any) {
    let storyboard = UIStoryboard(name: "Main", bundle: nil)
    guard let deviceManageVC = storyboard.instantiateViewController(withIdentifier: "DeviceManageViewController") as? DeviceManageViewController else {  return }
    deviceManageVC.handle=handle
    self.present(deviceManageVC, animated: true, completion: nil)
  }
  
  @IBAction func btcClick(_ sender: Any) {
    let storyboard = UIStoryboard(name: "Main", bundle: nil)
    guard let btcVC = storyboard.instantiateViewController(withIdentifier: "BTCViewController") as? BTCViewController else {  return }
    btcVC.handle=handle
    self.present(btcVC, animated: true, completion: nil)
  }
  
  @IBAction func ethClick(_ sender: Any) {
    let storyboard = UIStoryboard(name: "Main", bundle: nil)
    guard let ethVC = storyboard.instantiateViewController(withIdentifier: "ETHViewController") as? ETHViewController else {  return }
    ethVC.handle=handle
    self.present(ethVC, animated: true, completion: nil)
  }
  
  @IBAction func eosClick(_ sender: Any) {
    let storyboard = UIStoryboard(name: "Main", bundle: nil)
    guard let ethVC = storyboard.instantiateViewController(withIdentifier: "EOSViewController") as? EOSViewController else {  return }
    ethVC.handle=handle
    self.present(ethVC, animated: true, completion: nil)
  }
  
  @IBAction func imkClick(_ sender: Any) {
    //    Log.test_ffi()
    //    Log.checkUpdate()
    let seid = API.getSEID()
    Log.d("seid: \(seid)")
  }
  
  @IBAction func cosmosClick(_ sender: Any) {
    let storyboard = UIStoryboard(name: "Main", bundle: nil)
    guard let cosmosVC = storyboard.instantiateViewController(withIdentifier: "CosmosViewController") as? CosmosViewController else {  return }
    cosmosVC.handle=handle
    self.present(cosmosVC, animated: true, completion: nil)
  }
  
}


extension UIViewController{
  func toastMsg(message:String){
    toast(title: "提示", message: message)
  }
  
  func toast(title:String,message:String){
    let alertToast = UIAlertController(title: title, message: message, preferredStyle: .alert)
    DispatchQueue.main.async {
      self.present(alertToast, animated: true, completion: nil)
    }
    
    //一秒钟后自动消失
    
    DispatchQueue.main.asyncAfter(deadline: DispatchTime.now() + 1.5) {
      
      alertToast.dismiss(animated: false, completion: nil)
    }
  }
}

extension ViewController:UITableViewDataSource,UITableViewDelegate{
  func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
    return devices.count
  }
  
  func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
    let cell = tbDevices.dequeueReusableCell(withIdentifier: "NormalCell", for: indexPath)
    cell.textLabel?.text = devices[indexPath.row].name
    return cell
  }
  
  func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
    Log.d("select \(indexPath)")
    let device = devices[indexPath.row]
    BLE.shared().stopScan()
    do {
      //      handle = 0
      let result = try BLE.shared().connect(address: device.address,timeout: 12*1000)
      let err = DeviceError(rawValue: Int64(result))!
      Log.d("connect result:\(err.message)   handle:\(handle)")
      if(result == 0){
        currentDevice = device
        tvDeviceInfo.text = ""
        tvDeviceInfo.text += "蓝牙名称：" + device.name
        tvDeviceInfo.text += "\n蓝牙地址：" + device.address
      }else{
        toastMsg(message: "connect fail \(err.message)")
      }
    }catch let e as ImkeyError {
      Log.d("!!!error:\(e.message)")
      toastMsg(message: e.message)
    }catch{
      Log.d(error)
    }
  }
}

// Put this piece of code anywhere you like
extension UIViewController {
  func hideKeyboardWhenTappedAround() {
    let tap: UITapGestureRecognizer = UITapGestureRecognizer(target: self, action: #selector(UIViewController.dismissKeyboard))
    tap.cancelsTouchesInView = false
    view.addGestureRecognizer(tap)
  }
  
  @objc func dismissKeyboard() {
    view.endEditing(true)
  }
}

