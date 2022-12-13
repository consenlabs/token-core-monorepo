//
//  DeviceManageViewController.swift
//  imKeyConnector_Example
//
//  Created by joe on 7/9/19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import UIKit
import LTHRadioButton
import imKeyConnector

class DeviceManageViewController: UIViewController {
  
  override func viewDidLoad() {
    super.viewDidLoad()
    
    // Do any additional setup after loading the view.
    initRadios()
  }
  
  func initRadios(){
    let rbBTC = LTHRadioButton(selectedColor: .black)
    let rbETH = LTHRadioButton(selectedColor: .black)
    let rbEOS = LTHRadioButton(selectedColor: .black)
    let rbIMK = LTHRadioButton(selectedColor: .black)
    let rbCosmos = LTHRadioButton(selectedColor: .black)
    self.view.addSubview(rbBTC)
    self.view.addSubview(rbETH)
    self.view.addSubview(rbEOS)
    self.view.addSubview(rbIMK)
    self.view.addSubview(rbCosmos)
    rbBTC.translatesAutoresizingMaskIntoConstraints = false
    rbETH.translatesAutoresizingMaskIntoConstraints = false
    rbEOS.translatesAutoresizingMaskIntoConstraints = false
    rbIMK.translatesAutoresizingMaskIntoConstraints = false
    rbCosmos.translatesAutoresizingMaskIntoConstraints = false
    NSLayoutConstraint.activate([
      rbBTC.centerYAnchor.constraint(equalTo: labelBTC.centerYAnchor),
      rbBTC.leadingAnchor.constraint(equalTo: labelBTC.leadingAnchor,constant: -20),
      rbBTC.heightAnchor.constraint(equalToConstant: rbBTC.frame.height),
      rbBTC.widthAnchor.constraint(equalToConstant: rbBTC.frame.width)]
    )
    NSLayoutConstraint.activate([
      rbETH.centerYAnchor.constraint(equalTo: labelETH.centerYAnchor),
      rbETH.leadingAnchor.constraint(equalTo: labelETH.leadingAnchor,constant: -20),
      rbETH.heightAnchor.constraint(equalToConstant: rbETH.frame.height),
      rbETH.widthAnchor.constraint(equalToConstant: rbETH.frame.width)]
    )
    NSLayoutConstraint.activate([
      rbEOS.centerYAnchor.constraint(equalTo: labelEOS.centerYAnchor),
      rbEOS.leadingAnchor.constraint(equalTo: labelEOS.leadingAnchor,constant: -20),
      rbEOS.heightAnchor.constraint(equalToConstant: rbEOS.frame.height),
      rbEOS.widthAnchor.constraint(equalToConstant: rbEOS.frame.width)]
    )
    NSLayoutConstraint.activate([
      rbIMK.centerYAnchor.constraint(equalTo: labelIMK.centerYAnchor),
      rbIMK.leadingAnchor.constraint(equalTo: labelIMK.leadingAnchor,constant: -20),
      rbIMK.heightAnchor.constraint(equalToConstant: rbIMK.frame.height),
      rbIMK.widthAnchor.constraint(equalToConstant: rbIMK.frame.width)]
    )
    NSLayoutConstraint.activate([
      rbCosmos.centerYAnchor.constraint(equalTo: labelCosmsos.centerYAnchor),
      rbCosmos.leadingAnchor.constraint(equalTo: labelCosmsos.leadingAnchor,constant: -20),
      rbCosmos.heightAnchor.constraint(equalToConstant: rbBTC.frame.height),
      rbCosmos.widthAnchor.constraint(equalToConstant: rbBTC.frame.width)]
    )
    rbBTC.onSelect {
      rbETH.deselect()
      rbEOS.deselect()
      rbIMK.deselect()
      rbCosmos.deselect()
      self.appletName = Applet.btcName
    }
    rbETH.onSelect {
      rbBTC.deselect()
      rbEOS.deselect()
      rbIMK.deselect()
      rbCosmos.deselect()
      self.appletName = Applet.ethName
    }
    rbEOS.onSelect {
      rbBTC.deselect()
      rbETH.deselect()
      rbIMK.deselect()
      rbCosmos.deselect()
      self.appletName = Applet.eosName
    }
    rbIMK.onSelect {
      rbBTC.deselect()
      rbETH.deselect()
      rbEOS.deselect()
      rbCosmos.deselect()
      self.appletName = Applet.sioName
    }
    rbCosmos.onSelect {
      rbBTC.deselect()
      rbETH.deselect()
      rbEOS.deselect()
      rbIMK.deselect()
      self.appletName = Applet.cosmosName
    }
    rbBTC.select()
  }
  
  @IBOutlet weak var labelBTC: UILabel!
  @IBOutlet weak var labelETH: UILabel!
  @IBOutlet weak var labelEOS: UILabel!
  @IBOutlet weak var labelIMK: UILabel!
  @IBOutlet weak var labelCosmsos: UILabel!
  
  
  @IBAction func backClick(_ sender: Any) {
    self.dismiss(animated: true, completion: nil)
  }
  
  var handle:UInt = 0
  
  @IBAction func checkUpdateClick(_ sender: Any) {
    do {
      let res = try DeviceAPI.checkUpdate()
      Log.d(res)
      toastMsg(message: "success")
    } catch let e as ImkeyError {
      Log.d("!!!error:\(e.message)")
      toastMsg(message: e.message)
    }catch{
      Log.d(error)
    }
  }
  
  @IBAction func checkDeviceClick(_ sender: Any) {
    DispatchQueue.global().async {
      do {
        try DeviceAPI.checkDevice()
        self.toastMsg(message: "success")
      } catch let e as ImkeyError {
        Log.d("!!!error:\(e.message)")
        self.toastMsg(message: e.message)
      }catch{
        Log.d(error)
      }
    }
  }
  
  @IBAction func activeDeviceClick(_ sender: Any) {
    do {
      try DeviceAPI.activeDevice()
      toastMsg(message: "success")
    } catch let e as ImkeyError {
      Log.d("!!!error:\(e.message)")
      toastMsg(message: e.message)
    }catch{
      Log.d(error)
    }
  }
  
  var appletName = ""
  
  
  @IBAction func downloadClick(_ sender: Any) {
    do {
      try DeviceAPI.downloadApp(appletName: appletName)
      toastMsg(message: "success")
    } catch let e as ImkeyError {
      Log.d("!!!error:\(e.message)")
      toastMsg(message: e.message)
    }catch{
      Log.d(error)
    }
  }
  
  @IBAction func updateClick(_ sender: Any) {
    do {
      try DeviceAPI.updateApp(appletName: appletName)
      toastMsg(message: "success")
    } catch let e as ImkeyError {
      Log.d("!!!error:\(e.message)")
      toastMsg(message: e.message)
    }catch{
      Log.d(error)
    }
  }
  
  @IBAction func deleteClick(_ sender: Any) {
    do {
      try DeviceAPI.deleteApp(appletName: appletName)
      toastMsg(message: "success")
    } catch let e as ImkeyError {
      Log.d("!!!error:\(e.message)")
      toastMsg(message: e.message)
    }catch{
      Log.d(error)
    }
  }
}
