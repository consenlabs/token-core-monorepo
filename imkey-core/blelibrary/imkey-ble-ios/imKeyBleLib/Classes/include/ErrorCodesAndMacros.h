//
//  ErrorCodesAndMacro.h
//  FTTransmission
//
//  Created by FTsafe ID Department on 2017/4/14.
//  Copyright © 2017年 FT. All rights reserved.
//

#ifndef ErrorCodesAndMacro_h
#define ErrorCodesAndMacro_h

// 返回码 采用PKCS#11返回值
#define CKR_OK                                  0x00000000  // 正确
#define CKR_ARGUMENTS_BAD                       0x00000007  // 参数错误
#define CKR_DEVICE_ERROR                        0x00000030  // 设备异常
#define CKR_DEVICE_MEMORY                       0x00000031  // 设备空间不足
#define CKR_BUFFER_TOO_SMALL                    0x00000150  // 参数空间太小
#define CKR_CRYPTOKI_NOT_INITIALIZED            0x00000190  // SDK尚未初始化
#define CKR_CRYPTOKI_ALREADY_INITIALIZED        0x00000191  // SDK已经初始化

#define CKR_VENDOR_DEFINED                      0x80000000
#define CKR_DEVICE_IS_BUSY                      (CKR_VENDOR_DEFINED + 1)
#define CKR_COMMLIB_NOT_INITIALIZED             (CKR_VENDOR_DEFINED + 2)
#define CKR_COMMLIB_ALREADY_INITIALIZED         (CKR_VENDOR_DEFINED + 3)

#define CKR_TIMEOUT                             (CKR_VENDOR_DEFINED + 8)
#define CKR_USER_CANCEL                         (CKR_VENDOR_DEFINED + 9)
#define CKR_USER_END                            (CKR_VENDOR_DEFINED + 10)
#define CKR_NO_DEVICE                           (CKR_VENDOR_DEFINED + 11)
#define CKR_DEVICE_ALREADY_CONNECTED            (CKR_VENDOR_DEFINED + 12)

//蓝牙通讯库定义错误码
#define CKR_VENDOR_BLE_DEFINED                  0x81000000
#define CKR_BLE_POWEROFF                        (CKR_VENDOR_BLE_DEFINED + 1)
#define CKR_BLE_NOT_SUPPORT                     (CKR_VENDOR_BLE_DEFINED + 2)
#define CKR_BLE_CONNECT_FAIL                    (CKR_VENDOR_BLE_DEFINED + 3)
#define CKR_BLE_BOND_FAIL                       (CKR_VENDOR_BLE_DEFINED + 4)
#define CKR_BLE_NOT_AUTHORIZE                   (CKR_VENDOR_BLE_DEFINED + 5)
#define CKR_BLE_UNKNOW                          (CKR_VENDOR_BLE_DEFINED + 6)

//自定义
#define BLE_UNUSE_CONNECT                       (CKR_VENDOR_BLE_DEFINED + 7)

#endif /* ErrorCodesAndMacro_h */
