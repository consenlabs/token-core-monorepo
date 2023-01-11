//
//  FTBLEDelegate.h
//  FTTransmission
//
//  Created by FTsafe ID Department on 2018/8/9.
//  Copyright © 2018年 FT. All rights reserved.
//

#ifndef FTBLEDelegate_h
#define FTBLEDelegate_h
#import <Foundation/Foundation.h>

@protocol FTBLEDelegate <NSObject>


//----------------------统一的回调方法----------------------
@optional
/**
 *  设备连接上后的回调方法
 *
 *  @param uuid       已连接的设备uuid
 *  @param handler    已连接的设备句柄
 *  @param Error      连接设备的错误码（是否正常连接上设备）
 */
-(void)FTdidTheDeviceConnected:(NSString*)uuid handler:(NSInteger)handler ErrorCode:(NSInteger)Error;

@required
/**
 *  已经连接上的设备断开后的回调方法
 *  @param uuid       已连接的设备uuid
 *  @param Error      连接设备的错误码（是否正常连接上设备）
 */
-(void)FTdidTheDeviceDisconnected:(NSString*)uuid error:(NSInteger)Error;
@required
/**
 *  扫描到ble设备后回调方法
 *
 *  @param deviceName           扫描的设备名
 *  @param uuid                 设备的uuid
 */
-(void)FTDidFindBLEDevice:(NSString*)deviceName UUID:(NSString*)uuid;

@end
#endif /* FTBLEDelegate_h */
