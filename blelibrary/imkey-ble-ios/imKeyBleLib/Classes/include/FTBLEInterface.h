//
//  FTBLEInterface.h
//  FTTransmission
//
//  Created by FTsafe ID Department on 2018/8/8.
//  Copyright © 2018年 FT. All rights reserved.
//

#ifndef FTBLEInterface_h
#define FTBLEInterface_h

#import "FTBLEDelegate.h"

@interface BLEKeyInterface : NSObject
/**
 *  获取单例函数
 *  ret   单例对象
 */
+ (BLEKeyInterface*)SharedInstance;
/**
 *  初始化函数
 *  ret   错误码
 */
-(NSInteger)Initialize;
/**
 *  回收资源函数
 *  ret   错误码
 */
-(NSInteger)Finalize;
/**
 *  开始扫描函数
 *  ret   错误码
 */
-(NSInteger)StartScan;
/**
 *  停止扫描函数
 *  ret   错误码
 */
-(NSInteger)StopScan;
/**
 *  连接函数
 *
 *  @param uuid  扫描获取到的设备uuid
 *  @param handle  连接成功之后获取到的设备句柄
 *  @param timeout 连接过程的超时时间  单位为毫秒
 *  ret   错误码
 */
- (NSInteger)Connect:(const char*) uuid Handle:(unsigned long*)handle Timeout:(unsigned long)timeout;
/**
 *  断开连接函数
 *  @param handle  设备的连接句柄
 *  ret   错误码
 */
 - (NSInteger)Disconnect:(unsigned long)handle;
/**
 *  发送数据函数
 *
 *  @param handle  连接成功之后获取到的设备句柄
 *  @param data    要发送的数据
 *  @param len     发送的数据长度
 *  @param rcvData 接收到的数据
 *  @param rcvLen  接收到的数据长度
 *  @param timeout 发送函数的超时时间，单位是ms
 *  ret   错误码
 */
-(NSInteger)SendData:(unsigned long)handle Data:(const unsigned char*)data Length:(unsigned int)len RcvData:(unsigned char*)rcvData RcvDataLen:(unsigned int*)rcvLen Timeout:(unsigned int)timeout;
/**
 *  设置代理函数
 *  @param delegate  接收代理的实例
 *  ret   错误码
 */
-(void)SetDelegate:(id<FTBLEDelegate>)delegate;
/**
 *  移除代理函数
 */
-(void)RemoveDelegate;
/**
 *  获取库版本函数
 *  ret  库的版本号
 */
-(NSString*)GetLibVersion;
@end

#endif /* FTBLEInterface_h */
