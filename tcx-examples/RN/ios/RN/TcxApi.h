//
//  WalletAPI.h
//  RN
//
//  Created by xyz on 2019/11/26.
//  Copyright © 2019 Facebook. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>
#import "tcx.h"

NS_ASSUME_NONNULL_BEGIN

@interface TcxApi : NSObject <RCTBridgeModule>

-(void) callTcxApi:(NSString *)hex resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject;

@end

NS_ASSUME_NONNULL_END
