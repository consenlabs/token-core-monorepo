#ifdef __OBJC__
#import <UIKit/UIKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "imKeyBleLib.h"
#import "ErrorCodesAndMacros.h"
#import "FTBLEDelegate.h"
#import "FTBLEInterface.h"

FOUNDATION_EXPORT double imKeyBleLibVersionNumber;
FOUNDATION_EXPORT const unsigned char imKeyBleLibVersionString[];

