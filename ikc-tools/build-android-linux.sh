#!/bin/bash
#reference  https://medium.com/visly/rust-on-android-19f34a2fb43

JNI_LIBS=../examples/android/app/src/main/jniLibs
if [ ! -d $JNI_LIBS ]; then
    mkdir $JNI_LIBS
    mkdir $JNI_LIBS/arm64-v8a
    mkdir $JNI_LIBS/armeabi-v7a
    mkdir $JNI_LIBS/x86
    mkdir $JNI_LIBS/x86_64
fi

export ANDROID_NDK_TOOLCHAINS=~/.NDK
cd ../api
path_pwd=`pwd`
export OPENSSL_DIR=$path_pwd/../depend/openssl

AR=$ANDROID_NDK_TOOLCHAINS/arm64/bin/aarch64-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/arm64/bin/aarch64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/arm64/bin/aarch64-linux-android-ld PKG_CONFIG_ALLOW_CROSS=1 OPENSSL_DIR=$OPENSSL_DIR/android-arm64 LDFLAGS=-L$OPENSSL_DIR/android-arm64/lib/ CPPFLAGS=-I$OPENSSL_DIR/android-arm64/include cargo build --target aarch64-linux-android --release
AR=$ANDROID_NDK_TOOLCHAINS/arm/bin/arm-linux-androideabi-ar CC=$ANDROID_NDK_TOOLCHAINS/arm/bin/armv7a-linux-androideabi29-clang LD=$ANDROID_NDK_TOOLCHAINS/arm/bin/arm-linux-androideabi-ld PKG_CONFIG_ALLOW_CROSS=1 OPENSSL_DIR=$OPENSSL_DIR/android-arm LDFLAGS=-L$OPENSSL_DIR/android-arm/lib/ CPPFLAGS=-I$OPENSSL_DIR/android-arm/include cargo build --target armv7-linux-androideabi --release
AR=$ANDROID_NDK_TOOLCHAINS/x86/bin/i686-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/x86/bin/i686-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/x86/bin/i686-linux-android-ld PKG_CONFIG_ALLOW_CROSS=1 OPENSSL_DIR=$OPENSSL_DIR/android-x86 LDFLAGS=-L$OPENSSL_DIR/android-x86/lib/ CPPFLAGS=-I$OPENSSL_DIR/android-x86/include cargo build --target i686-linux-android --release
AR=$ANDROID_NDK_TOOLCHAINS/x86_64/bin/x86_64-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/x86_64/bin/x86_64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/x86_64/bin/x86_64-linux-android-ld PKG_CONFIG_ALLOW_CROSS=1 OPENSSL_DIR=$OPENSSL_DIR/android-x86_64 LDFLAGS=-L$OPENSSL_DIR/android-x86_64/lib/ CPPFLAGS=-I$OPENSSL_DIR/android-x86_64/include cargo build --target x86_64-linux-android --release

cp ../target/aarch64-linux-android/release/libconnector.so ../examples/android/app/src/main/jniLibs/arm64-v8a/libconnector.so
cp ../target/armv7-linux-androideabi/release/libconnector.so ../examples/android/app/src/main/jniLibs/armeabi-v7a/libconnector.so
cp ../target/i686-linux-android/release/libconnector.so ../examples/android/app/src/main/jniLibs/x86/libconnector.so
cp ../target/x86_64-linux-android/release/libconnector.so ../examples/android/app/src/main/jniLibs/x86_64/libconnector.so
