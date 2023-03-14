#!/bin/bash

export ANDROID_NDK_TOOLCHAINS=$ANDROID_SDK_ROOT/ndk/25.1.8937393/toolchains/llvm/prebuilt/linux-x86_64/bin

export OPENSSL_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl
export OPENSSL_LIB_ROOT_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl
export OPENSSL_INCLUDE_ROOT_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl
export OPENSSL_LIB_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl
export X86_64_LINUX_ANDROID_OPENSSL_LIB_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl/android-x86_64/lib/
export I686_LINUX_ANDROID_OPENSSL_LIB_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl/android-x86/lib/
export ARMV7_LINUX_ANDROIDEABI_OPENSSL_LIB_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl/android-arm/lib/
export AARCH64_LINUX_ANDROID_OPENSSL_LIB_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl/android-arm64/lib/
export OPENSSL_INCLUDE_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl
export X86_64_LINUX_ANDROID_OPENSSL_INCLUDE_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl/android-x86_64/include/
export I686_LINUX_ANDROID_OPENSSL_INCLUDE_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl/android-x86/include/
export ARMV7_LINUX_ANDROIDEABI_OPENSSL_INCLUDE_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl/android-arm/include/
export AARCH64_LINUX_ANDROID_OPENSSL_INCLUDE_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl/android-arm64/include/
export OPENSSL_DIR=/home/runner/work/token-core-monorepo/token-core-monorepo/imkey-core/ikc-depend/openssl

# OPENSSL_LIB_DIR=$OPENSSL_LIB_ROOT_DIR/android-arm64/lib OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_ROOT_DIR/android-arm64/include  AR=$ANDROID_NDK_TOOLCHAINS/llvm-ar CC=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/ld env OPENSSL_STATIC=1 cargo build --target aarch64-linux-android --release
OPENSSL_LIB_DIR=$OPENSSL_LIB_ROOT_DIR/android-arm/lib OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_ROOT_DIR/android-arm/include AR=$ANDROID_NDK_TOOLCHAINS/llvm-ar CC=$ANDROID_NDK_TOOLCHAINS/armv7a-linux-androideabi29-clang LD=$ANDROID_NDK_TOOLCHAINS/ld env OPENSSL_STATIC=1 cargo build --target armv7-linux-androideabi --release
# OPENSSL_LIB_DIR=$OPENSSL_LIB_ROOT_DIR/android-x86/lib OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_ROOT_DIR/android-x86/include AR=$ANDROID_NDK_TOOLCHAINS/llvm-ar CC=$ANDROID_NDK_TOOLCHAINS/i686-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/ld env OPENSSL_STATIC=1 cargo build --target i686-linux-android --release
# OPENSSL_LIB_DIR=$OPENSSL_LIB_ROOT_DIR/android-x86_64/lib OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_ROOT_DIR/android-x86_64/include AR=$ANDROID_NDK_TOOLCHAINS/llvm-ar CC=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/ld env OPENSSL_STATIC=1 cargo build --target x86_64-linux-android --release

pushd ../token-core/tcx-libs/secp256k1/
# AR=$ANDROID_NDK_TOOLCHAINS/llvm-ar CC=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/ld env OPENSSL_STATIC=1 cargo build --target aarch64-linux-android --release
# AR=$ANDROID_NDK_TOOLCHAINS/llvm-ar CC=$ANDROID_NDK_TOOLCHAINS/armv7a-linux-androideabi29-clang LD=$ANDROID_NDK_TOOLCHAINS/ld env OPENSSL_STATIC=1 cargo build --target armv7-linux-androideabi --release
# AR=$ANDROID_NDK_TOOLCHAINS/llvm-ar CC=$ANDROID_NDK_TOOLCHAINS/i686-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/ld env OPENSSL_STATIC=1 cargo build --target i686-linux-android --release
# AR=$ANDROID_NDK_TOOLCHAINS/llvm-ar CC=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/ld env OPENSSL_STATIC=1 cargo build --target x86_64-linux-android --release
popd

# copy so to jinLibs
# mkdir -p ../publish/android/tokencore/src/main/jniLibs/arm64-v8a/
# cp -rf ../target/aarch64-linux-android/release/libconnector.so ../publish/android/tokencore/src/main/jniLibs/arm64-v8a/
# cp -rf ../target/aarch64-linux-android/release/libtcx.so ../publish/android/tokencore/src/main/jniLibs/arm64-v8a/
# cp -rf ../token-core/tcx-libs/secp256k1/target/aarch64-linux-android/release/libsecp256k1.so ../publish/android/tokencore/src/main/jniLibs/arm64-v8a/

mkdir -p ../publish/android/tokencore/src/main/jniLibs/armeabi-v7a/
cp -rf ../target/armv7-linux-androideabi/release/libconnector.so ../publish/android/tokencore/src/main/jniLibs/armeabi-v7a/
# cp -rf ../target/armv7-linux-androideabi/release/libtcx.so ../publish/android/tokencore/src/main/jniLibs/armeabi-v7a/
# cp -rf ../token-core/tcx-libs/secp256k1/target/armv7-linux-androideabi/release/libsecp256k1.so ../publish/android/tokencore/src/main/jniLibs/armeabi-v7a/

# mkdir -p ../publish/android/tokencore/src/main/jniLibs/x86/
# cp -rf ../target/i686-linux-android/release/libconnector.so ../publish/android/tokencore/src/main/jniLibs/x86/
# cp -rf ../target/i686-linux-android/release/libtcx.so ../publish/android/tokencore/src/main/jniLibs/x86/
# cp -rf ../token-core/tcx-libs/secp256k1/target/i686-linux-android/release/libsecp256k1.so ../publish/android/tokencore/src/main/jniLibs/x86/

# mkdir -p ../publish/android/tokencore/src/main/jniLibs/x86_64/
# cp -rf ../target/x86_64-linux-android/release/libconnector.so ../publish/android/tokencore/src/main/jniLibs/x86_64/
# cp -rf ../target/x86_64-linux-android/release/libtcx.so ../publish/android/tokencore/src/main/jniLibs/x86_64/
# cp -rf ../token-core/tcx-libs/secp256k1/target/x86_64-linux-android/release/libsecp256k1.so ../publish/android/tokencore/src/main/jniLibs/x86_64/
