export ANDROID_NDK_TOOLCHAINS=$HOME/Library/Android/sdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/darwin-x86_64/bin

#JNI_LIBS=../examples/android/app/src/main/jniLibs
#if [ ! -d $JNI_LIBS ]; then
#    mkdir $JNI_LIBS
#    mkdir $JNI_LIBS/arm64-v8a
#    mkdir $JNI_LIBS/armeabi-v7a
#    mkdir $JNI_LIBS/x86
#    mkdir $JNI_LIBS/x86_64
#fi

#pushd ../api
#JNI_LIBS=../android/imkeylibrary/src/main/jniLibs
#export JNI_LIBS=/Users/xiaoguang/work/project/token-v2/android/app/src/main/jniLibs
export OPENSSL_LIB_ROOT_DIR=/Users/xiaoguang/work/project/token-core-monorepo/ikc-depend/openssl
export OPENSSL_INCLUDE_ROOT_DIR=/Users/xiaoguang/work/project/token-core-monorepo/ikc-depend/openssl
export OPENSSL_LIB_DIR=/Users/xiaoguang/work/project/token-core-monorepo/ikc-depend/openssl
export OPENSSL_INCLUDE_DIR=/Users/xiaoguang/work/project/token-core-monorepo/ikc-depend/openssl
export OPENSSL_DIR=/Users/xiaoguang/work/project/token-core-monorepo/ikc-depend/openssl


#export OPENSSL_INCLUDE_DIR=`brew --prefix openssl`/include
#export OPENSSL_LIB_DIR=`brew --prefix openssl`/lib
OPENSSL_LIB_DIR=$OPENSSL_LIB_ROOT_DIR/android-arm64/lib OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_ROOT_DIR/android-arm64/include  AR=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android-ld env OPENSSL_STATIC=1 cargo build --target aarch64-linux-android --release
OPENSSL_LIB_DIR=$OPENSSL_LIB_ROOT_DIR/android-arm/lib OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_ROOT_DIR/android-arm/include AR=$ANDROID_NDK_TOOLCHAINS/arm-linux-androideabi-ar CC=$ANDROID_NDK_TOOLCHAINS/armv7a-linux-androideabi29-clang LD=$ANDROID_NDK_TOOLCHAINS/arm-linux-androideabi-ld env OPENSSL_STATIC=1 cargo build --target armv7-linux-androideabi --release
OPENSSL_LIB_DIR=$OPENSSL_LIB_ROOT_DIR/android-x86/lib OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_ROOT_DIR/android-x86/include AR=$ANDROID_NDK_TOOLCHAINS/i686-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/i686-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/i686-linux-android-ld env OPENSSL_STATIC=1 cargo build --target i686-linux-android --release
OPENSSL_LIB_DIR=$OPENSSL_LIB_ROOT_DIR/android-x86_64/lib OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_ROOT_DIR/android-x86_64/include AR=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android-ld env OPENSSL_STATIC=1 cargo build --target x86_64-linux-android --release


##  linking with `cc` failed
#export RUSTFLAGS="-Clink-arg=-fuse-ld=gold"
#AR=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android-ld env OPENSSL_STATIC=1 cargo build --target aarch64-linux-android --release
#AR=$ANDROID_NDK_TOOLCHAINS/arm-linux-androideabi-ar CC=$ANDROID_NDK_TOOLCHAINS/armv7a-linux-androideabi29-clang LD=$ANDROID_NDK_TOOLCHAINS/arm-linux-androideabi-ld env OPENSSL_STATIC=1 cargo build --target armv7-linux-androideabi --release
#AR=$ANDROID_NDK_TOOLCHAINS/i686-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/i686-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/i686-linux-android-ld env OPENSSL_STATIC=1 cargo build --target i686-linux-android --release
#AR=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android-ld env OPENSSL_STATIC=1 cargo build --target x86_64-linux-android --release


#cp ../target/aarch64-linux-android/release/libconnector.so ../android/imkeylibrary/src/main/jniLibs/arm64-v8a/libconnector.so
#cp ../target/armv7-linux-androideabi/release/libconnector.so ../android/imkeylibrary/src/main/jniLibs/armeabi-v7a/libconnector.so
#cp ../target/i686-linux-android/release/libconnector.so ../android/imkeylibrary/src/main/jniLibs/x86/libconnector.so
#cp ../target/x86_64-linux-android/release/libconnector.so ../android/imkeylibrary/src/main/jniLibs/x86_64/libconnector.so

#popd