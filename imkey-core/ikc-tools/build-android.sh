export ANDROID_NDK_TOOLCHAINS=$HOME/Library/Android/sdk/ndk-bundle/toolchains/llvm/prebuilt/darwin-x86_64/bin

JNI_LIBS=../android/imkeylibrary/src/main/jniLibs
if [ ! -d $JNI_LIBS ]; then
    mkdir $JNI_LIBS
    mkdir $JNI_LIBS/arm64-v8a
    mkdir $JNI_LIBS/armeabi-v7a
    mkdir $JNI_LIBS/x86
    mkdir $JNI_LIBS/x86_64
fi

pushd ../api
JNI_LIBS=../android/imkeylibrary/src/main/jniLibs


export OPENSSL_INCLUDE_DIR=`brew --prefix openssl`/include
export OPENSSL_LIB_DIR=`brew --prefix openssl`/lib

##  linking with `cc` failed
#export RUSTFLAGS="-Clink-arg=-fuse-ld=gold"
AR=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/aarch64-linux-android-ld env OPENSSL_STATIC=1 cargo build --target aarch64-linux-android --release
AR=$ANDROID_NDK_TOOLCHAINS/arm-linux-androideabi-ar CC=$ANDROID_NDK_TOOLCHAINS/armv7a-linux-androideabi29-clang LD=$ANDROID_NDK_TOOLCHAINS/arm-linux-androideabi-ld env OPENSSL_STATIC=1 cargo build --target armv7-linux-androideabi --release
AR=$ANDROID_NDK_TOOLCHAINS/i686-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/i686-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/i686-linux-android-ld env OPENSSL_STATIC=1 cargo build --target i686-linux-android --release
AR=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android-ar CC=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android29-clang LD=$ANDROID_NDK_TOOLCHAINS/x86_64-linux-android-ld env OPENSSL_STATIC=1 cargo build --target x86_64-linux-android --release


cp ../target/aarch64-linux-android/release/libconnector.so ../android/imkeylibrary/src/main/jniLibs/arm64-v8a/libconnector.so
cp ../target/armv7-linux-androideabi/release/libconnector.so ../android/imkeylibrary/src/main/jniLibs/armeabi-v7a/libconnector.so
cp ../target/i686-linux-android/release/libconnector.so ../android/imkeylibrary/src/main/jniLibs/x86/libconnector.so
cp ../target/x86_64-linux-android/release/libconnector.so ../android/imkeylibrary/src/main/jniLibs/x86_64/libconnector.so

popd




