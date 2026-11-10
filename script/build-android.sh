#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK_VERSION="${NDK_VERSION:-25.2.9519653}"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${SDK_ROOT}/ndk/${NDK_VERSION}}}"
case "$(uname -s)" in
  Darwin) HOST_TAG=darwin-x86_64 ;;
  Linux) HOST_TAG=linux-x86_64 ;;
  *) echo "Unsupported NDK host: $(uname -s)" >&2; exit 1 ;;
esac
TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG/bin"
if [ ! -x "$TOOLCHAIN/llvm-ar" ]; then
  echo "NDK not found: $NDK_ROOT. Set ANDROID_NDK_HOME or ANDROID_SDK_ROOT." >&2
  exit 1
fi
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
OPENSSL_ROOT="$REPO_ROOT/imkey-core/ikc-depend/openssl"
cd "$REPO_ROOT"

build_abi() {
  local target="$1" abi="$2" compiler="$3" openssl_arch="$4"
  local linker_var="CARGO_TARGET_$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')_LINKER"
  env "$linker_var=$TOOLCHAIN/$compiler" \
    AR="$TOOLCHAIN/llvm-ar" CC="$TOOLCHAIN/$compiler" \
    OPENSSL_STATIC=1 OPENSSL_LIB_DIR="$OPENSSL_ROOT/$openssl_arch/lib" \
    OPENSSL_INCLUDE_DIR="$OPENSSL_ROOT/$openssl_arch/include" \
    cargo build --locked --release --target "$target" -p tcx -p ikc
  local destination="$REPO_ROOT/publish/android/tokencore/src/main/jniLibs/$abi"
  mkdir -p "$destination"
  cp "$TARGET_DIR/$target/release/libconnector.so" "$destination/"
  cp "$TARGET_DIR/$target/release/libtcx.so" "$destination/"
}

build_abi aarch64-linux-android arm64-v8a aarch64-linux-android29-clang android-arm64
build_abi armv7-linux-androideabi armeabi-v7a armv7a-linux-androideabi22-clang android-arm
build_abi i686-linux-android x86 i686-linux-android29-clang android-x86
build_abi x86_64-linux-android x86_64-linux-android29-clang android-x86_64
