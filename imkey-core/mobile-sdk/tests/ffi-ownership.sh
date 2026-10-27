#!/usr/bin/env bash
set -euo pipefail
# JNA_JAR is the host-compatible runtime jar; JNA_COMPILE_JAR may point to the
# SDK's older JNA version to verify source/API compatibility independently.
: "${JNA_JAR:?Set JNA_JAR to a local JNA jar}"
compile_jar=${JNA_COMPILE_JAR:-$JNA_JAR}
repo_root=$(cd "$(dirname "$0")/../../.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/classes"
cat > "$work_dir/mock.c" <<'C'
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static int allocated = 0, released = 0;
static const char *(*callback)(const char *, int32_t);
static char *owned(const char *value) { allocated++; return strdup(value); }
const char *call_imkey_api(const char *input) { (void)input; return owned("6869"); }
const char *get_apdu(void) { return owned("00A4040000"); }
const char *get_apdu_return(void) { return owned("9000"); }
const char *imkey_get_last_err_message(void) { return owned(""); }
void imkey_clear_err(void) {}
void imkey_free_const_string(const char *value) { if (value) { released++; free((void *)value); } }
void set_apdu(const char *value) { (void)value; }
void set_apdu_return(const char *value) { (void)value; }
void set_callback(const char *(*value)(const char *, int32_t)) { callback = value; }
int allocation_count(void) { return allocated; }
int release_count(void) { return released; }
int invoke_callback(void) { return callback && strcmp(callback("00A4040000", 20), "9000") == 0; }
void init_token_core_x(const char *value) { (void)value; }
const char *call_tcx_api(const char *value) { (void)value; return owned("6869"); }
const char *get_last_err_message(void) { return owned(""); }
void clear_err(void) {}
void free_const_string(const char *value) { imkey_free_const_string(value); }
C
case "$(uname -s)" in
  Darwin) cc -dynamiclib "$work_dir/mock.c" -o "$work_dir/libconnector.dylib"; cp "$work_dir/libconnector.dylib" "$work_dir/libtcx.dylib" ;;
  *) cc -shared -fPIC "$work_dir/mock.c" -o "$work_dir/libconnector.so"; cp "$work_dir/libconnector.so" "$work_dir/libtcx.so" ;;
esac
for family in sdk example; do
  if [[ $family == sdk ]]; then
    package=com.mk.imkeylibrary.keycore
    sender_import='import com.mk.imkeylibrary.utils.Sender;'
    source_dir="$repo_root/imkey-core/mobile-sdk/android/imkeylibrary/src/main/java/com/mk/imkeylibrary/keycore"
    sender="$repo_root/imkey-core/mobile-sdk/android/imkeylibrary/src/main/java/com/mk/imkeylibrary/utils/Sender.java"
  else
    package=com.mk.imkeydemo.keycore
    sender_import=''
    source_dir="$repo_root/imkey-core/ikc-examples/android/app/src/main/java/com/mk/imkeydemo/keycore"
    sender="$source_dir/Sender.java"
  fi
  mkdir -p "$work_dir/$family"
  cat > "$work_dir/$family/OwnershipTest.java" <<JAVA
package $package;
$sender_import
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
public final class OwnershipTest {
  public interface Probe extends Library {
    Probe INSTANCE = Native.load("connector", Probe.class);
    int allocation_count(); int release_count(); int invoke_callback();
  }
  private static void check(boolean condition) { if (!condition) throw new AssertionError(); }
  public static void main(String[] args) {
    RustApi api = RustApi.INSTANCE;
    check("6869".equals(api.call_imkey_api("00")));
    check("".equals(api.get_last_err_message()));
    check("00A4040000".equals(api.get_apdu()));
    check("9000".equals(api.get_apdu_return()));
    check(Probe.INSTANCE.allocation_count() == 4 && Probe.INSTANCE.release_count() == 4);
    final CallbackResponseBuffer buffer = new CallbackResponseBuffer();
    Pointer first = buffer.store("long previous response");
    check(Pointer.nativeValue(first) == Pointer.nativeValue(buffer.store("9000")));
    check("9000".equals(first.getString(0, "UTF-8")));
    check("中文".equals(buffer.store("中文").getString(0, "UTF-8")));
    check(buffer.store(new String(new char[131089])).getString(0, "UTF-8").startsWith("communication_error_"));
    final int[] calls = new int[] {0};
    Sender callback = new Sender() {
      public Pointer sendApdu(String input, int timeout) {
        check("00A4040000".equals(input) && timeout == 20); calls[0]++;
        return buffer.store("9000");
      }
    };
    java.lang.ref.WeakReference<Sender> reference = new java.lang.ref.WeakReference<Sender>(callback);
    api.set_callback(callback);
    callback = null;
    System.gc(); System.runFinalization();
    check(reference.get() != null);
    for (int i = 0; i < 1000; i++) check(Probe.INSTANCE.invoke_callback() == 1);
    check(calls[0] == 1000 && Probe.INSTANCE.release_count() == 4);
  }
}
JAVA
  javac -encoding UTF-8 -source 7 -target 7 -cp "$compile_jar" -d "$work_dir/classes" \
    "$sender" "$source_dir/RustApi.java" "$source_dir/CallbackResponseBuffer.java" "$work_dir/$family/OwnershipTest.java"
  java -Djna.nosys=true -Djna.library.path="$work_dir" -cp "$JNA_JAR:$work_dir/classes" "$package.OwnershipTest"
done
cat > "$work_dir/TokenCoreOwnershipTest.java" <<'JAVA'
package com.consenlabs.android.tokencoreexample;
import com.sun.jna.Library;
import com.sun.jna.Native;
public final class TokenCoreOwnershipTest {
  public interface Probe extends Library {
    Probe INSTANCE = Native.load("tcx", Probe.class);
    int allocation_count(); int release_count();
  }
  public static void main(String[] args) {
    if (!"6869".equals(TokenCore.INSTANCE.call_tcx_api("00")) || !"".equals(TokenCore.INSTANCE.get_last_err_message())
      || Probe.INSTANCE.allocation_count() != 2 || Probe.INSTANCE.release_count() != 2) throw new AssertionError();
  }
}
JAVA
javac -encoding UTF-8 -source 7 -target 7 -cp "$compile_jar" -d "$work_dir/classes" \
  "$repo_root/token-core/tcx-examples/android/app/src/main/java/com/consenlabs/android/tokencoreexample/TokenCore.java" "$work_dir/TokenCoreOwnershipTest.java"
java -Djna.nosys=true -Djna.library.path="$work_dir" -cp "$JNA_JAR:$work_dir/classes" com.consenlabs.android.tokencoreexample.TokenCoreOwnershipTest
if command -v swiftc >/dev/null; then
  python3 - "$repo_root" "$work_dir/Ownership.swift" <<'PY'
from pathlib import Path
import sys
source = (Path(sys.argv[1]) / 'imkey-core/mobile-sdk/ios/imKeyConnector/Classes/KeyCore/API.swift').read_text()
helpers = source[source.index('// Native results'):source.index('public class API')]
Path(sys.argv[2]).write_text('import Foundation\n' + helpers + '''
private var releases = 0
private func owned(_ value: String) -> UnsafePointer<Int8> {
    let bytes = value.utf8CString
    let pointer = UnsafeMutablePointer<Int8>.allocate(capacity: bytes.count)
    for index in 0..<bytes.count { pointer.advanced(by: index).initialize(to: bytes[index]) }
    return UnsafePointer(pointer)
}
func call_imkey_api(_ input: UnsafePointer<Int8>) -> UnsafePointer<Int8>? { return owned("6869") }
func imkey_get_last_err_message() -> UnsafePointer<Int8>? { return owned("") }
func imkey_free_const_string(_ input: UnsafePointer<Int8>) { releases += 1; UnsafeMutablePointer(mutating: input).deallocate() }
for _ in 0..<1000 { precondition(callImkeyHex("00") == "6869"); precondition(lastImkeyError().isEmpty) }
precondition(releases == 2000)
let first = ImkeyCallbackResponseBuffer.store("long previous response")
precondition(first == ImkeyCallbackResponseBuffer.store("9000"))
precondition(String(cString: first) == "9000")
precondition(String(cString: ImkeyCallbackResponseBuffer.store("中文")) == "中文")
precondition(String(cString: ImkeyCallbackResponseBuffer.store(String(repeating: "x", count: 131089))).hasPrefix("communication_error_"))
''')
PY
  swiftc -module-cache-path "$work_dir/swift-module-cache" "$work_dir/Ownership.swift" -o "$work_dir/swift-ownership"
  "$work_dir/swift-ownership"
  swiftc -frontend -parse "$repo_root/imkey-core/mobile-sdk/ios/imKeyConnector/Classes/KeyCore/API.swift"
  swiftc -frontend -parse "$repo_root/imkey-core/ikc-examples/ios/iosExample/API.swift"
  swiftc -frontend -parse "$repo_root/imkey-core/ikc-examples/ios/iosExample/ViewController.swift"
fi
printf 'Mobile bridge ownership checks passed (host mocks; no Android/iOS device integration).\n'
