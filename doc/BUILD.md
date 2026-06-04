# Build Guide

This guide describes the supported build paths for Token Core Monorepo. Start
from the repository root unless a command says otherwise.

## Toolchain

The Rust toolchain is pinned by [`../rust-toolchain.toml`](../rust-toolchain.toml):

```bash
rustup show
cargo --version
```

The pinned channel is `nightly-2026-04-06`. The workspace uses Cargo resolver
v2 and a repository-local Cargo config in [`../.cargo/config.toml`](../.cargo/config.toml).

On macOS, the repository config uses [`../scripts/rustc-wrapper.sh`](../scripts/rustc-wrapper.sh)
to set the deployment target expected by the current Rust toolchain. This only
affects the build/link environment; it must not change wallet algorithms,
addresses, signatures, or keystore behavior.

## Host Dependencies

Install Protobuf before building crates that generate Protobuf bindings:

```bash
brew install protobuf
```

Linux distributions can use their package manager, for example
`protobuf-compiler` and `libprotobuf-dev`.

## Workspace Build

```bash
cargo build
```

This compiles all workspace members listed in [`../Cargo.toml`](../Cargo.toml).

To compile test targets without running tests:

```bash
cargo test --workspace --no-run
```

## TokenCoreX Build

```bash
make build-tcx
```

This target enters `token-core` and runs `cargo build`.

The C ABI crate is [`../token-core/tcx`](../token-core/tcx). It builds library
types `staticlib`, `cdylib`, and `rlib`.

## imKeyCore Build

```bash
cargo build -p ikc
```

The C ABI crate is [`../imkey-core/ikc`](../imkey-core/ikc). It builds library
types `staticlib` and `cdylib`.

Hardware communication code can compile without a connected imKey device, but
runtime tests or examples that call HID/APDU paths require a real device.

## WebAssembly Build

Install the wasm target and tools:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
brew install llvm
```

The default Makefile values expect Homebrew LLVM:

```bash
make test-wasm
make build-wasm
```

Override the compiler path when needed:

```bash
WASM_CC=/path/to/clang WASM_AR=/path/to/llvm-ar make build-wasm
```

Run the browser example:

```bash
make dev-wasm
```

The example is documented in [`../examples/wasm/README.md`](../examples/wasm/README.md).

## Android Artifacts

Android release builds require:

- Android SDK
- NDK `25.2.9519653`
- Java 17
- Gradle through [`../publish/android/gradlew`](../publish/android/gradlew)
- Rust targets:
  - `aarch64-linux-android`
  - `armv7-linux-androideabi`
  - `i686-linux-android`
  - `x86_64-linux-android`

The release workflow builds Rust native libraries through
[`../script/build-android.sh`](../script/build-android.sh), then builds the AAR
under [`../publish/android`](../publish/android).

For local packaging checks:

```bash
cd publish/android
./gradlew assemble
```

For publishing details, see [`RELEASE.md`](./RELEASE.md) and
[`../publish/android/README.md`](../publish/android/README.md).

## iOS Artifacts

iOS release builds require:

- Xcode
- Rust targets:
  - `aarch64-apple-ios`
  - `aarch64-apple-ios-sim`
  - `x86_64-apple-ios`
- `cbindgen` version `0.26.0`
- `protobuf`

The release workflow builds:

- `imKeyCoreX.xcframework` from `imkey-core/ikc`
- `TokenCoreX.xcframework` from `token-core/tcx`

The current iOS deployment target in release automation is `14.0`.

## Generated and Local Outputs

Common generated outputs include:

- `target/`: Cargo build artifacts
- `examples/wasm/src/pkg/` and `examples/wasm/public/`: wasm example output
- `publish/npm/`: npm-style wasm package output
- `publish/android/tokencore/build/`: Android AAR output
- `ios-release/` and root `ios-*.zip`: iOS release workflow output

Do not commit generated artifacts unless a release or packaging workflow
explicitly requires them.
