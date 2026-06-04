# Release Guide

This repository has multiple release surfaces. Keep the version source, tag,
artifact, and changelog entry aligned before publishing.

## Release Surfaces

| Surface | Version source | Publishing path | Artifact |
| ------- | -------------- | --------------- | -------- |
| Android AAR | Root [`../VERSION`](../VERSION), with short commit appended by CI | [`../.github/workflows/build-release-android.yml`](../.github/workflows/build-release-android.yml) | Maven Central package `io.github.consenlabs.android:token-core` |
| iOS XCFrameworks | Root [`../VERSION`](../VERSION), with short commit in zip names | [`../.github/workflows/build-release-ios.yml`](../.github/workflows/build-release-ios.yml) | GitHub Release `v<VERSION>` containing `ios-tcx-<VERSION>+<sha>.zip` and `ios-ikc-<VERSION>+<sha>.zip` |
| WebAssembly/npm files | [`../token-core/tcx-wasm/Cargo.toml`](../token-core/tcx-wasm/Cargo.toml) and generated package metadata | `make build-npm`, then `make publish-npm` when publishing is intended | Files under `publish/npm/` |

The root `VERSION` currently governs mobile release automation. Individual Rust
crate versions do not automatically imply a mobile SDK release.

## Version and Tag Rules

- Use semantic versions in `VERSION`, for example `2.8.4`.
- iOS release automation creates or updates GitHub Release tag `v<VERSION>`.
- Android release automation publishes a Maven Central version derived from
  `VERSION` plus the release commit short SHA.
- `tcx-wasm` has its own crate/package version. Bump it when the wasm API or
  npm package behavior changes.
- Do not reuse a tag for different artifacts.

## Changelog Rules

Record user-facing changes in [`../CHANGELOG.md`](../CHANGELOG.md) before a
release. Group entries by release version and date when known.

Recommended categories:

- `Added`
- `Changed`
- `Fixed`
- `Security`
- `Compatibility`
- `Documentation`

For internal-only refactors, include the change only if it affects supported
builds, tests, artifacts, API behavior, or external contributors.

## Android Release Flow

The Android workflow starts after an approved pull request review. It:

1. Checks out the reviewed PR head commit.
2. Installs Rust, Android SDK/NDK, Java 17, Gradle, and Protobuf.
3. Builds Rust native libraries through [`../script/build-android.sh`](../script/build-android.sh).
4. Builds `tokencore-release.aar` under [`../publish/android`](../publish/android).
5. Publishes to a staging repository.
6. Deploys to Maven Central with JReleaser.
7. Uploads JReleaser logs as workflow artifacts.

Required release secrets are documented in
[`../publish/android/README.md`](../publish/android/README.md).

Local checks:

```bash
cd publish/android
./gradlew assemble
./gradlew jreleaserConfig
```

## iOS Release Flow

The iOS workflow starts after an approved pull request review. It:

1. Checks out the reviewed PR head commit.
2. Installs Rust targets, `cbindgen`, and Protobuf.
3. Builds `imkey-core/ikc` for iOS device and simulator targets.
4. Builds `token-core/tcx` for iOS device and simulator targets.
5. Produces `imKeyCoreX.xcframework` and `TokenCoreX.xcframework`.
6. Packages zip files and records SHA-256 hashes.
7. Creates a GitHub Release tagged `v<VERSION>`.

The current iOS deployment target in automation is `14.0`.

## WebAssembly/npm Flow

Build the npm-style package files:

```bash
make build-npm
```

This creates `publish/npm/` and copies:

- `tcx_wasm_bg.wasm`
- `tcx_wasm.js`
- `tcx_wasm.d.ts`
- `tcx_wasm_bg.wasm.d.ts`
- `README.md` from [`../examples/wasm/README.md`](../examples/wasm/README.md)

Publish only after validating the generated files and package metadata:

```bash
make publish-npm
```

## Pre-Release Checklist

- `CHANGELOG.md` contains the release entry.
- `VERSION` is correct for mobile release surfaces.
- `token-core/tcx-wasm/Cargo.toml` is correct for wasm package changes.
- `cargo fmt --check` passes.
- `make test-workspace` passes or any skipped hardware boundary is documented.
- `make test-wasm` passes for wasm-facing changes.
- Android release changes have at least `./gradlew assemble` validated under
  `publish/android`.
- iOS release changes have the relevant Rust target builds validated when
  Xcode is available.
- Release notes identify compatibility changes in addresses, signatures,
  derivation paths, C ABI errors, Protobuf fields, or artifact coordinates.
