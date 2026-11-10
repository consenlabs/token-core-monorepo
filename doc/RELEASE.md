# Release Guide

This repository has multiple release surfaces. Keep the version source, tag,
artifact, and changelog entry aligned before publishing.

## Release Surfaces

| Surface | Version source | Publishing path | Artifact |
| ------- | -------------- | --------------- | -------- |
| Android AAR | Root [`../VERSION`](../VERSION), with short commit appended by CI | [`../.github/workflows/build-release-android.yml`](../.github/workflows/build-release-android.yml) | Maven Central package `io.github.consenlabs.android:token-core` |
| iOS XCFrameworks | Root [`../VERSION`](../VERSION), with short commit appended by CI | [`../.github/workflows/build-release-ios.yml`](../.github/workflows/build-release-ios.yml) | GitHub Release `v<VERSION>+<short-sha>` containing `ios-tcx-<VERSION>+<short-sha>.zip` and `ios-ikc-<VERSION>+<short-sha>.zip` |
| WebAssembly/npm files | [`../publish/npm/package.json`](../publish/npm/package.json) for `@imtoken/wallet-core-web` | `make build-npm`, then `make publish-npm` when publishing is intended | Both WASM modules and JS/TypeScript adapters under `publish/npm/` |

The root `VERSION` currently governs mobile release automation. Individual Rust
crate versions do not automatically imply a mobile SDK release.

## Version and Tag Rules

- Use semantic versions in `VERSION`, for example `2.8.4`.
- iOS release automation creates or updates GitHub Release tag
  `v<VERSION>+<short-sha>`, matching the published zip artifact version.
- Android release automation publishes a Maven Central version derived from
  `VERSION` plus the release commit short SHA.
- The aggregate npm package version comes from `publish/npm/package.json`;
  the `tcx-wasm` and `ikc-wasm` Rust crate versions are independent. Bump the
  npm version when its public API or package behavior changes.
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

1. Verifies that the review is still approved, its exact SHA is the PR head,
   and the latest quality-gate run for that SHA passed without skipped jobs.
   Checks out that fixed SHA after the release environment approval.
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
bash script/build-android.sh
./publish/android/gradlew -p publish/android :tokencore:assembleRelease
python3 scripts/check-android-aar.py publish/android/tokencore/build/outputs/aar/tokencore-release.aar
./publish/android/gradlew -p publish/android jreleaserConfig
```

## iOS Release Flow

The iOS workflow starts after an approved pull request review. It:

1. Verifies the current approval and quality gates for the exact reviewed SHA,
   then checks out that fixed SHA after the release environment approval.
2. Installs Rust targets, `cbindgen`, and Protobuf.
3. Builds `imkey-core/ikc` for iOS device and simulator targets.
4. Builds `token-core/tcx` for iOS device and simulator targets.
5. Produces `imKeyCoreX.xcframework` and `TokenCoreX.xcframework`.
6. Packages zip files and records SHA-256 hashes.
7. Creates a GitHub Release tagged `v<VERSION>+<short-sha>`.

The current iOS deployment target in automation is `14.0`.

## WebAssembly/npm Flow

Build the npm-style package files:

```bash
make build-npm
```

This builds both `tcx-wasm` and `ikc-wasm` and copies their WASM binaries,
JavaScript glue and TypeScript declarations into `publish/npm/`. The aggregate
package also includes the maintained JS facade, browser adapters, package
manifest and [npm README](../publish/npm/README.md). Building must not replace
these maintained files with a single-crate manifest or the browser example README.

Publish only after validating the generated files and package metadata:

```bash
make test-npm
make test-npm-package
make publish-npm
```

## Pre-Release Checklist

The `Mobile Build Smoke` workflow can be run manually on the selected branch
to build Android native libraries/AARs or the three iOS Rust targets without
release credentials or publishing. iOS XCFramework assembly and application
loading remain separate integration checks.

- `CHANGELOG.md` contains the release entry.
- `VERSION` is correct for mobile release surfaces.
- `publish/npm/package.json` is correct for npm changes; Rust crate versions
  are reviewed separately.
- `doc/QUALITY_DEBT.md` still matches current clippy and cargo-deny exceptions.
- `cargo fmt --check` passes.
- `make test-workspace` passes or any skipped hardware boundary is documented.
- `make test-wasm` passes for wasm-facing changes.
- Android release changes build the Rust libraries, assemble the AAR, and pass
  `scripts/check-android-aar.py`; assembly alone is insufficient.
- iOS release changes have the relevant Rust target builds validated when
  Xcode is available.
- Release notes identify compatibility changes in addresses, signatures,
  derivation paths, C ABI errors, Protobuf fields, or artifact coordinates.
