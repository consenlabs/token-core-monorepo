# Publishing

This directory contains packaging projects and generated release output for
Token Core Monorepo.

## Release Surfaces

| Surface | Source | Output |
| ------- | ------ | ------ |
| Android | [`android`](./android/README.md) | Maven Central AAR `io.github.consenlabs.android:token-core` |
| WebAssembly/npm | `make build-npm` from repository root | Generated files under `publish/npm/` |
| iOS | GitHub Actions release workflow | GitHub Release assets generated from `token-core/tcx` and `imkey-core/ikc` |

The full release policy is documented in [`../doc/RELEASE.md`](../doc/RELEASE.md).

## Android Local Check

```bash
cd publish/android
./gradlew assemble
./gradlew jreleaserConfig
```

## WebAssembly Package Build

```bash
make build-npm
```

`publish/npm/` is generated output. Do not edit generated files directly; change
the wasm crate, example README, or packaging command that produces them.
