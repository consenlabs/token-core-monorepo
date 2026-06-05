# Changelog

All notable user-facing changes to this repository should be documented here.

This project has multiple release surfaces:

- Mobile release artifacts follow the root [`VERSION`](./VERSION).
- iOS releases use GitHub tags named `v<VERSION>+<short-sha>`.
- Android releases publish Maven Central artifacts under
  `io.github.consenlabs.android:token-core`.
- `tcx-wasm` has a separate crate/package version in
  [`token-core/tcx-wasm/Cargo.toml`](./token-core/tcx-wasm/Cargo.toml).

## Unreleased

### Documentation

- Reworked the root README files as current monorepo entrypoints.
- Reworked `token-core` and `imkey-core` README files to clarify package
  boundaries and current documentation paths.
- Added build, test, release, support, security, and compatibility documents for
  external contributors.

## 2.8.4

- Current root version recorded in [`VERSION`](./VERSION). Add release notes
  here before publishing new mobile artifacts from this version line.
