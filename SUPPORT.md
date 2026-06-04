# Support Policy

This repository is maintained as an open-source wallet core codebase. Support is
focused on buildability, testability, release artifacts, API behavior, and
security-sensitive wallet logic.

## Supported Questions

Use GitHub issues or pull requests for:

- Reproducible build failures from a clean clone.
- Test failures that do not require a private environment.
- Documentation gaps in supported build, test, release, or integration paths.
- Bugs in address derivation, transaction signing, message signing, migration,
  Protobuf API behavior, C ABI behavior, or `tcx-wasm`.
- Release artifact problems for Android, iOS, or wasm package files.

Use `sec@token.im` instead of public GitHub issues for suspected security
vulnerabilities. See [`SECURITY.md`](./SECURITY.md).

## Not Covered

The maintainers do not provide general support for:

- Private wallet recovery, account recovery, or seed phrase handling.
- End-user imToken or imKey product support.
- Custom chain integrations without a focused technical issue or pull request.
- Private mobile app integration debugging.
- Hardware tests when no authorized imKey device is available.

For product help, use the imToken help center:
https://support.token.im/hc/en-us

## Maintained Surfaces

| Surface | Support expectation |
| ------- | ------------------- |
| `token-core` | Software-wallet core, C ABI, Protobuf API, chain signing behavior |
| `imkey-core` | imKey hardware-wallet core, APDU command wrappers, host-safe tests |
| `tcx-wasm` | Browser/WebAssembly subset and example integration |
| `publish/android` | Android AAR packaging and Maven Central publishing configuration |
| iOS release workflow | TokenCoreX and imKeyCoreX XCFramework packaging |
| Documentation | Build, test, release, security, support, and compatibility docs |

## Issue Quality

A useful issue includes:

- Repository commit, branch, or release tag.
- Host OS and architecture.
- Rust version from `rustc --version --verbose`.
- Command that failed.
- Full relevant error output.
- Whether the issue reproduces after a clean checkout.
- Whether hardware, network, Android SDK/NDK, Xcode, wasm tooling, or release
  credentials are required.

For API behavior changes, include a minimal request payload and expected
response when possible. Do not include real mnemonics, private keys, production
keystores, or sensitive APDU logs.
