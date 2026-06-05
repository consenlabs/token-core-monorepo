# imKeyCore

`imkey-core` contains the hardware wallet side of this workspace. It wraps imKey
device communication, APDU transport, device management, and chain-specific
hardware signing commands behind a stable C ABI for mobile SDK integration.

The external API boundary is the `ikc` crate:

- C ABI entrypoint: `call_imkey_api(hex_str)`
- Request format: hex-encoded Protobuf `ImkeyAction`
- APDU bridge helpers: `get_apdu`, `set_apdu`, `get_apdu_return`,
  `set_apdu_return`, and `set_callback`
- Hardware boundary: functions that call `hid_connect` or `send_apdu` require a
  connected, authorized imKey device or a callback APDU channel.

## Crate Map

| Crate or path | Purpose |
| ------------- | ------- |
| [`ikc`](./ikc) | imKeyCore API wrapper and C ABI |
| [`ikc-proto`](./ikc-proto) | Protobuf-generated API types |
| [`ikc-common`](./ikc-common) | APDU builders, path validation, hash/crypto helpers, TSM client |
| [`ikc-transport`](./ikc-transport) | HID transport and APDU sending |
| [`ikc-device`](./ikc-device) | Device binding, activation, app management, certificates |
| [`ikc-wallet`](./ikc-wallet) | Chain-specific address and signing command wrappers |
| [`mobile-sdk`](./mobile-sdk/README.md) | Mobile SDK bridge code |
| [`blelibrary`](./blelibrary) | BLE libraries for Android and iOS |
| [`ikc-examples`](./ikc-examples) | Android and iOS example projects |

## Build

From the repository root:

```bash
cargo build -p ikc
```

For mobile release artifacts, use the workspace release documentation instead
of running crate-level commands directly:

- Android: [`../publish/android/README.md`](../publish/android/README.md)
- iOS release workflow: [`../doc/RELEASE.md`](../doc/RELEASE.md)
- Build prerequisites: [`../doc/BUILD.md`](../doc/BUILD.md)

## Test

Host-safe tests do not require a physical imKey device:

```bash
make test-ikc
```

Hardware tests require a connected and authorized imKey device and run serially:

```bash
make test-hardware
```

Tests that call `bind_test()`, `hid_connect(...)`, or `send_apdu(...)` should be
treated as hardware tests. Do not skip these tests silently in CI; keep the
hardware boundary explicit.

See [`../doc/TEST.md`](../doc/TEST.md) for the current workspace test policy.

## Documentation

- [`ikc-docs/BUILD.zh.md`](./ikc-docs/BUILD.zh.md): historical imKeyCore build notes.
- [`ikc-docs/API.zh.md`](./ikc-docs/API.zh.md): imKeyCore API notes.
- [`ikc-docs/TECH.zh.md`](./ikc-docs/TECH.zh.md): architecture notes.
- [`ikc-docs/FAQ.md`](./ikc-docs/FAQ.md): imKeyCore FAQ.
- [`mobile-sdk/README.md`](./mobile-sdk/README.md): mobile SDK overview.
- [`../doc/COMPATIBILITY.md`](../doc/COMPATIBILITY.md): current compatibility matrix.

## Security

For vulnerability reports, follow the root policy in [`../SECURITY.md`](../SECURITY.md).

## License

Apache License, Version 2.0. See [`../LICENSE`](../LICENSE).
