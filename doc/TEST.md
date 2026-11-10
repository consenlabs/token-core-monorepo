# Test Guide

This guide defines the test boundary used by local contributors and CI.

## Fast Host-Safe Path

Run the standard host-safe verification from the repository root:

```bash
make test-workspace
```

This target:

1. Compiles all workspace test targets with `cargo test --workspace --no-run`.
2. Runs the TokenCoreX test suite with `make test-tcx`.
3. Runs the imKeyCore host-safe subset with `make test-ikc`.
4. Runs the npm JS adapter/session tests with `make test-npm` (Node.js 22 or newer).

Run this target separately from other native TCX integration-test processes;
the legacy harness shares a temporary wallet directory across processes.

## TokenCoreX Tests

```bash
make test-tcx
```

The target expands to:

```bash
MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 \
  cargo test --workspace --exclude 'ikc*' --exclude 'coin*'
```

This covers software-wallet crates, integration tests, and doc tests. Migration
tests may run for more than 60 seconds; that warning is not automatically a
hang.

`KDF_ROUNDS=1` is used only to reduce local/CI test runtime. It is not a
production default.

## imKeyCore Host-Safe Tests

```bash
make test-ikc
```

The target runs `ikc-common` (including a loopback HTTP mock), `ikc-proto`,
device upgrade contracts, API compatibility checks, callback/transport worker
tests and `make test-coin-host`. The coin runner uses an explicit list of
hardware-independent golden vectors and async transport mocks, and fails when
a listed test is missing. This subset requires neither a real device nor an
external TSM service; the HTTP mock needs permission to bind a loopback socket.

## Hardware Tests

```bash
make test-hardware
```

Hardware tests require:

- A connected imKey device.
- Device authorization where the test flow asks for it.
- Serial execution, which the Makefile enforces with `--test-threads=1`.

Treat tests as hardware tests when they call any of the following:

- `bind_test()`
- `hid_connect(...)`
- `send_apdu(...)`
- Address display, xpub retrieval, hardware signing, device management,
  binding, COS, or app management flows.

Do not hide hardware requirements by silently skipping tests. Keep host-safe and
hardware coverage separate.

## WebAssembly Tests

```bash
make test-wasm
```

This target checks both WASM crates for `wasm32-unknown-unknown` and compiles
native `tcx-wasm` test targets. Run actual WASM and package tests separately:

```bash
make test-wasm-node
make test-wasm-browser  # requires Chrome/Chromedriver
make test-npm
make test-npm-package
```

These tests use mock devices. Browser tests verify WASM exports and session
behavior, not real WebUSB permissions or physical firmware/signing flows.

Use the browser example for interactive validation:

```bash
npm ci --prefix examples/wasm
make dev-wasm
```

Then open `http://localhost:3000`.

## CI Gates

The GitHub Actions workflow [`../.github/workflows/run-unittest.yml`](../.github/workflows/run-unittest.yml)
runs:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --no-run`
- `make test-tcx`
- `make test-ikc`
- `make test-wasm`
- Four KDF API feature configurations
- WASM Node/Chrome smoke tests and the packed npm consumer
- npm JS tests and Android/Swift FFI host mocks
- Release policy, AAR packaging policy and local Markdown links
- `cargo-deny` advisories, licenses, and sources checks

Run the narrowest meaningful local test first, then broaden to
`make test-workspace` for shared behavior or release-facing changes.

## Fixture Policy

Fixtures under `token-core/test-data` and `imkey-core/test-data` are
compatibility-sensitive. Do not update them unless the expected wallet behavior
or migration output intentionally changes and the change is documented in the
test.
