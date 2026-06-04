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

The target runs:

```bash
MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 \
  cargo test -p ikc-common -- --skip https::test::post_test
MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 cargo test -p ikc-proto
MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 cargo test -p ikc normalize_sign_param
```

This subset avoids real hardware and avoids the external TSM network test.

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

This target checks `tcx-wasm` for `wasm32-unknown-unknown` and compiles native
test targets without running browser tests.

Use the browser example for interactive validation:

```bash
make build-wasm
make dev-wasm
```

Then open `http://localhost:3000`.

## CI Gates

The GitHub Actions workflow [`../.github/workflows/run-unittest.yml`](../.github/workflows/run-unittest.yml)
runs:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets` with the repository's current allowlist
- `cargo test --workspace --no-run`
- `make test-tcx`
- `make test-ikc`
- `make test-wasm`
- `cargo-deny` advisories, licenses, and sources checks

Run the narrowest meaningful local test first, then broaden to
`make test-workspace` for shared behavior or release-facing changes.

## Fixture Policy

Fixtures under `token-core/test-data` and `imkey-core/test-data` are
compatibility-sensitive. Do not update them unless the expected wallet behavior
or migration output intentionally changes and the change is documented in the
test.
