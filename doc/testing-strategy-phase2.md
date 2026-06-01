# Phase 2 Testing Strategy

This document records the phase 2 test boundaries and the initial `tcx-wasm`
integration decision.

## Test Layers

### Host unit tests

Default local and CI tests should not require a real imKey device.

Run:

```bash
make test-tcx
make test-ikc
make test-workspace
```

`make test-tcx` runs the TokenCoreX workspace slice and excludes imKey crates.
`make test-ikc` runs the imKey host-safe subset:

- `ikc-common`, excluding `https::test::post_test` because it depends on TSM network access.
- `ikc-proto`.
- focused `ikc` host tests for API-boundary compatibility such as `SignParam.seg_wit` defaulting.

`make test-workspace` first compiles every workspace test target with
`cargo test --workspace --no-run`, then runs the host-safe test targets above.

### Hardware tests

Hardware tests are any tests that connect to a real imKey device or require APDU
confirmation. Typical markers in the code are:

- `bind_test()`
- `hid_connect(...)`
- `send_apdu(...)`
- tests that require applet selection, xpub reads, address display, signing, app
  management, binding, activation, or COS operations.

Run them explicitly and serially:

```bash
make test-hardware
```

The target uses `--test-threads=1 --nocapture` so device prompts can be handled
one by one.

### Wasm tests

`tcx-wasm` is now a workspace member and is validated separately from native
TokenCoreX tests:

```bash
make test-wasm
```

The wasm check uses:

- target: `wasm32-unknown-unknown`
- default C compiler: `/opt/homebrew/opt/llvm/bin/clang`
- `CFLAGS_wasm32_unknown_unknown=-Wno-implicit-function-declaration`

The compiler and flags are required because `secp256k1-sys` builds C code for
wasm and Apple clang does not provide a usable wasm target in this environment.
Both values can be overridden with `WASM_CC=...` and `WASM_CFLAGS=...`.

### Integration and release smoke tests

Integration tests are native TokenCoreX tests under `token-core/tcx/tests`.
Release smoke tests should be small command-level checks that confirm:

- `cargo test --workspace --no-run` still compiles every test target.
- `make test-tcx` passes without imKey hardware.
- `make test-ikc` passes without imKey hardware.
- `make test-wasm` passes with a wasm-capable clang.
- `make test-hardware` remains explicit and serial.

## `feat/keyless` / `tcx-wasm` Evaluation

The current phase 2 branch imports the Rust `token-core/tcx-wasm` crate and the
browser example app from `feat/keyless`.

Included:

- `token-core/tcx-wasm/Cargo.toml`
- `token-core/tcx-wasm/src/lib.rs`
- `token-core/tcx-wasm/src/types.rs`
- `token-core/tcx-wasm/src/nostr.rs`
- `examples/wasm`, a Next.js browser example used to exercise the generated
  wasm package.

Not included in this step:

- `doc/architecture-wasm-web-support.md`, because this document records the
  narrower phase 2 integration status.
- `web-core` and `openspec/changes/web-core-wasm` from `feat/wasm-verify`,
  because those represent a broader web-core proposal and should be reviewed as
  a separate merge unit.

Native TokenCoreX impact:

- `tcx-wasm` depends on existing `tcx-*` crates through normal path
  dependencies.
- The wasm-specific random-source features are enabled from `tcx-wasm`; native
  crates do not need code changes for this integration.
- `tcx-wasm` uses exact dependency versions aligned with the phase 1 dependency
  upgrade policy.

Open follow-up:

- If `web-core` is still desired, review it independently from the minimal
  `tcx-wasm` plus `examples/wasm` workspace inclusion.
