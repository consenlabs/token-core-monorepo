# Phase 7 / #191 Follow-up

## Scope

- BTC/DOGE async signing builds change outputs through its supplied transport; BCH and both LTC async signing branches derive change through async helpers. Existing synchronous signing entry points and APDU protocol are unchanged. Only necessary output handling from `c010d6f9` was extracted.
- Every public async `ikc-wasm` operation owns a Rust device session until completion. Transport, TSM, binding storage and transport profile are captured before waiting. The 37 public async exports do not call one another, avoiding recursive acquisition.
- npm and browser-example clients bind their own context inside a shared session queue. Lock order is JS runtime, JS transport/device session, Rust session, then single APDU. No layer acquires an outer lock from an inner one. Same-transport clients share a device queue even across runtime objects; a shared runtime also serializes different transports because its binding state is global.
- Low-level transport callbacks must not reenter public device operations. Raw transport access and separate native synchronous callers remain explicit low-level boundaries; native async HID/callback adapters move the unchanged blocking operation to a worker. Dropping a future does not cancel an already running native command.
- Mobile FFI changes are limited to imKey ownership bridges, headers and tests, based on the FFI portion of `1cf20efc`. No other signing/security policy changes from that commit are included.

## Test Entrypoints

- `make test-coin-host`: reviewed exact-name coin test allowlist, including async mock change derivation. Missing names fail rather than silently selecting zero tests. Hardware tests keep their original attributes and remain under `make test-hardware`.
- `make test-ikc`: adds callback tests, native worker tests and coin host tests to existing checks.
- `make test-npm`: JS WebUSB, TSM and complete-operation multi-client session tests, including failure recovery.
- `JNA_JAR=/path/to/jna.jar make test-mobile-ffi`: Android SDK/example JNA ownership and Swift ownership mocks. `JNA_COMPILE_JAR` optionally checks compilation against an older JNA API.
- `make test-wasm-node`: actual wasm exports in Node for imKey session concurrency/failure recovery and TokenCore wasm tests.
- `make test-wasm-browser`: the same imKey export tests in headless Chrome, including a signing operation concurrent with `get_seid` and transport snapshot isolation. No real USB device is required.

The wasm compiler defaults to Homebrew LLVM when available, otherwise `clang` on PATH. The archiver defaults to Rust's `llvm-tools-preview` component (`rustup component add llvm-tools-preview`). `WASM_CC` and `WASM_AR` remain overridable. Apple `/usr/bin/ar` can compile an archive but fails to index wasm secp256k1 symbols for linking; use `llvm-ar` for executable tests.

## Integration Notes

Phases 1-6 provide the path, public Rust API, KDF and packaging contracts inherited
by this phase. `make test-npm` runs JS tests; `make test-npm-package` builds both
WASM modules, packs the aggregate npm package and exercises a tarball consumer.
The aggregate manifest is maintained in `publish/npm/package.json` and must not
be replaced with a single-crate wasm-pack manifest. The phase 5 `test-kdf`
targets and phase 6 portable Android/AAR/mobile smoke gates remain available;
FFI host mocks do not replace device integration.

## Local Validation

With `CARGO_TARGET_DIR=/private/tmp/token-quality-target KDF_ROUNDS=1`:

- Passed 42 exact-name coin host tests, 3 callback tests (including 100,000 borrowed-input calls), and the native worker yield/failure recovery test.
- Passed all 9 npm JS tests, Android SDK/example ownership mocks (JNA 5.6 compile API, 5.10 host runtime) and Swift ownership/parse checks.
- Passed `cargo check -p ikc-wasm --target wasm32-unknown-unknown`, 2 imKey + 2 TokenCore wasm Node tests and 2 imKey headless Chrome tests with `/usr/bin/clang` and Rust `llvm-ar`.
- Passed scoped Rust formatting and `git diff --check`.
- Full `make test-ikc` stopped at the existing local TCP server test because sandbox networking denied the bind. A targeted clippy run found a new test-only no-op waker lint, fixed with `Waker::noop()`; the worker test was rerun successfully. Full workspace/clippy and final integrated gates are left to the phase integrator as requested. No real-device, Android/iOS app integration or Next.js build was run.
