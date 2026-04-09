# AGENTS.md

This file provides working guidance for coding agents in `/Users/xyz/Code/token-core-monorepo`.

## Project Structure & Module Organization
- Rust workspace managed by `Cargo.toml` at the root; crates live under `token-core/*`, `token-core/tcx-libs/*`, and `imkey-core/*`.
- Docs live in `doc/`. CI config and PR templates live in `.github/`.
- Mobile build scripts live in `script/`. Common build shortcuts are defined in `Makefile`.

## Build, Test, and Development Commands
- Toolchain is pinned via `rust-toolchain.toml` to `nightly-2023-06-15`.
- Verify toolchain/components with `rustup show` and `rustup component add rustfmt clippy`.
- Build the whole workspace with `cargo build`.
- Build TokenCore specifically with `make build-tcx`.
- Build the protobuf crate with `make build-tcx-proto`.
- Run checks with `make check-tcx`.
- Run all tests with `cargo test`.
- For faster crypto-heavy tests, use `KDF_ROUNDS=1 cargo test`.
- Run targeted suites with `make test-tcx` and `make test-ikc`.
- Mobile/local packaging scripts: `script/build-android-local.sh` and `script/build-ios-local.sh`.

## Coding Style & Naming Conventions
- Use standard Rust style with 4-space indentation.
- **After every code change, run `cargo fmt --all` and verify with `cargo fmt -- --check` before finishing.** This is a mandatory step, not optional.
- Keep lint output clean with `cargo clippy --all-targets --all-features -- -D warnings`.
- Use `snake_case` for modules, files, and functions.
- Use `UpperCamelCase` for structs, enums, and traits.
- Use `SCREAMING_SNAKE_CASE` for constants.
- Keep crate and module paths aligned with directory names, for example `token-core/tcx-crypto/src/...`.

## Testing Guidelines
- Prefer unit tests in `#[cfg(test)] mod tests` inside `src/`.
- Use integration tests in `tests/` when behavior spans crate boundaries.
- Keep tests deterministic and avoid network or external I/O.
- Use `KDF_ROUNDS=1` when speeding up password/KDF-heavy test paths.
- Add or update tests alongside bug fixes and new features.
- Prioritize coverage for signing flows, key derivation, serialization, and migration edge cases.

## Commit & Pull Request Guidelines
- Follow conventional commit prefixes seen in repo history, such as `feat:`, `fix:`, `chore:`, and `CI:`.
- Include Jira IDs when applicable, for example `feat: add xxx [R2D2-12345]`.
- Keep PRs focused and explain motivation, scope, and test plan.
- Use `.github/PULL_REQUEST_TEMPLATE.md` when preparing PR descriptions.
- Include issue links and screenshots when they materially help review.
- Complete platform-specific and security checklist items before merging.

## WASM API Sync Convention
- When modifying `#[wasm_bindgen]` exports in `token-core/tcx-wasm/src/lib.rs` or `types.rs`, **always** update the wasm example (`examples/wasm/`) and its `README.md` accordingly.
- Detailed rules and the full API checklist are in `.cursor/rules/tcx-wasm-api-sync.mdc`.

## Security & Configuration Tips
- Never commit secrets, private keys, mnemonic phrases, or keystores.
- Treat signing, key management, serialization, and migration changes as security-sensitive.
- For iOS and Android builds, install the required Rust targets and platform SDKs first.
- Follow environment notes in `script/*`, including OpenSSL-related setup when required.
