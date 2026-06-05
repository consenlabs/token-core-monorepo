# Quality Debt Register

This document explains the current CI quality exceptions so contributors can
distinguish intentional compatibility debt from accidental silence.

## Clippy Allowlist

The CI clippy job runs `cargo clippy --workspace --all-targets -- -D warnings`
without any clippy allowlist. New warnings fail CI.

Historical clippy debt was cleared by converting mechanical style issues,
`Option` control flow, address `Display` implementations, FFI safety docs, test
initializers, and API-adjacent slice signatures to warning-free code. Do not
add new clippy allows unless the compatibility reason is documented here and a
removal path is clear.

## Cargo Deny Exceptions

`cargo-deny` is enabled in CI for advisories, licenses, and sources. The
advisory exceptions in `deny.toml` are intentionally documented because they are
not direct patch-level upgrades.

| Advisory | Crate | Current dependency path | Why ignored for now | Resolution path |
| -------- | ----- | ----------------------- | ------------------- | --------------- |
| `RUSTSEC-2023-0071` | `rsa` | Direct dependency of `ikc-device` | The tested newer `rsa 0.10.0-rc.18` was still affected; no safe patched version was available when recorded. | Re-check upstream `rsa`; migrate only when a patched version exists and binding-code encryption compatibility is verified. |
| `RUSTSEC-2024-0370` | `proc-macro-error` | Legacy Filecoin `forest_cid` / `cid` / `multihash` stack | Removing it requires a Filecoin codec dependency migration. | Migrate Filecoin address/message codec stack with Filecoin golden vectors. |
| `RUSTSEC-2024-0436` | `paste` | Substrate `sp-core 41.0.0` stack | No simple direct dependency update removes it from the current Substrate stack. | Upgrade or replace Substrate dependencies as a dedicated compatibility project. |
| `RUSTSEC-2025-0161` | `libsecp256k1` | Substrate `sp-core 41.0.0` stack | The advisory has no safe direct upgrade and implies a larger Substrate/k256 migration. | Review Substrate crypto stack and migrate away from the affected dependency path. |

## Policy

- Do not add new clippy allows without documenting why they are needed.
- Do not remove a cargo-deny advisory ignore unless the dependency path is gone
  or a compatible patched upgrade has been verified.
- For address, transaction, signature, keystore, Protobuf, or C ABI changes,
  keep golden vectors or compatibility assertions with the cleanup.

## Resolved Exceptions

| Advisory | Former crate | Resolution |
| -------- | ------------ | ---------- |
| `RUSTSEC-2020-0036` | `failure` via `bch_addr` / `cash_addr` | Replaced `bch_addr` with `bitcoincash-addr` in `tcx-btc-kin` and `coin-bch`; retained legacy/cashaddr conversion behavior and no-prefix cashaddr output. |
| `RUSTSEC-2023-0037` | `xsalsa20poly1305` | Replaced with `crypto_secretbox 0.1.1`; preserved `tcx-substrate` keystore ciphertext/decryption compatibility through existing v2/v3 fixture tests. |
