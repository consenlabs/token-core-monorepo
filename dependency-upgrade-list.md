# Dependency Upgrade Report

Generated after upgrading the remaining 12 crates and pinning registry dependency declarations to exact `=x.y.z` requirements.

## Result

- `cargo update --verbose` result: `Locking 0 packages to latest compatible versions`; no `behind latest` entries remain.
- Exact version scan over all `Cargo.toml` dependency sections: 0 non-exact version declarations.
- Workspace registry dependencies reported by `cargo metadata --no-deps` also all use exact requirements beginning with `=`.
- `generic-array 0.14.9` requires a local `[patch.crates-io]` for `crypto-common 0.1.7`, because upstream `crypto-common 0.1.7` exact-pins `generic-array = 0.14.7`.
- `forest_message`, `forest_crypto`, and unused `crypto-mac` were removed to clear old transitive constraints.

## Additional 12 Dependencies Completed

| Dependency | Previous current | Current/latest | Note |
|---|---:|---:|---|
| `bitstream-io` | `2.6.0` | `4.10.0` | 直接依赖，已适配 bitstream-io 4 API |
| `blst` | `0.3.3` | `0.3.16` | 直接依赖；移除 Filecoin 侧旧 forest BLS 约束后完成 |
| `bytebuffer` | `0.2.1` | `2.3.0` | 直接依赖 |
| `ed25519-bip32` | `0.3.2` | `0.4.1` | 直接依赖 |
| `ed25519-zebra` | `4.0.3` | `4.2.0` | 传递依赖，Cargo.lock 已解析到最新 |
| `ethereum-types` | `0.14.1` | `0.16.0` | 直接依赖，已适配 uint API 变化 |
| `generic-array` | `0.14.7` | `0.14.9` | 传递依赖；通过本地 patch crypto-common 0.1.7 解除上游精确锁定 |
| `keccak-hash` | `0.10.0` | `0.12.0` | 直接依赖 |
| `rand` | `0.8.6` | `0.10.1` | 直接依赖；Cargo.lock 仍保留 0.8/0.9 作为上游传递依赖 |
| `rlp` | `0.5.2` | `0.6.1` | 直接依赖/传递依赖已解析到 0.6.1 |
| `rsa` | `0.7.2` | `0.9.10` | 直接依赖，已切换到 Pkcs1v15Encrypt API |
| `subtle` | `2.4.1` | `2.6.1` | 传递依赖，移除旧 crypto-mac 约束后完成 |

## Direct Manifest Changes

Changed dependency names: 76

| Dependency | Before | After |
|---|---:|---:|
| `aes` | `=0.8.3` | `=0.9.0` |
| `anyhow` | `=1.0.79` | `=1.0.102` |
| `base32` | `=0.4.0` | `=0.5.1` |
| `base64` | `0.22, =0.13.1` | `=0.22.1` |
| `bech32` | `=0.9.1` | `=0.11.1` |
| `bitcoin` | `=0.29.2` | `=0.32.9` |
| `bitcoin_hashes` | `=0.11.0` | `=0.20.0` |
| `bitstream-io` | `=2.3.0` | `=4.10.0` |
| `blake2b_simd` | `=1.0.1` | `=1.0.4` |
| `byteorder` | `1, =1.4.3` | `=1.5.0` |
| `bytes` | `=1.4.0` | `=1.11.1` |
| `cargo-husky` | `1` | `=1.5.0` |
| `cbc` | `=0.1.2` | `=0.2.1` |
| `cc` | `1.0.50, >= 1.0.28` | `=1.2.62` |
| `crc` | `=3.2.1` | `=3.4.0` |
| `crypto-mac` | `=0.11.1` | `-` |
| `ctr` | `=0.9.2` | `=0.10.1` |
| `derivation-path` | `0.2.0` | `=0.2.0` |
| `digest` | `=0.10.6` | `=0.11.3` |
| `ed25519-dalek` | `2.1.0, =2.1.0` | `=2.2.0` |
| `ethereum-types` | `0.14.0, =0.14.0` | `=0.16.0` |
| `forest_crypto` | `0.5.3, =0.5.3` | `-` |
| `forest_message` | `=0.7.2` | `-` |
| `hex` | `0.4.2, =0.4.3` | `=0.4.3` |
| `hex-literal` | `=0.3.4` | `=1.1.0` |
| `hidapi` | `=2.0.2` | `=2.6.6` |
| `hkdf` | `=0.12.3` | `=0.13.0` |
| `hmac` | `0.12.0, =0.12.1` | `=0.13.0` |
| `hmac-sha256` | `=1.1.6` | `=1.1.14` |
| `http-body-util` | `-` | `=0.1.3` |
| `hyper` | `=0.14.23` | `=1.9.0` |
| `hyper-timeout` | `=0.4.1` | `=0.5.2` |
| `hyper-tls` | `=0.5.0` | `=0.6.0` |
| `hyper-util` | `-` | `=0.1.20` |
| `lazy_static` | `1.4.0, =1.4.0` | `=1.5.0` |
| `libc` | `=0.2.140` | `=0.2.186` |
| `log` | `=0.4.17` | `=0.4.29` |
| `mockall` | `=0.11.3` | `=0.14.0` |
| `multihash` | `=0.18.1` | `=0.19.5` |
| `multihash-codetable` | `-` | `=0.2.2` |
| `num-bigint` | `0.2, =0.4.3` | `=0.2.6, =0.4.6` |
| `num-integer` | `0.1, =0.1.45` | `=0.1.46` |
| `num-traits` | `0.2, =0.2.15` | `=0.2.19` |
| `parity-scale-codec` | `-` | `=3.7.5` |
| `parking_lot` | `=0.12.1` | `=0.12.5` |
| `pbkdf2` | `=0.11.0` | `=0.13.0` |
| `proc-macro2` | `1` | `=1.0.106` |
| `prost` | `=0.11.2` | `=0.14.3` |
| `prost-build` | `=0.11.4` | `=0.14.3` |
| `prost-types` | `=0.11.2` | `=0.14.3` |
| `quote` | `1` | `=1.0.45` |
| `rand` | `0.6, =0.8.5` | `=0.10.1, =0.6.5` |
| `rand_core` | `0.5, 0.6.4` | `=0.5.1, =0.6.4` |
| `regex` | `=1.9.3` | `=1.12.3` |
| `schnorrkel` | `=0.9.1` | `=0.11.5` |
| `scrypt` | `=0.10.0` | `=0.12.0` |
| `secp256k1` | `=0.24.3` | `=0.31.1` |
| `serde` | `1.0, =1.0.147` | `=1.0.228` |
| `serde_derive` | `=1.0.147` | `=1.0.228` |
| `serde_json` | `=1.0.89` | `=1.0.149` |
| `serde_test` | `1.0` | `=1.0.177` |
| `serial_test` | `=2.0.0` | `=3.4.0` |
| `sha1` | `=0.6.1` | `=0.11.0` |
| `sha2` | `0.10.1, =0.10.6` | `=0.11.0` |
| `sp-core` | `=7.0.0` | `=41.0.0` |
| `sp-keyring` | `=7.0.0` | `=47.0.0` |
| `sp-runtime` | `=7.0.0` | `=47.0.0` |
| `ssz_rs` | `=0.8.0` | `=0.9.0` |
| `ssz_rs_derive` | `=0.8.0` | `=0.9.0` |
| `strum` | `=0.25.0` | `=0.28.0` |
| `syn` | `1` | `=1.0.109` |
| `thiserror` | `=1.0.56` | `=2.0.18` |
| `tiny-bip39` | `=1.0.0` | `=2.0.0` |
| `tokio` | `=1.28.2` | `=1.52.3` |
| `uuid` | `=1.2.2` | `=1.23.1` |
| `xsalsa20poly1305` | `=0.9.0` | `=0.9.1` |

## Current Cargo.toml Registry Requirements

Current registry dependency names declared in Cargo.toml files: 94

| Dependency | Requirement |
|---|---:|
| `aes` | `=0.9.0` |
| `anyhow` | `=1.0.102` |
| `base32` | `=0.5.1` |
| `base58` | `=0.2.0` |
| `base64` | `=0.22.1` |
| `bch_addr` | `=0.1.0` |
| `bech32` | `=0.11.1` |
| `bitcoin` | `=0.32.9` |
| `bitcoin_hashes` | `=0.20.0` |
| `bitstream-io` | `=4.10.0` |
| `blake2b-rs` | `=0.2.0` |
| `blake2b_simd` | `=1.0.4` |
| `blst` | `=0.3.16` |
| `bytebuffer` | `=2.3.0` |
| `byteorder` | `=1.5.0` |
| `bytes` | `=1.11.1` |
| `cargo-husky` | `=1.5.0` |
| `cbc` | `=0.2.1` |
| `cc` | `=1.2.62` |
| `crc` | `=3.4.0` |
| `ctr` | `=0.10.1` |
| `derivation-path` | `=0.2.0` |
| `digest` | `=0.11.3` |
| `ed25519-bip32` | `=0.4.1` |
| `ed25519-dalek` | `=2.2.0` |
| `ethereum-types` | `=0.16.0` |
| `fff_derive` | `=0.2.2` |
| `forest_address` | `=0.3.2` |
| `forest_bigint` | `=0.1.4` |
| `forest_cid` | `=0.3.0` |
| `forest_encoding` | `=0.2.2` |
| `forest_vm` | `=0.3.2` |
| `generic-array` | `=0.14.9` |
| `hex` | `=0.4.3` |
| `hex-literal` | `=1.1.0` |
| `hidapi` | `=2.6.6` |
| `hkdf` | `=0.13.0` |
| `hmac` | `=0.13.0` |
| `hmac-sha256` | `=1.1.14` |
| `http-body-util` | `=0.1.3` |
| `hyper` | `=1.9.0` |
| `hyper-timeout` | `=0.5.2` |
| `hyper-tls` | `=0.6.0` |
| `hyper-util` | `=0.1.20` |
| `jsonrpc-core` | `=18.0.0` |
| `keccak-hash` | `=0.12.0` |
| `lazy_static` | `=1.5.0` |
| `libc` | `=0.2.186` |
| `linked-hash-map` | `=0.5.6` |
| `log` | `=0.4.29` |
| `mockall` | `=0.14.0` |
| `multihash` | `=0.19.5` |
| `multihash-codetable` | `=0.2.2` |
| `num-bigint` | `=0.2.6, =0.4.6` |
| `num-integer` | `=0.1.46` |
| `num-traits` | `=0.2.19` |
| `parity-scale-codec` | `=3.7.5` |
| `parking_lot` | `=0.12.5` |
| `pbkdf2` | `=0.13.0` |
| `proc-macro2` | `=1.0.106` |
| `prost` | `=0.14.3` |
| `prost-build` | `=0.14.3` |
| `prost-types` | `=0.14.3` |
| `quote` | `=1.0.45` |
| `rand` | `=0.10.1, =0.6.5` |
| `rand_core` | `=0.5.1, =0.6.4` |
| `regex` | `=1.12.3` |
| `rlp` | `=0.6.1` |
| `rsa` | `=0.9.10` |
| `rustc-hex` | `=2.1.0` |
| `schnorrkel` | `=0.11.5` |
| `scrypt` | `=0.12.0` |
| `secp256k1` | `=0.31.1` |
| `serde` | `=1.0.228` |
| `serde_derive` | `=1.0.228` |
| `serde_json` | `=1.0.149` |
| `serde_test` | `=1.0.177` |
| `serial_test` | `=3.4.0` |
| `sha1` | `=0.11.0` |
| `sha2` | `=0.11.0` |
| `sp-core` | `=41.0.0` |
| `sp-keyring` | `=47.0.0` |
| `sp-runtime` | `=47.0.0` |
| `ssz_rs` | `=0.9.0` |
| `ssz_rs_derive` | `=0.9.0` |
| `strum` | `=0.28.0` |
| `syn` | `=1.0.109` |
| `thiserror` | `=2.0.18` |
| `tiny-bip39` | `=2.0.0` |
| `tiny-keccak` | `=2.0.2` |
| `tokio` | `=1.52.3` |
| `typenum` | `=1.20.0` |
| `uuid` | `=1.23.1` |
| `xsalsa20poly1305` | `=0.9.1` |

## Still Behind crates.io Latest

None according to `cargo update --verbose` on 2026-05-21.

## Cargo.lock Resolved Version Changes

Changed resolved package names: 57

| Package | Before | After |
|---|---:|---:|
| `base64` | `0.12.3, 0.22.1` | `0.22.1` |
| `bitstream-io` | `2.6.0` | `4.10.0` |
| `bls-signatures` | `0.9.0` | `-` |
| `blst` | `0.3.3` | `0.3.16` |
| `blstrs` | `0.2.2` | `-` |
| `bytebuffer` | `0.2.1` | `2.3.0` |
| `byteorder` | `0.3.13, 1.5.0` | `1.5.0` |
| `chacha20` | `-` | `0.10.0` |
| `crypto-mac` | `0.11.1, 0.8.0` | `-` |
| `cryptoxide` | `0.3.6` | `0.4.4` |
| `darling` | `0.10.2` | `-` |
| `darling_core` | `0.10.2` | `-` |
| `darling_macro` | `0.10.2` | `-` |
| `der` | `0.6.1, 0.7.10` | `0.7.10` |
| `derive_builder` | `0.9.0` | `-` |
| `derive_builder_core` | `0.9.0` | `-` |
| `ed25519-bip32` | `0.3.2` | `0.4.1` |
| `ed25519-zebra` | `4.0.3` | `4.2.0` |
| `ethbloom` | `0.13.0` | `0.14.1` |
| `ethereum-types` | `0.14.1` | `0.16.0` |
| `foldhash` | `0.1.5` | `0.1.5, 0.2.0` |
| `forest_crypto` | `0.5.3` | `-` |
| `forest_message` | `0.7.2` | `-` |
| `generic-array` | `0.12.4, 0.14.7` | `0.12.4, 0.14.9` |
| `getrandom` | `0.1.16, 0.2.17, 0.3.4, 0.4.2` | `0.2.17, 0.3.4, 0.4.2` |
| `groupy` | `0.3.1` | `-` |
| `hashbrown` | `0.13.2, 0.14.5, 0.15.5, 0.17.1` | `0.13.2, 0.15.5, 0.16.1, 0.17.1` |
| `hmac` | `0.12.1, 0.13.0, 0.8.1` | `0.12.1, 0.13.0` |
| `hmac-drbg` | `0.3.0` | `-` |
| `ident_case` | `1.0.1` | `-` |
| `impl-codec` | `0.6.0, 0.7.1` | `0.7.1` |
| `impl-rlp` | `0.3.0` | `0.4.0` |
| `impl-serde` | `0.4.0, 0.5.0` | `0.5.0` |
| `keccak-hash` | `0.10.0` | `0.12.0` |
| `libsecp256k1` | `0.6.0, 0.7.2` | `0.7.2` |
| `libsecp256k1-core` | `0.2.2, 0.3.0` | `0.3.0` |
| `libsecp256k1-gen-ecmult` | `0.2.1, 0.3.0` | `0.3.0` |
| `libsecp256k1-gen-genmult` | `0.2.1, 0.3.0` | `0.3.0` |
| `no_std_io2` | `-` | `0.9.4` |
| `pem-rfc7468` | `0.6.0` | `0.7.0` |
| `pkcs1` | `0.4.1` | `0.7.5` |
| `pkcs8` | `0.10.2, 0.9.0` | `0.10.2` |
| `primitive-types` | `0.12.2, 0.13.1` | `0.13.1, 0.14.0` |
| `rand` | `0.7.3, 0.8.6, 0.9.4` | `0.10.1, 0.8.6, 0.9.4` |
| `rand_chacha` | `0.2.2, 0.3.1, 0.9.0` | `0.3.1, 0.9.0` |
| `rand_core` | `0.5.1, 0.6.4, 0.9.5` | `0.10.1, 0.6.4, 0.9.5` |
| `rand_hc` | `0.2.0` | `-` |
| `rand_xorshift` | `0.2.0` | `-` |
| `rlp` | `0.5.2` | `0.6.1` |
| `rsa` | `0.7.2` | `0.9.10` |
| `signature` | `1.6.4, 2.2.0` | `2.2.0` |
| `spki` | `0.6.0, 0.7.3` | `0.7.3` |
| `strsim` | `0.9.3` | `-` |
| `subtle` | `2.4.1` | `2.6.1` |
| `uint` | `0.10.0, 0.9.5` | `0.10.0` |
| `wasi` | `0.11.1+wasi-snapshot-preview1, 0.9.0+wasi-snapshot-preview1` | `0.11.1+wasi-snapshot-preview1` |
| `zmij` | `1.0.21` | `-` |
