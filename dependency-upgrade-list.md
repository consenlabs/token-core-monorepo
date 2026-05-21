# Dependency Upgrade Report

Generated after pinning external Cargo dependency declarations to exact `=x.y.z` versions.

## Direct Manifest Changes

Changed dependency names: 74

| Dependency | Before | After |
|---|---:|---:|
| `aes` | `=0.8.3` | `=0.9.0` |
| `anyhow` | `=1.0.79` | `=1.0.102` |
| `base32` | `=0.4.0` | `=0.5.1` |
| `base64` | `0.22, =0.13.1` | `=0.22.1` |
| `bech32` | `=0.9.1` | `=0.11.1` |
| `bitcoin` | `=0.29.2` | `=0.32.9` |
| `bitcoin_hashes` | `=0.11.0` | `=0.20.0` |
| `bitstream-io` | `=2.3.0` | `=2.6.0` |
| `blake2b_simd` | `=1.0.1` | `=1.0.4` |
| `byteorder` | `1, =1.4.3` | `=1.5.0` |
| `bytes` | `=1.4.0` | `=1.11.1` |
| `cargo-husky` | `1` | `=1.5.0` |
| `cbc` | `=0.1.2` | `=0.2.1` |
| `cc` | `1.0.50, >= 1.0.28` | `=1.2.62` |
| `crc` | `=3.2.1` | `=3.4.0` |
| `ctr` | `=0.9.2` | `=0.10.1` |
| `derivation-path` | `0.2.0` | `=0.2.0` |
| `digest` | `=0.10.6` | `=0.11.3` |
| `ed25519-dalek` | `2.1.0, =2.1.0` | `=2.2.0` |
| `ethereum-types` | `0.14.0, =0.14.0` | `=0.14.1` |
| `forest_crypto` | `0.5.3, =0.5.3` | `=0.5.3` |
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
| `rand` | `0.6, =0.8.5` | `=0.6.5, =0.8.6` |
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

## Still Behind crates.io Latest

Source: `cargo update --verbose` after the upgrade pass.

| Dependency | Current | Latest available | Note |
|---|---:|---:|---|
| `bitstream-io` | `2.6.0` | `4.10.0` | 直接依赖仍在 2.x 兼容线，4.x 为破坏性主版本 |
| `blst` | `0.3.3` | `0.3.16` | 由直接依赖及 Filecoin/BLS 链路共同约束 |
| `bytebuffer` | `0.2.1` | `2.3.0` | 直接依赖仍在 0.2 兼容线，2.x 为破坏性主版本 |
| `ed25519-bip32` | `0.3.2` | `0.4.1` | 直接依赖仍在 0.3 兼容线 |
| `ed25519-zebra` | `4.0.3` | `4.2.0` | Substrate sp-core 41.0.0 传递依赖约束 |
| `ethereum-types` | `0.14.1` | `0.16.0` | Ethereum 相关直接依赖仍在 0.14 兼容线 |
| `generic-array` | `0.14.7` | `0.14.9` | 传递依赖约束，Cargo 未解析到新 patch |
| `keccak-hash` | `0.10.0` | `0.12.0` | 直接依赖仍在 0.10 兼容线，0.12 为破坏性主版本 |
| `rand` | `0.8.6` | `0.10.1` | 多处直接/传递依赖仍在 0.8 兼容线 |
| `rlp` | `0.5.2` | `0.6.1` | Ethereum 相关直接/传递依赖仍在 0.5 兼容线 |
| `rsa` | `0.7.2` | `0.9.10` | ikc-device 直接依赖仍在 0.7 兼容线 |
| `subtle` | `2.4.1` | `2.6.1` | 传递依赖约束，Cargo 未解析到新 patch |

## Cargo.lock Resolved Version Changes

Changed resolved package names: 430

| Package | Before | After |
|---|---:|---:|
| `addr2line` | `0.19.0` | `0.25.1` |
| `adler` | `1.0.2` | `-` |
| `adler2` | `-` | `2.0.1` |
| `aes` | `0.8.3` | `0.9.0` |
| `ahash` | `0.7.7` | `0.8.12` |
| `aho-corasick` | `1.1.2` | `1.1.4` |
| `allocator-api2` | `-` | `0.2.21` |
| `android-tzdata` | `0.1.1` | `-` |
| `android_system_properties` | `0.1.5` | `-` |
| `ansi_term` | `0.12.1` | `-` |
| `anstyle` | `-` | `1.0.14` |
| `anyhow` | `1.0.79` | `1.0.102` |
| `ark-bls12-377` | `-` | `0.4.0` |
| `ark-bls12-381` | `-` | `0.4.0, 0.5.0` |
| `ark-ec` | `-` | `0.4.2, 0.5.0` |
| `ark-ed-on-bls12-381-bandersnatch` | `-` | `0.5.0` |
| `ark-ff` | `-` | `0.4.2, 0.5.0` |
| `ark-ff-asm` | `-` | `0.4.2, 0.5.0` |
| `ark-ff-macros` | `-` | `0.4.2, 0.5.0` |
| `ark-poly` | `-` | `0.4.2, 0.5.0` |
| `ark-serialize` | `-` | `0.4.2, 0.5.0` |
| `ark-serialize-derive` | `-` | `0.4.2, 0.5.0` |
| `ark-std` | `-` | `0.4.0, 0.5.0` |
| `ark-transcript` | `-` | `0.0.3` |
| `ark-vrf` | `-` | `0.5.0` |
| `array-bytes` | `4.2.0` | `6.2.3` |
| `arrayref` | `0.3.7` | `0.3.9` |
| `arrayvec` | `0.5.2, 0.7.4` | `0.5.2, 0.7.6` |
| `async-trait` | `0.1.75` | `-` |
| `atomic-waker` | `-` | `1.1.2` |
| `autocfg` | `1.1.0` | `1.5.0` |
| `backtrace` | `0.3.67` | `0.3.76` |
| `base16ct` | `-` | `0.2.0` |
| `base256emoji` | `-` | `1.0.2` |
| `base32` | `0.4.0` | `0.5.1` |
| `base58ck` | `-` | `0.1.0` |
| `base64` | `0.12.3, 0.13.1, 0.22.1` | `0.12.3, 0.22.1` |
| `base64ct` | `1.6.0` | `1.8.3` |
| `bech32` | `0.6.0, 0.9.1` | `0.11.1, 0.6.0` |
| `binary-merkle-tree` | `-` | `16.1.1` |
| `bip39` | `-` | `2.2.2` |
| `bitcoin` | `0.29.2` | `0.32.9` |
| `bitcoin-consensus-encoding` | `-` | `0.1.0` |
| `bitcoin-internals` | `-` | `0.3.0, 0.5.0` |
| `bitcoin-io` | `-` | `0.1.4` |
| `bitcoin-units` | `-` | `0.1.3` |
| `bitcoin_hashes` | `0.11.0` | `0.14.1, 0.20.0` |
| `bitflags` | `1.3.2, 2.4.1` | `1.3.2, 2.11.1` |
| `bitstream-io` | `2.3.0` | `2.6.0` |
| `blake2b_simd` | `0.5.11, 1.0.1` | `0.5.11, 1.0.4` |
| `blake2s_simd` | `1.0.2` | `1.0.4` |
| `blake3` | `1.5.0` | `1.8.5` |
| `block-buffer` | `0.10.4, 0.7.3, 0.9.0` | `0.10.4, 0.12.0, 0.7.3, 0.9.0` |
| `block-padding` | `0.1.5, 0.3.3` | `0.1.5, 0.4.2` |
| `bounded-collections` | `-` | `0.3.2` |
| `bs58` | `0.2.5` | `0.2.5, 0.5.1` |
| `bumpalo` | `3.14.0` | `3.20.2` |
| `byte-slice-cast` | `1.2.2` | `1.2.3` |
| `byteorder` | `0.3.13, 1.4.3` | `0.3.13, 1.5.0` |
| `bytes` | `1.4.0` | `1.11.1` |
| `cbc` | `0.1.2` | `0.2.1` |
| `cc` | `1.0.83` | `1.2.62` |
| `cfg-if` | `1.0.0` | `1.0.4` |
| `chrono` | `0.4.31` | `-` |
| `cipher` | `0.4.4` | `0.4.4, 0.5.2` |
| `cmov` | `-` | `0.5.3` |
| `common-path` | `-` | `1.0.0` |
| `const-oid` | `0.9.6` | `0.10.2, 0.9.6` |
| `const-str` | `-` | `0.4.3` |
| `const_format` | `-` | `0.2.36` |
| `const_format_proc_macros` | `-` | `0.2.34` |
| `constant_time_eq` | `0.1.5, 0.2.6, 0.3.0` | `0.1.5, 0.4.2` |
| `core-foundation` | `0.9.4` | `0.10.1` |
| `core-foundation-sys` | `0.8.6` | `0.8.7` |
| `core2` | `0.4.0` | `-` |
| `cpubits` | `-` | `0.1.1` |
| `cpufeatures` | `0.2.9` | `0.2.17, 0.3.0` |
| `crc` | `3.2.1` | `3.4.0` |
| `crc-catalog` | `2.4.0` | `2.5.0` |
| `crunchy` | `0.2.2` | `0.2.4` |
| `crypto-bigint` | `-` | `0.5.5` |
| `crypto-common` | `0.1.6` | `0.1.7, 0.2.2` |
| `ctr` | `0.9.2` | `0.10.1` |
| `ctutils` | `-` | `0.4.2` |
| `curve25519-dalek` | `2.1.3, 3.2.0, 4.1.1` | `4.1.3` |
| `dashmap` | `5.5.3` | `-` |
| `data-encoding` | `2.5.0` | `2.11.0` |
| `data-encoding-macro` | `0.1.14` | `0.1.20` |
| `data-encoding-macro-internal` | `0.1.12` | `0.1.18` |
| `der` | `0.6.1, 0.7.8` | `0.6.1, 0.7.10` |
| `deranged` | `-` | `0.5.8` |
| `derivative` | `-` | `2.2.0` |
| `derive-syn-parse` | `-` | `0.2.0` |
| `derive_more` | `0.99.17` | `1.0.0` |
| `derive_more-impl` | `-` | `1.0.0` |
| `difflib` | `0.4.0` | `-` |
| `digest` | `0.10.6, 0.8.1, 0.9.0` | `0.10.7, 0.11.3, 0.8.1, 0.9.0` |
| `docify` | `-` | `0.2.9` |
| `docify_macros` | `-` | `0.2.9` |
| `downcast-rs` | `1.2.0` | `-` |
| `dyn-clonable` | `0.9.0` | `-` |
| `dyn-clonable-impl` | `0.9.0` | `-` |
| `dyn-clone` | `1.0.16` | `1.0.20` |
| `ecdsa` | `-` | `0.16.9` |
| `ed25519-dalek` | `2.1.0` | `2.2.0` |
| `ed25519-zebra` | `3.1.0` | `4.0.3` |
| `educe` | `-` | `0.6.0` |
| `either` | `1.9.0` | `1.16.0` |
| `elliptic-curve` | `-` | `0.13.8` |
| `enum-ordinalize` | `-` | `4.3.2` |
| `enum-ordinalize-derive` | `-` | `4.3.2` |
| `equivalent` | `1.0.1` | `1.0.2` |
| `errno` | `0.3.8` | `0.3.14` |
| `ethereum-types` | `0.14.0` | `0.14.1` |
| `expander` | `-` | `2.2.1` |
| `fastrand` | `1.9.0` | `2.4.1` |
| `ff` | `-` | `0.13.1` |
| `fiat-crypto` | `0.2.5` | `0.2.9` |
| `file-guard` | `-` | `0.2.0` |
| `find-msvc-tools` | `-` | `0.1.9` |
| `fixedbitset` | `0.4.2` | `0.5.7` |
| `float-cmp` | `0.9.0` | `-` |
| `foldhash` | `-` | `0.1.5` |
| `fragile` | `2.0.0` | `2.1.0` |
| `fs-err` | `-` | `2.11.0` |
| `futures` | `0.3.30` | `0.3.32` |
| `futures-channel` | `0.3.30` | `0.3.32` |
| `futures-core` | `0.3.30` | `0.3.32` |
| `futures-executor` | `0.3.30` | `0.3.32` |
| `futures-io` | `0.3.30` | `0.3.32` |
| `futures-macro` | `0.3.30` | `0.3.32` |
| `futures-sink` | `0.3.30` | `0.3.32` |
| `futures-task` | `0.3.30` | `0.3.32` |
| `futures-util` | `0.3.30` | `0.3.32` |
| `getrandom` | `0.1.16, 0.2.9` | `0.1.16, 0.2.17, 0.3.4, 0.4.2` |
| `getrandom_or_panic` | `-` | `0.0.3` |
| `gimli` | `0.27.3` | `0.32.3` |
| `glob` | `0.3.1` | `0.3.3` |
| `group` | `-` | `0.13.0` |
| `h2` | `0.3.26` | `0.4.14` |
| `half` | `1.8.2` | `1.8.3` |
| `hash-db` | `0.15.2` | `0.16.0` |
| `hashbrown` | `0.12.3, 0.14.3` | `0.13.2, 0.14.5, 0.15.5, 0.17.1` |
| `heck` | `0.4.1` | `0.5.0` |
| `hermit-abi` | `0.3.3` | `0.5.2` |
| `hex-conservative` | `-` | `0.2.2, 0.3.2` |
| `hex-literal` | `0.3.4` | `1.1.0` |
| `hex_lit` | `-` | `0.1.1` |
| `hidapi` | `2.0.2` | `2.6.6` |
| `hkdf` | `0.12.3` | `0.13.0` |
| `hmac` | `0.11.0, 0.12.1, 0.8.1` | `0.12.1, 0.13.0, 0.8.1` |
| `hmac-sha256` | `1.1.6` | `1.1.14` |
| `http` | `0.2.11` | `1.4.0` |
| `http-body` | `0.4.6` | `1.0.1` |
| `http-body-util` | `-` | `0.1.3` |
| `httparse` | `1.8.0` | `1.10.1` |
| `hybrid-array` | `-` | `0.4.12` |
| `hyper` | `0.14.23` | `1.9.0` |
| `hyper-timeout` | `0.4.1` | `0.5.2` |
| `hyper-tls` | `0.5.0` | `0.6.0` |
| `hyper-util` | `-` | `0.1.20` |
| `iana-time-zone` | `0.1.58` | `-` |
| `iana-time-zone-haiku` | `0.1.2` | `-` |
| `id-arena` | `-` | `2.3.0` |
| `impl-codec` | `0.6.0` | `0.6.0, 0.7.1` |
| `impl-num-traits` | `-` | `0.2.0` |
| `impl-serde` | `0.4.0` | `0.4.0, 0.5.0` |
| `impl-trait-for-tuples` | `0.2.2` | `0.2.3` |
| `indexmap` | `2.1.0` | `2.14.0` |
| `inout` | `0.1.3` | `0.1.4, 0.2.2` |
| `instant` | `0.1.12` | `-` |
| `io-lifetimes` | `1.0.11` | `-` |
| `itertools` | `0.10.5` | `0.10.5, 0.11.0, 0.13.0, 0.14.0` |
| `itoa` | `1.0.10` | `1.0.18` |
| `jam-codec` | `-` | `0.1.1` |
| `jam-codec-derive` | `-` | `0.1.1` |
| `js-sys` | `0.3.66` | `0.3.98` |
| `k256` | `-` | `0.13.4` |
| `keccak` | `0.1.4` | `0.1.6, 0.2.0` |
| `konst` | `-` | `0.2.20` |
| `konst_macro_rules` | `-` | `0.2.19` |
| `lazy_static` | `1.4.0` | `1.5.0` |
| `leb128` | `0.2.5` | `0.2.6` |
| `leb128fmt` | `-` | `0.1.0` |
| `libc` | `0.2.140` | `0.2.186` |
| `libm` | `0.2.8` | `0.2.16` |
| `libsecp256k1` | `0.6.0, 0.7.1` | `0.6.0, 0.7.2` |
| `linux-raw-sys` | `0.3.8` | `0.12.1` |
| `lock_api` | `0.4.11` | `0.4.14` |
| `log` | `0.4.17` | `0.4.29` |
| `lru` | `0.8.1` | `-` |
| `match-lookup` | `-` | `0.1.2` |
| `matchers` | `0.0.1` | `0.2.0` |
| `memchr` | `2.6.4` | `2.8.0` |
| `memory-db` | `0.30.0` | `0.34.0` |
| `memory_units` | `0.4.0` | `-` |
| `merlin` | `2.0.1` | `3.0.0` |
| `miniz_oxide` | `0.6.2` | `0.8.9` |
| `mio` | `0.8.8` | `1.2.0` |
| `mockall` | `0.11.3` | `0.14.0` |
| `mockall_derive` | `0.11.3` | `0.14.0` |
| `multibase` | `0.8.0, 0.9.1` | `0.8.0, 0.9.2` |
| `multihash` | `0.13.2, 0.18.1` | `0.13.2, 0.19.5` |
| `multihash-codetable` | `-` | `0.2.2` |
| `multihash-derive` | `0.7.2, 0.8.1` | `0.7.2, 0.9.3` |
| `multihash-derive-impl` | `-` | `0.1.3` |
| `multimap` | `0.8.3` | `0.10.1` |
| `native-tls` | `0.2.11` | `0.2.18` |
| `normalize-line-endings` | `0.3.0` | `-` |
| `nu-ansi-term` | `-` | `0.50.3` |
| `num-bigint` | `0.3.3, 0.4.3` | `0.3.3, 0.4.6` |
| `num-bigint-dig` | `0.8.4` | `0.8.6` |
| `num-conv` | `-` | `0.2.2` |
| `num-integer` | `0.1.45` | `0.1.46` |
| `num-iter` | `0.1.43` | `0.1.45` |
| `num-rational` | `0.4.1` | `-` |
| `num-traits` | `0.2.15` | `0.2.19` |
| `num_cpus` | `1.16.0` | `1.17.0` |
| `object` | `0.30.4` | `0.37.3` |
| `once_cell` | `1.19.0` | `1.21.4` |
| `opaque-debug` | `0.2.3, 0.3.0` | `0.2.3, 0.3.1` |
| `openssl` | `0.10.66` | `0.10.80` |
| `openssl-probe` | `0.1.5` | `0.2.1` |
| `openssl-sys` | `0.9.103` | `0.9.116` |
| `parity-scale-codec` | `3.5.0` | `3.7.5` |
| `parity-scale-codec-derive` | `3.6.9` | `3.7.5` |
| `parity-util-mem` | `0.12.0` | `-` |
| `parity-util-mem-derive` | `0.1.0` | `-` |
| `parity-wasm` | `0.45.0` | `-` |
| `parking_lot` | `0.12.1` | `0.12.5` |
| `parking_lot_core` | `0.9.9` | `0.9.12` |
| `password-hash` | `0.4.2` | `0.5.0` |
| `paste` | `1.0.14` | `1.0.15` |
| `pbkdf2` | `0.11.0, 0.4.0, 0.8.0` | `0.12.2, 0.13.0` |
| `petgraph` | `0.6.4` | `0.8.3` |
| `picosimd` | `-` | `0.9.3` |
| `pin-project-lite` | `0.2.13` | `0.2.17` |
| `pin-utils` | `0.1.0` | `-` |
| `pkg-config` | `0.3.28` | `0.3.33` |
| `platforms` | `3.3.0` | `-` |
| `polkavm-common` | `-` | `0.33.0` |
| `polkavm-derive` | `-` | `0.33.0` |
| `polkavm-derive-impl` | `-` | `0.33.0` |
| `polkavm-derive-impl-macro` | `-` | `0.33.0` |
| `powerfmt` | `-` | `0.2.0` |
| `ppv-lite86` | `0.2.17` | `0.2.21` |
| `predicates` | `2.1.5` | `3.1.4` |
| `predicates-core` | `1.0.6` | `1.0.10` |
| `predicates-tree` | `1.0.9` | `1.0.13` |
| `prettyplease` | `0.1.25` | `0.2.37` |
| `primitive-types` | `0.12.2` | `0.12.2, 0.13.1` |
| `proc-macro-crate` | `1.1.3, 2.0.0` | `1.3.1, 3.5.0` |
| `proc-macro-warning` | `-` | `1.84.1` |
| `proc-macro2` | `1.0.76` | `1.0.106` |
| `prometheus` | `-` | `0.13.4` |
| `prost` | `0.11.2` | `0.14.3` |
| `prost-build` | `0.11.4` | `0.14.3` |
| `prost-derive` | `0.11.9` | `0.14.3` |
| `prost-types` | `0.11.2` | `0.14.3` |
| `quote` | `1.0.35` | `1.0.45` |
| `r-efi` | `-` | `5.3.0, 6.0.0` |
| `rand` | `0.7.3, 0.8.5` | `0.7.3, 0.8.6, 0.9.4` |
| `rand_chacha` | `0.2.2, 0.3.1` | `0.2.2, 0.3.1, 0.9.0` |
| `rand_core` | `0.5.1, 0.6.4` | `0.5.1, 0.6.4, 0.9.5` |
| `rand_pcg` | `0.2.1` | `-` |
| `redox_syscall` | `0.3.5, 0.4.1` | `0.5.18` |
| `ref-cast` | `1.0.21` | `1.0.25` |
| `ref-cast-impl` | `1.0.21` | `1.0.25` |
| `regex` | `1.9.3` | `1.12.3` |
| `regex-automata` | `0.1.10, 0.3.9` | `0.4.14` |
| `regex-syntax` | `0.6.29, 0.7.5` | `0.8.10` |
| `rfc6979` | `-` | `0.4.0` |
| `ripemd` | `-` | `0.2.0` |
| `rustc-demangle` | `0.1.23` | `0.1.27` |
| `rustc_version` | `0.4.0` | `0.4.1` |
| `rustix` | `0.37.7` | `1.1.4` |
| `rustversion` | `1.0.14` | `1.0.22` |
| `ryu` | `1.0.16` | `-` |
| `salsa20` | `0.10.2` | `0.10.2, 0.11.0` |
| `same-file` | `-` | `1.0.6` |
| `scale-info` | `2.10.0` | `2.11.6` |
| `scale-info-derive` | `2.10.0` | `2.11.6` |
| `scc` | `-` | `2.4.0` |
| `schannel` | `0.1.23` | `0.1.29` |
| `schnellru` | `-` | `0.2.4` |
| `schnorrkel` | `0.9.1` | `0.11.5` |
| `scrypt` | `0.10.0` | `0.12.0` |
| `sdd` | `-` | `3.0.10` |
| `sec1` | `-` | `0.7.3` |
| `secp256k1` | `0.24.3` | `0.28.2, 0.29.1, 0.31.1` |
| `secp256k1-sys` | `0.6.1` | `0.10.1, 0.11.0, 0.9.2` |
| `security-framework` | `2.9.2` | `3.7.0` |
| `security-framework-sys` | `2.9.1` | `2.17.0` |
| `semver` | `1.0.20` | `1.0.28` |
| `serde` | `1.0.147` | `1.0.228` |
| `serde_bytes` | `-` | `0.11.19` |
| `serde_core` | `-` | `1.0.228` |
| `serde_derive` | `1.0.147` | `1.0.228` |
| `serde_json` | `1.0.89` | `1.0.149` |
| `serde_repr` | `0.1.17` | `0.1.20` |
| `serde_spanned` | `-` | `0.6.9` |
| `serdect` | `-` | `0.2.0` |
| `serial_test` | `2.0.0` | `3.4.0` |
| `serial_test_derive` | `2.0.0` | `3.4.0` |
| `sha1` | `0.6.1` | `0.11.0` |
| `sha1_smol` | `1.0.0` | `-` |
| `sha2` | `0.10.6, 0.8.2, 0.9.9` | `0.10.9, 0.11.0, 0.8.2, 0.9.9` |
| `sha3` | `0.10.8` | `0.10.9, 0.11.0` |
| `shlex` | `-` | `1.3.0` |
| `signal-hook-registry` | `1.4.1` | `1.4.8` |
| `signature` | `1.6.4, 2.1.0` | `1.6.4, 2.2.0` |
| `simple-mermaid` | `-` | `0.1.1` |
| `slab` | `0.4.9` | `0.4.12` |
| `smallvec` | `1.11.2` | `1.15.1` |
| `socket2` | `0.4.9` | `0.6.3` |
| `sp-application-crypto` | `7.0.0` | `46.0.0` |
| `sp-arithmetic` | `6.0.0` | `28.0.1` |
| `sp-core` | `7.0.0` | `41.0.0` |
| `sp-core-hashing` | `5.0.0` | `-` |
| `sp-crypto-hashing` | `-` | `0.1.0` |
| `sp-debug-derive` | `5.0.0` | `15.0.0` |
| `sp-externalities` | `0.13.0` | `0.32.0` |
| `sp-io` | `7.0.0` | `46.0.0` |
| `sp-keyring` | `7.0.0` | `47.0.0` |
| `sp-keystore` | `0.13.0` | `0.47.0` |
| `sp-panic-handler` | `5.0.0` | `13.0.2` |
| `sp-runtime` | `7.0.0` | `47.0.0` |
| `sp-runtime-interface` | `7.0.0` | `35.0.0` |
| `sp-runtime-interface-proc-macro` | `6.0.0` | `21.0.0` |
| `sp-state-machine` | `0.13.0` | `0.51.0` |
| `sp-std` | `5.0.0` | `14.0.0` |
| `sp-storage` | `7.0.0` | `23.0.0` |
| `sp-tracing` | `6.0.0` | `19.0.0` |
| `sp-trie` | `7.0.0` | `44.0.0` |
| `sp-wasm-interface` | `7.0.0` | `25.0.0` |
| `sp-weights` | `4.0.0` | `34.0.0` |
| `spin` | `0.5.2` | `0.9.8` |
| `ss58-registry` | `1.44.0` | `1.51.0` |
| `ssz_rs` | `0.8.0` | `0.9.0` |
| `ssz_rs_derive` | `0.8.0` | `0.9.0` |
| `strum` | `0.24.1, 0.25.0` | `0.26.3, 0.28.0` |
| `strum_macros` | `0.24.3, 0.25.3` | `0.26.4, 0.28.0` |
| `substrate-bip39` | `0.4.5` | `0.6.1` |
| `substrate-prometheus-endpoint` | `-` | `0.17.7` |
| `syn` | `1.0.109, 2.0.48` | `1.0.109, 2.0.117` |
| `synstructure` | `0.12.6` | `0.12.6, 0.13.2` |
| `tempfile` | `3.5.0` | `3.27.0` |
| `termcolor` | `-` | `1.4.1` |
| `termtree` | `0.4.1` | `0.5.1` |
| `thiserror` | `1.0.56` | `1.0.69, 2.0.18` |
| `thiserror-impl` | `1.0.56` | `1.0.69, 2.0.18` |
| `thread_local` | `1.1.7` | `1.1.9` |
| `time` | `-` | `0.3.47` |
| `time-core` | `-` | `0.1.8` |
| `time-macros` | `-` | `0.2.27` |
| `tiny-bip39` | `0.8.2, 1.0.0` | `2.0.0` |
| `tinyvec` | `1.6.0` | `1.11.0` |
| `tokio` | `1.28.2` | `1.52.3` |
| `tokio-io-timeout` | `1.2.0` | `-` |
| `tokio-macros` | `2.1.0` | `2.7.0` |
| `tokio-util` | `0.7.10` | `0.7.18` |
| `toml` | `0.5.11` | `0.8.23` |
| `toml_datetime` | `0.6.5` | `0.6.11, 1.1.1+spec-1.1.0` |
| `toml_edit` | `0.20.7` | `0.19.15, 0.22.27, 0.25.11+spec-1.1.0` |
| `toml_parser` | `-` | `1.1.2+spec-1.1.0` |
| `toml_write` | `-` | `0.1.2` |
| `tower-service` | `0.3.2` | `0.3.3` |
| `tracing` | `0.1.40` | `0.1.44` |
| `tracing-attributes` | `0.1.27` | `0.1.31` |
| `tracing-core` | `0.1.32` | `0.1.36` |
| `tracing-log` | `0.1.4` | `0.2.0` |
| `tracing-serde` | `0.1.3` | `-` |
| `tracing-subscriber` | `0.2.25` | `0.3.23` |
| `trie-db` | `0.24.0` | `0.31.0` |
| `trie-root` | `0.17.0` | `0.18.0` |
| `tuplex` | `-` | `0.1.2` |
| `typenum` | `1.17.0` | `1.20.0` |
| `uint` | `0.9.5` | `0.10.0, 0.9.5` |
| `unicode-ident` | `1.0.12` | `1.0.24` |
| `unicode-normalization` | `0.1.22` | `0.1.25` |
| `unicode-xid` | `0.2.4` | `0.2.6` |
| `unsigned-varint` | `0.5.1, 0.7.2` | `0.5.1, 0.8.0` |
| `uuid` | `1.2.2` | `1.23.1` |
| `valuable` | `0.1.0` | `0.1.1` |
| `version_check` | `0.9.4` | `0.9.5` |
| `w3f-bls` | `-` | `0.1.9` |
| `w3f-pcs` | `-` | `0.0.5` |
| `w3f-plonk-common` | `-` | `0.0.7` |
| `w3f-ring-proof` | `-` | `0.0.8` |
| `walkdir` | `-` | `2.5.0` |
| `wasi` | `0.11.0+wasi-snapshot-preview1, 0.9.0+wasi-snapshot-preview1` | `0.11.1+wasi-snapshot-preview1, 0.9.0+wasi-snapshot-preview1` |
| `wasip2` | `-` | `1.0.3+wasi-0.2.9` |
| `wasip3` | `-` | `0.4.0+wasi-0.3.0-rc-2026-01-06` |
| `wasm-bindgen` | `0.2.89` | `0.2.121` |
| `wasm-bindgen-backend` | `0.2.89` | `-` |
| `wasm-bindgen-macro` | `0.2.89` | `0.2.121` |
| `wasm-bindgen-macro-support` | `0.2.89` | `0.2.121` |
| `wasm-bindgen-shared` | `0.2.89` | `0.2.121` |
| `wasm-encoder` | `-` | `0.244.0` |
| `wasm-metadata` | `-` | `0.244.0` |
| `wasmi` | `0.13.2` | `-` |
| `wasmi-validation` | `0.5.0` | `-` |
| `wasmi_core` | `0.2.1` | `-` |
| `wasmparser` | `-` | `0.244.0` |
| `which` | `4.4.0` | `-` |
| `winapi-util` | `-` | `0.1.11` |
| `windows-core` | `0.51.1` | `-` |
| `windows-link` | `-` | `0.2.1` |
| `windows-sys` | `0.45.0, 0.48.0, 0.52.0` | `0.61.2` |
| `windows-targets` | `0.42.2, 0.48.5, 0.52.0` | `-` |
| `windows_aarch64_gnullvm` | `0.42.2, 0.48.5, 0.52.0` | `-` |
| `windows_aarch64_msvc` | `0.42.2, 0.48.5, 0.52.0` | `-` |
| `windows_i686_gnu` | `0.42.2, 0.48.5, 0.52.0` | `-` |
| `windows_i686_msvc` | `0.42.2, 0.48.5, 0.52.0` | `-` |
| `windows_x86_64_gnu` | `0.42.2, 0.48.5, 0.52.0` | `-` |
| `windows_x86_64_gnullvm` | `0.42.2, 0.48.5, 0.52.0` | `-` |
| `windows_x86_64_msvc` | `0.42.2, 0.48.5, 0.52.0` | `-` |
| `winnow` | `0.5.30` | `0.5.40, 0.7.15, 1.0.3` |
| `wit-bindgen` | `-` | `0.51.0, 0.57.1` |
| `wit-bindgen-core` | `-` | `0.51.0` |
| `wit-bindgen-rust` | `-` | `0.51.0` |
| `wit-bindgen-rust-macro` | `-` | `0.51.0` |
| `wit-component` | `-` | `0.244.0` |
| `wit-parser` | `-` | `0.244.0` |
| `xsalsa20poly1305` | `0.9.0` | `0.9.1` |
| `zerocopy` | `-` | `0.8.48` |
| `zerocopy-derive` | `-` | `0.8.48` |
| `zeroize` | `1.7.0` | `1.8.2` |
| `zeroize_derive` | `1.4.2` | `1.4.3` |
| `zmij` | `-` | `1.0.21` |
