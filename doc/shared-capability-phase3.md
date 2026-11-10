# Phase 3 Shared Capability Assessment

This document records the phase 3 assessment for converging duplicate pure
logic between `imkey-core / ikc` and `token-core / tcx`.

## Goals

- Keep TokenCoreX and imKeyCore product boundaries separate.
- Extract only device-independent, keystore-independent, pure logic first.
- Preserve public APIs, error strings, address strings, transaction bytes, and
  signature behavior.
- Use small PRs with golden test vectors for each extraction.

## Extraction Boundaries

### Prefer To Extract

| Area | Current Locations | Reason |
| --- | --- | --- |
| CKB Molecule serialization | `token-core/tcx-ckb/src/serializer.rs`, `imkey-core/ikc-wallet/coin-ckb/src/serializer.rs` | Identical pure serialization helpers with existing golden vectors. |
| CKB short address pure logic | `token-core/tcx-ckb/src/address.rs`, `imkey-core/ikc-wallet/coin-ckb/src/address.rs` | Same secp256k1 compression, CKB blake2b-160, short payload, and bech32 validation. |
| Hex encode/decode pure helpers | `token-core/tcx-common/src/hex.rs`, `token-core/tcx-common/src/util.rs`, `imkey-core/ikc-common/src/hex.rs`, `imkey-core/ikc-common/src/utility.rs` | Identical hex encoding, `0x` handling, auto-prefix detection, and UTF-8-or-hex conversion; wrappers preserve each side's trait API and error mapping. |
| Hash helpers | `token-core/tcx-common/src/hash.rs`, `imkey-core/ikc-common/src/utility.rs` | Shared pure `sha256`, `sha256d`, `ripemd160`, `keccak256`, and Merkle hash implementation; wrappers preserve product-specific function sets and return types. |
| ETH checksum/address pure logic | `token-core/tcx-eth/src/address.rs`, `imkey-core/ikc-wallet/coin-ethereum/src/address.rs` | Same EIP-55 checksum algorithm; extraction must preserve each side's public key input and validation behavior. |
| TRON address pure logic | `token-core/tcx-tron/src/address.rs`, `imkey-core/ikc-wallet/coin-tron/src/address.rs` | Same keccak + `0x41` + base58check algorithm; extraction must account for compressed/uncompressed key handling. |
| Cosmos/ATOM address pure logic | `token-core/tcx-atom/src/address.rs`, `imkey-core/ikc-wallet/coin-cosmos/src/address.rs` | Same secp256k1 compression, hash160, and bech32 encoding; tcx keeps chain-id-to-HRP mapping. |
| Tezos tz1/edpk pure logic | `token-core/tcx-tezos/src/address.rs`, `imkey-core/ikc-wallet/coin-tezos/src/address.rs` | Same ed25519 public-key hash, tz1 base58check, and edpk public-key encoding. |
| BTC scriptPubKey/address payload pure logic | `token-core/tcx-btc-kin`, `imkey-core/ikc-wallet/coin-bitcoin`, `coin-btc-fork` | Public-key-to-payload and payload-to-script helpers are shared; full address parsing remains product-specific. |
| Filecoin address pure logic | `token-core/tcx-filecoin/src/address.rs`, `imkey-core/ikc-wallet/coin-filecoin/src/address.rs` | Same blake2b payload/checksum and base32 address encoding; hardware public-key retrieval remains imKey-specific. |

### Do Not Extract In This Phase

| Area | Reason |
| --- | --- |
| `ikc-device`, `ikc-transport` | Real-device transport, binding, APDU state, and hardware lifecycle are imKey-only concerns. |
| APDU interaction | Must remain in imKeyCore; TokenCoreX should not depend on hardware protocol details. |
| Hardware signing flows | Device prompts, applet selection, secure element signatures, and verification are product-specific. |
| `tcx-keystore` unlock/cache/derived-key storage | Software wallet secret storage is TokenCoreX-specific and should not leak into imKeyCore. |
| Mobile SDK / FFI facade | Public ABI and mobile packaging are product-specific compatibility boundaries. |
| Substrate address flow | Both sides can emit SS58 addresses, but TokenCoreX derives sr25519 software public keys while imKeyCore consumes ed25519 APDU public keys. Merge only after a dedicated curve/input contract review. |

## Extracted Shared Crate

New shared crate:

- `common/wallet-core-common`

Feature-gated modules:

- `wallet_core_common::btc` behind `btc`
- `wallet_core_common::ckb::molecule`
- `wallet_core_common::ckb::address` behind `ckb-address`
- `wallet_core_common::cosmos` behind `cosmos`
- `wallet_core_common::eth` behind `eth`
- `wallet_core_common::filecoin` behind `filecoin`
- `wallet_core_common::hash` behind `hash`
- `wallet_core_common::hex`
- `wallet_core_common::tezos` behind `tezos`
- `wallet_core_common::tron` behind `tron`

The feature gates keep unrelated dependencies out of crates that only need a
small subset. For example, CKB serializer users do not need to compile ETH or
TRON dependencies.

## Extracted Pure Helpers

### CKB Molecule Serialization

Moved pure helpers:

- `serialize_u32`
- `serialize_u64`
- `serialize_struct`
- `serialize_dynamic_vec`
- `serialize_fixed_vec`

Compatibility wrappers kept:

- `token-core/tcx-ckb/src/serializer.rs`
- `imkey-core/ikc-wallet/coin-ckb/src/serializer.rs`

The wrappers keep the existing `Serializer` type and method names, so existing
call sites and public re-exports do not change.

### BTC Payload And Script Helpers

Moved pure helpers:

- p2pkh hash derivation from public key
- p2sh-wrapped p2wpkh script hash derivation
- p2wpkh witness program derivation
- p2tr witness program derivation
- p2pkh / p2sh / witness payload to `scriptPubKey`

Compatibility wrappers kept:

- `token-core/tcx-btc-kin/src/address.rs`
- `imkey-core/ikc-wallet/coin-bitcoin/src/btc_kin_address.rs`
- `imkey-core/ikc-wallet/coin-btc-fork/src/address.rs`

Full BTC address parsing, network lookup, bech32 HRP mapping, base58 version
mapping, and product-specific error mapping remain in the original crates.
Those behaviors differ enough that they should only be merged after a dedicated
golden-vector pass.

### CKB Short Address

Moved pure helpers:

- secp256k1 public key parsing/compression
- CKB `blake2b_160`
- short address payload construction
- bech32 short/full address validation

Compatibility wrappers kept:

- `token-core/tcx-ckb/src/address.rs`
- `imkey-core/ikc-wallet/coin-ckb/src/address.rs`

### ETH Address

Moved pure helpers:

- EIP-55 checksum formatting
- checksum validation with historical lowercase-address acceptance
- public-key-to-address byte derivation

Compatibility wrappers kept:

- `token-core/tcx-eth/src/address.rs`
- `imkey-core/ikc-wallet/coin-ethereum/src/address.rs`

### TRON Address

Moved pure helpers:

- secp256k1 public key parsing/compression
- keccak + `0x41` payload construction
- base58check encoding and validation

Compatibility wrappers kept:

- `token-core/tcx-tron/src/address.rs`
- `imkey-core/ikc-wallet/coin-tron/src/address.rs`

### Tezos Address And Public Key Encoding

Moved pure helpers:

- `tz1` address generation from ed25519 public key bytes
- Tezos base58check validation
- `edpk` public key encoding

Compatibility wrappers kept:

- `token-core/tcx-tezos/src/address.rs`
- `imkey-core/ikc-wallet/coin-tezos/src/address.rs`

### Cosmos/ATOM Address

Moved pure helpers:

- secp256k1 public key parsing/compression
- hash160
- bech32 address encoding and payload length validation

Compatibility wrappers kept:

- `token-core/tcx-atom/src/address.rs`
- `imkey-core/ikc-wallet/coin-cosmos/src/address.rs`

`tcx-atom` still owns `chain_id -> HRP` resolution. The shared helper only
receives the resolved HRP.

### Filecoin Address

Moved pure helpers:

- secp256k1 uncompressed public-key payload hashing
- BLS public-key address payload handling
- protocol-byte checksum generation
- Filecoin base32 address formatting

Compatibility wrappers kept:

- `token-core/tcx-filecoin/src/address.rs`
- `imkey-core/ikc-wallet/coin-filecoin/src/address.rs`

`coin-filecoin` still owns APDU applet selection, device binding checks, xpub
construction, display-address registration, and hardware public-key retrieval.
`tcx-filecoin` still owns software-wallet curve dispatch and Forest address
validation.

### Hex Helpers

Moved pure helpers:

- hex encoding
- `0x` prefix encoding
- compatible `0x` stripping used by legacy `from_0x_hex`
- `0x`/`0X` auto-prefix detection
- hex decoding
- UTF-8-or-hex input conversion

Compatibility wrappers kept:

- `token-core/tcx-common/src/hex.rs`
- `token-core/tcx-common/src/util.rs`
- `imkey-core/ikc-common/src/hex.rs`
- `imkey-core/ikc-common/src/utility.rs`

Both wrappers continue to expose their existing `ToHex` / `FromHex` traits and
map decode errors through their local `Result` types. The shared helper avoids
changing public imports used throughout each product.

### Hash Helpers

Moved pure helpers:

- `sha256`
- `sha256d`
- `ripemd160`
- `keccak256`
- Merkle hash over 1024-byte chunks

Compatibility wrappers kept:

- `token-core/tcx-common/src/hash.rs`
- `imkey-core/ikc-common/src/utility.rs`

`tcx-common` keeps the original `Hash256` / `Hash160` aliases and function
names. `ikc-common::sha256_hash` keeps returning `Vec<u8>` for existing APDU and
signature call sites.

## Golden Vectors

The new shared crate owns golden vectors for each extracted module.

CKB Molecule:

- `serialize_u32(0x12345678) -> 78563412`
- `serialize_u64(0x0123456789abcdef) -> efcdab8967452301`
- `serialize_struct([1113, 201709]) -> 1113201709`
- `serialize_fixed_vec([1234567890abcdef]) -> 080000001234567890abcdef`
- empty dynamic vec -> `04000000`
- single dynamic vec item -> `0e00000008000000020000001234`
- multi-item dynamic vec -> `34000000180000001e00000022000000280000002d00000002000000123400000000020000000567010000008903000000abcdef`

Address examples:

- BTC p2sh scriptPubKey: `a914bc64b2d79807cd3d72101c3298b89117d32097fb87`
- BTC p2wpkh scriptPubKey: `0014e6cfaab9a59ba187f0a45db0b169c21bb48f09b3`
- CKB testnet: `ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqswmu83`
- CKB mainnet: `ckb1qyqrdsefa43s6m882pcj53m4gdnj4k440axqdt9rtd`
- ETH: `0xC2D7CF95645D33006175B78989035C7c9061d3F9`
- TRON: `THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acotq`
- Tezos: `tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNo9`
- Tezos edpk: `edpkuCxAMMrmdQZwVafQPJZZqcEj9FizeoXYovmLQyokYJcG7CYD8o`
- Cosmos: `cosmos1pt9904aqg739q6p9kgc2v0puqvj6atp0zsj70g`
- Osmosis HRP variant: `osmo1m566v5rcklnac8vc0dftfu4lnvznhlu79269e8`
- Filecoin secp256k1: `t15ihq5ibzwki2b4ep2f46avlkrqzhpqgtga7pdrq`
- Filecoin BLS: `t3vvmn62lofvhjd2ugzca6sof2j2ubwok6cj4xxbfzz4yuxfkgobpihhd2thlanmsh3w2ptld2gqkn2jvlss4a`
- Hex encode: `01020304`
- Hex auto-decode: `0X01020304 -> [1, 2, 3, 4]`
- UTF-8-or-hex: `0x1234 -> [0x12, 0x34]`, `1234 -> b"1234"`
- SHA-256 `abc`: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
- Keccak-256 `abc`: `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45`

Original chain-crate tests are retained as compatibility checks over wrapper
APIs.

## Verification

Commands run after the current extraction batch:

```bash
cargo fmt
cargo test -p wallet-core-common --all-features
cargo test -p wallet-core-common --features btc btc
cargo test -p tcx-btc-kin address::tests::test_script_pubkey
cargo test -p tcx-btc-kin address::tests::test_btc_kin_address
cargo test -p coin-btc-fork address::test::test_btc_fork_address_from_str
cargo test -p tcx-ckb serializer::tests
cargo test -p coin-ckb serializer::tests
cargo test -p tcx-ckb address::tests
cargo test -p coin-ckb address::tests::test_from_public_key
cargo test -p tcx-eth address::test
cargo test -p coin-ethereum address::test::test_pubkey_to_address
cargo test -p coin-ethereum address::test::test_checksummed_address
cargo test -p tcx-tron address::tests
cargo test -p coin-tron address::tests::tron_address
cargo test -p tcx-tezos address::test
cargo test -p tcx-atom address::tests
cargo test -p wallet-core-common --features filecoin filecoin
cargo test -p tcx-filecoin address::tests
cargo check -p tcx-filecoin -p coin-filecoin
cargo test -p wallet-core-common hex
cargo test -p tcx-common hex::tests
cargo test -p tcx-common util::tests
cargo test -p ikc-common hex::tests
cargo test -p ikc-common utility::tests::utf8_or_hex_to_bytes_test
cargo test -p wallet-core-common --features hash hash
cargo test -p tcx-common hash::tests
cargo test -p ikc-common utility::tests::sha256_hash_test
cargo check -p tcx-btc-kin -p coin-bitcoin -p coin-btc-fork
cargo check -p tcx-ckb -p coin-ckb
cargo check -p tcx-eth -p tcx-tron -p coin-ethereum -p coin-tron
cargo check -p coin-tezos -p tcx-tezos
cargo check -p coin-cosmos -p tcx-atom
git diff --check
```

`coin-ckb` full tests were intentionally not run because that crate also has
real-device tests. Focused pure tests and package checks cover this extraction
batch without requiring imKey hardware.

## Next Candidates

Recommended next small PRs:

1. Evaluate full BTC address parsing and Display after collecting golden
   vectors for legacy, p2sh, bech32, Litecoin, Dogecoin, BCH, and KIN variants.
2. Evaluate common hash/hex wrappers after mapping each side's error behavior.
3. Evaluate Tezos transaction signature formatting separately from address
   encoding because it touches signing output.
4. Evaluate Filecoin/Substrate address helpers separately; they are pure but
   use chain-specific protocol crates and should be isolated in small PRs.

Each follow-up should include golden vectors in `wallet-core-common` and keep
the product-specific wrapper APIs unchanged.
