//! End-to-end tests for the new ETH batch transaction signing path.
//!
//! These tests call `connector::ethereum_signer::sign_txs` directly,
//! exercising:
//!
//!   - the pre-flight validation branches (size limit / empty /
//!     invalid path / missing tx / missing sender), which return
//!     synchronously before any device session and therefore run
//!     in CI without a connected imKey;
//!   - the per-item loop dispatching to the existing single-tx
//!     `coin_ethereum::transaction::Transaction::sign`, gated by
//!     `bind_test()` and asserting byte-for-byte equality against
//!     the on-chain canonical fixtures already validated by the
//!     in-source single-tx tests in `ethereum_signer.rs`.
//!
//! Going via the in-process Rust API (rather than `call_imkey_api`)
//! is deliberate: it keeps each test file readable and lets future
//! per-feature E2E suites live here without dragging C-ABI
//! envelope plumbing through every assertion. The dispatcher branch
//! itself (`"sign_txs" =>` in `lib.rs`) is a one-liner —
//! a simple smoke test elsewhere is cheap enough; the heavy lifting
//! belongs at the function level.
//!
//! Why `bind_test()` directly (and not a hand-rolled `bind_check` /
//! `bind_acquire` pair): `bind_test()` triggers `bind_acquire` for
//! **any** non-`bound_this` status — covers both `unbound` and
//! `bound_other` — and pins the host key file at `TEST_KEY_PATH`
//! (`/tmp/`), the same path the in-source unit tests use. A flow
//! that only handles `bound_other` silently falls through on
//! `unbound`, leaving the in-memory `KEY_MANAGER` pointing at a
//! freshly-generated key the device never agreed to, and the very
//! next ETH APDU then fails the applet's binding-signature check
//! with sw `0x6942` (`imkey_signature_verify_fail`). Same hazard
//! exists if a host-side flow puts the key file under
//! `WALLET_FILE_DIR=../test-data/` while the in-source tests are
//! using `/tmp/` — the two surfaces tug-of-war over the device's
//! binding key. Going through `bind_test()` sidesteps both.

use prost::Message;

use coin_ethereum::ethapi::{AccessList, EthTxInput, SignTxsInput, SignTxsItem, SignTxsOutput};
use connector::ethereum_signer::sign_txs;
use ikc_common::constants::ETH_TRANSACTION_TYPE_EIP1559;
use ikc_common::SignParam;
use ikc_device::device_binding::bind_test;

const ETH_PATH: &str = "m/44'/60'/0'/0/0";

// Sender / display strings copied from the existing single-tx
// fixtures in `ethereum_signer.rs::tests`. Reused so every batch
// item produces a signature that's byte-equal to the recorded
// single-tx output (the device verifies sender against the derived
// address; changing it would invalidate the canonical hash).
const SENDER: &str = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b";
const RECEIVER: &str = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3";
const PAYMENT: &str = "0.01 ETH";
const FEE: &str = "0.0032 ether";

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// Minimal `SignParam` carrying just the outer batch-shared HD path.
/// `input` is unused for the batch path — the function takes the
/// encoded `SignTxsInput` as its first argument.
fn make_sign_param(path: &str) -> SignParam {
    SignParam {
        chain_type: "ETHEREUM".to_string(),
        path: path.to_string(),
        network: "MAINNET".to_string(),
        input: None,
        payment: "".to_string(),
        receiver: "".to_string(),
        sender: "".to_string(),
        fee: "".to_string(),
        seg_wit: "".to_string(),
    }
}

/// Build a structurally-valid `SignTxsItem` carrying a placeholder
/// legacy tx. Used by pre-flight tests where the goal is to trip a
/// validation branch before the device is touched. Caller mutates
/// fields after construction to express the specific failure path
/// each test wants.
fn make_valid_item() -> SignTxsItem {
    SignTxsItem {
        tx: Some(EthTxInput {
            nonce: "1".to_string(),
            gas_price: "20000000008".to_string(),
            gas_limit: "189000".to_string(),
            to: "3535353535353535353535353535353535353535".to_string(),
            value: "512".to_string(),
            data: "".to_string(),
            chain_id: "28".to_string(),
            r#type: "".to_string(),
            max_fee_per_gas: "".to_string(),
            max_priority_fee_per_gas: "".to_string(),
            access_list: vec![],
        }),
        payment: PAYMENT.to_string(),
        receiver: "0x3535353535353535353535353535353535353535".to_string(),
        sender: SENDER.to_string(),
        fee: FEE.to_string(),
        path: "".to_string(),
    }
}

// Mirrors `test_sign_eth_transaction_legacy` in `ethereum_signer.rs`.
fn legacy_item() -> SignTxsItem {
    SignTxsItem {
        tx: Some(EthTxInput {
            nonce: "8".to_string(),
            gas_price: "20000000008".to_string(),
            gas_limit: "189000".to_string(),
            to: "3535353535353535353535353535353535353535".to_string(),
            value: "512".to_string(),
            data: "".to_string(),
            chain_id: "28".to_string(),
            r#type: "".to_string(),
            max_fee_per_gas: "".to_string(),
            max_priority_fee_per_gas: "".to_string(),
            access_list: vec![],
        }),
        payment: PAYMENT.to_string(),
        receiver: RECEIVER.to_string(),
        sender: SENDER.to_string(),
        fee: FEE.to_string(),
        path: "".to_string(),
    }
}

// Mirrors `test_sign_eth_transaction_eip1559_no_access_list`.
fn eip1559_no_access_list_item() -> SignTxsItem {
    SignTxsItem {
        tx: Some(EthTxInput {
            nonce: "8".to_string(),
            gas_price: "".to_string(),
            gas_limit: "14298499".to_string(),
            to: "ef970655297d1234174bcfe31ee803aaa97ad0ca".to_string(),
            value: "11".to_string(),
            data: "ee".to_string(),
            chain_id: "130".to_string(),
            r#type: "0x2".to_string(),
            max_fee_per_gas: "850895266216".to_string(),
            max_priority_fee_per_gas: "69".to_string(),
            access_list: vec![],
        }),
        payment: PAYMENT.to_string(),
        receiver: RECEIVER.to_string(),
        sender: SENDER.to_string(),
        fee: FEE.to_string(),
        path: "".to_string(),
    }
}

// Mirrors `test_sign_eth_transaction_eip1559_multi_access_list`.
fn eip1559_multi_access_list_item() -> SignTxsItem {
    SignTxsItem {
        tx: Some(EthTxInput {
            nonce: "1".to_string(),
            gas_price: "".to_string(),
            gas_limit: "4286".to_string(),
            to: "6f4ecd70932d65ac08b56db1f4ae2da4391f328e".to_string(),
            value: "3490361".to_string(),
            data: "200184c0486d5f082a27".to_string(),
            chain_id: "63".to_string(),
            r#type: "0x02".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list: vec![
                AccessList {
                    address: "019fda53b3198867b8aae65320c9c55d74de1938".to_string(),
                    storage_keys: vec![],
                },
                AccessList {
                    address: "1b976cdbc43cfcbeaad2623c95523981ea1e664a".to_string(),
                    storage_keys: vec![
                        "d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2"
                            .to_string(),
                    ],
                },
                AccessList {
                    address: "f1946eba70f89687d67493d8106f56c90ecba943".to_string(),
                    storage_keys: vec![
                        "b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9"
                            .to_string(),
                        "6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82"
                            .to_string(),
                        "0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064"
                            .to_string(),
                    ],
                },
            ],
        }),
        payment: PAYMENT.to_string(),
        receiver: RECEIVER.to_string(),
        sender: SENDER.to_string(),
        fee: FEE.to_string(),
        path: "".to_string(),
    }
}

// Mirrors `test_sign_eth_transaction_eip1559` (single access list).
fn eip1559_with_access_list_item() -> SignTxsItem {
    SignTxsItem {
        tx: Some(EthTxInput {
            nonce: "4".to_string(),
            gas_price: "".to_string(),
            gas_limit: "54".to_string(),
            to: "d5539a0e4d27ebf74515fc4acb38adcc3c513f25".to_string(),
            value: "64".to_string(),
            data: "f579eebd8a5295c6f9c86e".to_string(),
            chain_id: "276".to_string(),
            r#type: String::from(ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: "963240322143".to_string(),
            max_priority_fee_per_gas: "28710".to_string(),
            access_list: vec![AccessList {
                address: "70b361fc3a4001e4f8e4e946700272b51fe4f0c4".to_string(),
                storage_keys: vec![
                    "8419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63".to_string(),
                    "8a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3".to_string(),
                    "897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab9".to_string(),
                ],
            }],
        }),
        payment: PAYMENT.to_string(),
        receiver: RECEIVER.to_string(),
        sender: SENDER.to_string(),
        fee: FEE.to_string(),
        path: "".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Expected outputs from the existing single-tx fixtures.
// Copied verbatim from `imkey-core/ikc/src/ethereum_signer.rs::tests`,
// which validates them against the canonical encoding.
// ---------------------------------------------------------------------------
const LEGACY_SIGNATURE: &str = "f867088504a817c8088302e248943535353535353535353535353535353535353535820200805ba03aa62abb45b77418caf139dda0179aea802c99967b3d690b87d586a87bc805afa02b5ce94f40dc865ca63403e0e5e723e1523884f001573677cd8cec11c7ca332f";
const LEGACY_TX_HASH: &str = "0x09fa41c4d6b92482506c8c56f65b217cc3398821caec7695683110997426db01";

const EIP1559_NO_AL_SIGNATURE: &str = "02f86a8182084585c61d4f61a883da2d8394ef970655297d1234174bcfe31ee803aaa97ad0ca0b81eec001a043b16ce6f245f8ec1d145e8b1f36bb9f6e7a7fd9030139a8143c3e0e9ccb6e9ca04020e1ae4920cfbf7c88e7be6a73751bb28d9bc8e6ecf3c5c989310c5871de8a";
const EIP1559_NO_AL_TX_HASH: &str =
    "0xd38f47550c709e39519a3e35024a5ec135a8893890001658f2bd96e60f88fd9a";

const EIP1559_MULTI_AL_SIGNATURE: &str = "02f901413f0181e285faac6c45d88210be946f4ecd70932d65ac08b56db1f4ae2da4391f328e833542398a200184c0486d5f082a27f8cbd694019fda53b3198867b8aae65320c9c55d74de1938c0f7941b976cdbc43cfcbeaad2623c95523981ea1e664ae1a0d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2f87a94f1946eba70f89687d67493d8106f56c90ecba943f863a0b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9a06a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82a00c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb206480a0c5dfcb3a472086ca8c29fa31b9a86c40a6bbaeeb9db938c6729305e5f35aaeb1a04a83adc3c02b706c2c3d67de0274aa771b75c2da04c4c21ed0745637a6f937de";
const EIP1559_MULTI_AL_TX_HASH: &str =
    "0xabb4c4b2b6f406b3598b5d8c5e0e7780209a50503ca5350c87ddcb82b5f518ff";

const EIP1559_AL_SIGNATURE: &str = "02f8f18201140482702685e04598e45f3694d5539a0e4d27ebf74515fc4acb38adcc3c513f25408bf579eebd8a5295c6f9c86ef87cf87a9470b361fc3a4001e4f8e4e946700272b51fe4f0c4f863a08419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63a08a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3a0897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab980a0bacd306ae19a67ffe6a6864b982dda2adc433cea38b13bfc21ca3155f1655bb6a039dad052cbb7c685c4048cafb16df681ce9e554c0cca173620a216935654c00b";
const EIP1559_AL_TX_HASH: &str =
    "0xe66abf92ea7b79ec05519444d1f360a121f224e9d6981a41e2ada82f7f50afe9";

// ===========================================================================
// Pre-flight rejection tests. NO DEVICE REQUIRED.
//
// Each of these produces an error inside `sign_txs`
// before any per-item `Transaction::sign` runs, so `select_applet`
// is never called. They run in CI without an attached imKey.
// ===========================================================================

#[test]
fn test_sign_txs_empty_rejected() {
    let data = SignTxsInput { items: vec![] }.encode_to_vec();
    let err = sign_txs(&data, &make_sign_param(ETH_PATH))
        .expect_err("empty batch must be rejected pre-flight");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid_param"),
        "expected `invalid_param`, got: {}",
        msg
    );
}

#[test]
fn test_sign_txs_size_limit_rejected() {
    // 101 dummy items > ETH_MAX_BATCH_SIZE (100). Items don't have
    // to be valid — pre-flight rejects before any signing work.
    let items: Vec<SignTxsItem> = (0..101).map(|_| make_valid_item()).collect();
    let data = SignTxsInput { items }.encode_to_vec();
    let err = sign_txs(&data, &make_sign_param(ETH_PATH))
        .expect_err("over-limit batch must be rejected pre-flight");
    let msg = err.to_string();
    assert!(
        msg.contains("exceeds limit 100"),
        "expected size-limit error mentioning 100, got: {}",
        msg
    );
}

#[test]
fn test_sign_txs_invalid_path_rejected() {
    let mut items = vec![make_valid_item(), make_valid_item(), make_valid_item()];
    // Depth < 3 trips `check_path_validity`. Pin the bad path on
    // index 1 so the assertion locks in the index-propagation
    // contract: errors must point at the offending item.
    items[1].path = "m/44'".to_string();

    let data = SignTxsInput { items }.encode_to_vec();
    let err = sign_txs(&data, &make_sign_param(ETH_PATH))
        .expect_err("invalid item path must be rejected pre-flight");
    let msg = err.to_string();
    assert!(
        msg.contains("failed at index 1"),
        "expected `failed at index 1`, got: {}",
        msg
    );
}

#[test]
fn test_sign_txs_missing_tx_rejected() {
    let mut items = vec![make_valid_item(), make_valid_item()];
    items[1].tx = None;

    let data = SignTxsInput { items }.encode_to_vec();
    let err = sign_txs(&data, &make_sign_param(ETH_PATH))
        .expect_err("missing item.tx must be rejected pre-flight");
    let msg = err.to_string();
    assert!(
        msg.contains("failed at index 1") && msg.contains("missing tx"),
        "expected `failed at index 1: missing tx`, got: {}",
        msg
    );
}

#[test]
fn test_sign_txs_missing_sender_rejected() {
    let mut items = vec![make_valid_item(), make_valid_item()];
    items[0].sender = "".to_string();

    let data = SignTxsInput { items }.encode_to_vec();
    let err = sign_txs(&data, &make_sign_param(ETH_PATH))
        .expect_err("missing item.sender must be rejected pre-flight");
    let msg = err.to_string();
    assert!(
        msg.contains("failed at index 0") && msg.contains("missing sender"),
        "expected `failed at index 0: missing sender`, got: {}",
        msg
    );
}

#[test]
fn test_sign_txs_legacy_single_item_e2e() {
    bind_test();

    let data = SignTxsInput {
        items: vec![legacy_item()],
    }
    .encode_to_vec();
    let res = sign_txs(&data, &make_sign_param(ETH_PATH)).unwrap();
    let output = SignTxsOutput::decode(res.as_slice()).unwrap();

    assert_eq!(output.outputs.len(), 1);
    assert_eq!(output.outputs[0].signature, LEGACY_SIGNATURE);
    assert_eq!(output.outputs[0].tx_hash, LEGACY_TX_HASH);
}

#[test]
fn test_sign_txs_eip1559_single_item_e2e() {
    bind_test();

    let data = SignTxsInput {
        items: vec![eip1559_with_access_list_item()],
    }
    .encode_to_vec();
    let res = sign_txs(&data, &make_sign_param(ETH_PATH)).unwrap();
    let output = SignTxsOutput::decode(res.as_slice()).unwrap();

    assert_eq!(output.outputs.len(), 1);
    assert_eq!(output.outputs[0].signature, EIP1559_AL_SIGNATURE);
    assert_eq!(output.outputs[0].tx_hash, EIP1559_AL_TX_HASH);
}

#[test]
fn test_sign_txs_mixed_three_items_e2e() {
    bind_test();

    // Item 1 explicitly sets the per-item path; the resolved path
    // happens to equal the outer default so the on-chain output is
    // unchanged, but this exercises the override branch
    // (`item.path.is_empty() ? outer : item.path`).
    let mut item1 = eip1559_no_access_list_item();
    item1.path = ETH_PATH.to_string();

    let data = SignTxsInput {
        items: vec![legacy_item(), item1, eip1559_multi_access_list_item()],
    }
    .encode_to_vec();
    let res = sign_txs(&data, &make_sign_param(ETH_PATH)).unwrap();
    let output = SignTxsOutput::decode(res.as_slice()).unwrap();

    assert_eq!(output.outputs.len(), 3);

    assert_eq!(output.outputs[0].signature, LEGACY_SIGNATURE);
    assert_eq!(output.outputs[0].tx_hash, LEGACY_TX_HASH);

    assert_eq!(output.outputs[1].signature, EIP1559_NO_AL_SIGNATURE);
    assert_eq!(output.outputs[1].tx_hash, EIP1559_NO_AL_TX_HASH);

    assert_eq!(output.outputs[2].signature, EIP1559_MULTI_AL_SIGNATURE);
    assert_eq!(output.outputs[2].tx_hash, EIP1559_MULTI_AL_TX_HASH);
}
