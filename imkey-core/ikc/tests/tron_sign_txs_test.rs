//! Full TRON batch-signing integration tests.
//!
//! Every request in this file crosses the public C ABI:
//! `ImkeyAction -> call_imkey_api -> sign_txs dispatcher -> TRON signer`.
//! Static rejection cases run without a device. Successful signing and
//! device-side sender rejection are ignored by default because they require a
//! bound imKey and physical confirmations.

use std::ffi::{CStr, CString};

use coin_tron::tronapi::{SignTxsInput, SignTxsItem, SignTxsOutput, TronTxInput, TronTxOutput};
use connector::api::{AddressParam, AddressResult, ErrorResponse, ImkeyAction};
use connector::{
    call_imkey_api, imkey_clear_err, imkey_free_const_string, imkey_get_last_err_message,
};
use ikc_common::utility::sha256_hash;
use ikc_common::SignParam;
use ikc_device::device_binding::bind_test;
use prost::Message;

const OUTER_PATH: &str = "m/44'/195'/0'/0/0";
const OVERRIDE_PATH: &str = "m/44'/195'/0'/0/1";
const RAW_DATA: &str = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d";
const RECEIVER: &str = "TDQqAkUUVYBuzaykLKCVwEeS3gFdM69jQo";

fn action(method: &str, param: impl Message) -> ImkeyAction {
    ImkeyAction {
        method: method.to_string(),
        param: Some(prost_types::Any {
            type_url: format!("imkey.{}", method),
            value: param.encode_to_vec(),
        }),
    }
}

fn read_and_release(ptr: *const std::os::raw::c_char) -> String {
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("C API must return UTF-8 hex")
        .to_string();
    unsafe { imkey_free_const_string(ptr) };
    value
}

fn call(action: ImkeyAction) -> Result<Vec<u8>, String> {
    unsafe { imkey_clear_err() };
    let action_hex = hex::encode(action.encode_to_vec());
    let request = CString::new(action_hex).unwrap();
    let response_hex = read_and_release(unsafe { call_imkey_api(request.as_ptr()) });

    if !response_hex.is_empty() {
        return hex::decode(response_hex).map_err(|err| err.to_string());
    }

    let error_hex = read_and_release(unsafe { imkey_get_last_err_message() });
    if error_hex.is_empty() {
        return Err("call_imkey_api returned neither result nor error".to_string());
    }
    let error_bytes = hex::decode(error_hex).map_err(|err| err.to_string())?;
    let error = ErrorResponse::decode(error_bytes.as_slice()).map_err(|err| err.to_string())?;
    Err(error.error)
}

fn batch_param(path: &str, items: Vec<SignTxsItem>) -> SignParam {
    SignParam {
        chain_type: "TRON".to_string(),
        path: path.to_string(),
        network: "MAINNET".to_string(),
        input: Some(prost_types::Any {
            type_url: "tronapi.SignTxsInput".to_string(),
            value: SignTxsInput { items }.encode_to_vec(),
        }),
        payment: String::new(),
        receiver: String::new(),
        sender: String::new(),
        fee: String::new(),
        seg_wit: String::new(),
    }
}

fn single_param(path: &str, sender: &str) -> SignParam {
    SignParam {
        chain_type: "TRON".to_string(),
        path: path.to_string(),
        network: "MAINNET".to_string(),
        input: Some(prost_types::Any {
            type_url: "tronapi.TronTxInput".to_string(),
            value: TronTxInput {
                raw_data: RAW_DATA.to_string(),
            }
            .encode_to_vec(),
        }),
        payment: "0.1 TRX".to_string(),
        receiver: RECEIVER.to_string(),
        sender: sender.to_string(),
        fee: String::new(),
        seg_wit: String::new(),
    }
}

fn item(raw_data: &str, sender: &str, path: &str) -> SignTxsItem {
    SignTxsItem {
        tx: Some(TronTxInput {
            raw_data: raw_data.to_string(),
        }),
        payment: "0.1 TRX".to_string(),
        receiver: RECEIVER.to_string(),
        sender: sender.to_string(),
        path: path.to_string(),
    }
}

fn get_address(path: &str) -> String {
    let param = AddressParam {
        chain_type: "TRON".to_string(),
        path: path.to_string(),
        network: "MAINNET".to_string(),
        seg_wit: String::new(),
    };
    let encoded = call(action("get_address", param)).unwrap();
    AddressResult::decode(encoded.as_slice()).unwrap().address
}

fn expected_tx_hash() -> String {
    hex::encode(sha256_hash(&hex::decode(RAW_DATA).unwrap()))
}

#[test]
fn call_imkey_api_rejects_empty_tron_batch() {
    let error = call(action("sign_txs", batch_param(OUTER_PATH, vec![]))).unwrap_err();
    assert_eq!(error, "sign_txs batch is empty");
}

#[test]
fn call_imkey_api_preflights_the_entire_tron_batch() {
    let items = vec![item(RAW_DATA, "sender", ""), item("not-hex", "sender", "")];
    let error = call(action("sign_txs", batch_param(OUTER_PATH, items))).unwrap_err();

    assert!(error.contains("sign_txs failed at index 1"));
    assert!(error.contains("invalid raw_data hex"));
}

#[test]
#[ignore = "requires a bound imKey device and physical confirmations"]
fn call_imkey_api_tron_batch_matches_single_signing() {
    bind_test();
    let outer_sender = get_address(OUTER_PATH);
    let override_sender = get_address(OVERRIDE_PATH);

    let single_outer = TronTxOutput::decode(
        call(action("sign_tx", single_param(OUTER_PATH, &outer_sender)))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let single_override = TronTxOutput::decode(
        call(action(
            "sign_tx",
            single_param(OVERRIDE_PATH, &override_sender),
        ))
        .unwrap()
        .as_slice(),
    )
    .unwrap();

    let n1 = SignTxsOutput::decode(
        call(action(
            "sign_txs",
            batch_param(OUTER_PATH, vec![item(RAW_DATA, &outer_sender, "")]),
        ))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    assert_eq!(n1.outputs.len(), 1);
    assert_eq!(
        n1.outputs[0].tx.as_ref().unwrap().signature,
        single_outer.signature
    );

    let batch = SignTxsOutput::decode(
        call(action(
            "sign_txs",
            batch_param(
                OUTER_PATH,
                vec![
                    item(RAW_DATA, &outer_sender, ""),
                    item(RAW_DATA, &override_sender, OVERRIDE_PATH),
                ],
            ),
        ))
        .unwrap()
        .as_slice(),
    )
    .unwrap();

    assert_eq!(batch.outputs.len(), 2);
    assert_eq!(
        batch.outputs[0].tx.as_ref().unwrap().signature,
        single_outer.signature
    );
    assert_eq!(
        batch.outputs[1].tx.as_ref().unwrap().signature,
        single_override.signature
    );
    assert_eq!(batch.outputs[0].tx_hash, expected_tx_hash());
    assert_eq!(batch.outputs[1].tx_hash, expected_tx_hash());
    assert_eq!(batch.outputs[0].from_address, outer_sender);
    assert_eq!(batch.outputs[1].from_address, override_sender);
}

#[test]
#[ignore = "requires a bound imKey device and physical confirmations"]
fn call_imkey_api_tron_batch_rejects_sender_mismatch_without_output() {
    bind_test();
    let sender = get_address(OUTER_PATH);
    let items = vec![
        item(RAW_DATA, &sender, ""),
        item(RAW_DATA, "TInvalidSenderForDeviceValidation", ""),
    ];
    let error = call(action("sign_txs", batch_param(OUTER_PATH, items))).unwrap_err();

    assert!(error.contains("sign_txs failed at index 1"));
}
