use crate::api::{AddressParam, ErrorResponse, ExternalAddressParam, ImkeyAction, PubKeyParam};
use anyhow::{anyhow, Error};
use ikc_common::SignParam;
use prost::Message;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::result;

pub mod api;
pub mod bch_address;
pub mod bch_signer;
pub mod btc_address;
pub mod btc_fork_address;
pub mod btc_fork_signer;
pub mod btc_signer;
pub mod cosmos_address;
pub mod cosmos_signer;
pub mod device_manager;
pub mod eos_pubkey;
pub mod eos_signer;
pub mod error_handling;
pub mod ethereum_address;
pub mod ethereum_signer;
pub mod filecoin_address;
pub mod filecoin_signer;
pub mod message_handler;
pub mod nervos_address;
pub mod nervos_signer;
pub mod substrate_address;
pub mod substrate_signer;
pub mod tron_address;
pub mod tron_signer;

use parking_lot::Mutex;
mod handler;
pub mod tezos_address;
pub mod tezos_signer;

#[macro_use]
extern crate lazy_static;
extern crate anyhow;
use crate::error_handling::{landingpad, LAST_ERROR};
use crate::handler::derive_accounts;
use crate::message_handler::encode_message;
use ikc_transport::message;

lazy_static! {
    pub static ref API_LOCK: Mutex<String> = Mutex::new("".to_string());
}

pub type Result<T> = result::Result<T, Error>;

#[no_mangle]
pub extern "C" fn get_apdu() -> *const c_char {
    message::get_apdu()
}

#[no_mangle]
pub extern "C" fn set_apdu(apdu: *const c_char) {
    message::set_apdu(apdu);
}

#[no_mangle]
pub extern "C" fn get_apdu_return() -> *const c_char {
    message::get_apdu_return()
}

#[no_mangle]
pub extern "C" fn set_apdu_return(apdu_return: *const c_char) {
    message::set_apdu_return(apdu_return);
}

#[no_mangle]
pub extern "C" fn set_callback(
    callback: extern "C" fn(apdu: *const c_char, timeout: i32) -> *const c_char,
) {
    message::set_callback(callback);
}

#[no_mangle]
pub unsafe extern "C" fn imkey_free_const_string(s: *const c_char) {
    if s.is_null() {
        return;
    }
    let _ = CStr::from_ptr(s);
}

/// dispatch protobuf rpc call
#[no_mangle]
pub unsafe extern "C" fn call_imkey_api(hex_str: *const c_char) -> *const c_char {
    let mut _l = API_LOCK.lock();
    let hex_c_str = CStr::from_ptr(hex_str);
    let hex_str = hex_c_str.to_str().expect("parse_arguments to_str");

    let data = hex::decode(hex_str).expect("imkey_illegal_prarm");
    let action: ImkeyAction = ImkeyAction::decode(data.as_slice()).expect("decode imkey api");
    let reply: Result<Vec<u8>> = match action.method.to_lowercase().as_str() {
        "init_imkey_core_x" => {
            landingpad(|| device_manager::init_imkey_core(&action.param.unwrap().value))
        }
        // imkey manager
        "app_download" => landingpad(|| device_manager::app_download(&action.param.unwrap().value)),
        "app_update" => landingpad(|| device_manager::app_update(&action.param.unwrap().value)),
        "app_delete" => landingpad(|| device_manager::app_delete(&action.param.unwrap().value)),
        "device_activate" => landingpad(|| device_manager::se_activate()),
        "check_update" => landingpad(|| device_manager::check_update()),
        "device_secure_check" => landingpad(|| device_manager::se_secure_check()),
        "bind_check" => landingpad(|| device_manager::bind_check()),
        "bind_display_code" => landingpad(|| device_manager::bind_display_code()),
        "bind_acquire" => landingpad(|| device_manager::bind_acquire(&action.param.unwrap().value)),
        "get_seid" => landingpad(|| device_manager::get_seid()),
        "get_sn" => landingpad(|| device_manager::get_sn()),
        "get_ram_size" => landingpad(|| device_manager::get_ram_size()),
        "get_firmware_version" => landingpad(|| device_manager::get_firmware_version()),
        "get_battery_power" => landingpad(|| device_manager::get_battery_power()),
        "get_life_time" => landingpad(|| device_manager::get_life_time()),
        "get_ble_name" => landingpad(|| device_manager::get_ble_name()),
        "set_ble_name" => landingpad(|| device_manager::set_ble_name(&action.param.unwrap().value)),
        "get_ble_version" => landingpad(|| device_manager::get_ble_version()),
        "get_sdk_info" => landingpad(|| device_manager::get_sdk_info()),
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        "cos_update" => landingpad(|| device_manager::cos_update()),
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        "cos_check_update" => landingpad(|| device_manager::cos_check_update()),
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        "device_connect" => {
            landingpad(|| device_manager::device_connect(&action.param.unwrap().value))
        }
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        "is_bl_status" => landingpad(|| device_manager::is_bl_status()),

        "get_address" => landingpad(|| {
            let param: AddressParam = AddressParam::decode(action.param.unwrap().value.as_slice())
                .expect("imkey_illegal_param");
            match param.chain_type.as_str() {
                "BITCOIN" => btc_address::get_address(&param),
                "ETHEREUM" => ethereum_address::get_address(&param),
                "COSMOS" => cosmos_address::get_address(&param),
                "FILECOIN" => filecoin_address::get_address(&param),
                "POLKADOT" => substrate_address::get_address(&param),
                "KUSAMA" => substrate_address::get_address(&param),
                "TRON" => tron_address::get_address(&param),
                "NERVOS" => nervos_address::get_address(&param),
                "TEZOS" => tezos_address::get_address(&param),
                "BITCOINCASH" => bch_address::get_address(&param),
                "LITECOIN" => btc_fork_address::get_address(&param),
                _ => Err(anyhow!("get_address unsupported_chain")),
            }
        }),
        "derive_accounts" => landingpad(|| derive_accounts(&action.param.unwrap().value)),
        "get_pub_key" => landingpad(|| {
            let param: PubKeyParam = PubKeyParam::decode(action.param.unwrap().value.as_slice())
                .expect("imkey_illegal_param");
            match param.chain_type.as_str() {
                "EOS" => eos_pubkey::get_eos_pubkey(&param),
                "TEZOS" => tezos_address::get_pub_key(&param),
                "COSMOS" => cosmos_address::get_cosmos_pub_key(&param),
                _ => Err(anyhow!("get_pub_key unsupported_chain")),
            }
        }),

        "register_pub_key" => landingpad(|| {
            let param: PubKeyParam = PubKeyParam::decode(action.param.unwrap().value.as_slice())
                .expect("imkey_illegal_param");
            match param.chain_type.as_str() {
                "EOS" => eos_pubkey::display_eos_pubkey(&param),
                _ => Err(anyhow!("register_pub_key unsupported_chain")),
            }
        }),

        "register_address" => landingpad(|| {
            let param: AddressParam = AddressParam::decode(action.param.unwrap().value.as_slice())
                .expect("imkey_illegal_param");
            match param.chain_type.as_str() {
                "BITCOIN" => btc_address::register_btc_address(&param),
                "ETHEREUM" => ethereum_address::register_address(&param),
                "COSMOS" => cosmos_address::display_cosmos_address(&param),
                "FILECOIN" => filecoin_address::display_filecoin_address(&param),
                "POLKADOT" => substrate_address::display_address(&param),
                "KUSAMA" => substrate_address::display_address(&param),
                "TRON" => tron_address::display_address(&param),
                "NERVOS" => nervos_address::display_address(&param),
                "TEZOS" => tezos_address::display_tezos_address(&param),
                _ => Err(anyhow!("register_address unsupported_chain")),
            }
        }),

        "sign_tx" => landingpad(|| {
            let param: SignParam = SignParam::decode(action.param.unwrap().value.as_slice())
                .expect("sign_tx unpack error");
            match param.chain_type.as_str() {
                "BITCOIN" => {
                    btc_signer::sign_btc_transaction(&param.clone().input.unwrap().value, &param)
                }
                "ETHEREUM" => ethereum_signer::sign_eth_transaction(
                    &param.clone().input.unwrap().value,
                    &param,
                ),
                "EOS" => {
                    eos_signer::sign_eos_transaction(&param.clone().input.unwrap().value, &param)
                }
                "COSMOS" => cosmos_signer::sign_cosmos_transaction(
                    &param.clone().clone().input.unwrap().value,
                    &param,
                ),
                "FILECOIN" => filecoin_signer::sign_filecoin_transaction(
                    &param.clone().input.unwrap().value,
                    &param,
                ),
                "POLKADOT" => {
                    substrate_signer::sign_transaction(&param.clone().input.unwrap().value, &param)
                }
                "KUSAMA" => {
                    substrate_signer::sign_transaction(&param.clone().input.unwrap().value, &param)
                }
                "TRON" => {
                    tron_signer::sign_transaction(&param.clone().input.unwrap().value, &param)
                }
                "NERVOS" => {
                    nervos_signer::sign_transaction(&param.clone().input.unwrap().value, &param)
                }
                "TEZOS" => tezos_signer::sign_tezos_transaction(
                    &param.clone().input.unwrap().value,
                    &param,
                ),
                "BITCOINCASH" => {
                    bch_signer::sign_transaction(&param.clone().input.unwrap().value, &param)
                }
                "LITECOIN" => {
                    btc_fork_signer::sign_transaction(&param.clone().input.unwrap().value, &param)
                }
                _ => Err(anyhow!("sign_tx unsupported_chain")),
            }
        }),

        "sign_message" => landingpad(|| {
            let param: SignParam = SignParam::decode(action.param.unwrap().value.as_slice())
                .expect("unpack sign_message param error");
            match param.chain_type.as_str() {
                "ETHEREUM" => ethereum_signer::sign_eth_message(
                    param.clone().input.unwrap().value.as_slice(),
                    &param,
                ),
                "EOS" => eos_signer::sign_eos_message(
                    param.clone().input.unwrap().value.as_slice(),
                    &param,
                ),
                "TRON" => tron_signer::sign_message(&param.clone().input.unwrap().value, &param),
                _ => Err(anyhow!(
                    "sign message is not supported the chain {}",
                    param.chain_type
                )),
            }
        }),

        // btc
        "calc_external_address" => landingpad(|| {
            let param: ExternalAddressParam =
                ExternalAddressParam::decode(action.param.unwrap().value.as_slice())
                    .expect("calc external address unpack error");
            match param.chain_type.as_str() {
                "BITCOIN" => btc_address::calc_external_address(&param),
                _ => Err(anyhow!("only support calc bitcoin external address")),
            }
        }),

        "btc_get_xpub" => landingpad(|| btc_address::get_btc_xpub(&action.param.unwrap().value)),

        _ => landingpad(|| Err(anyhow!("unsupported_method"))),
    };
    match reply {
        Ok(reply) => {
            let ret_str = hex::encode(reply);
            CString::new(ret_str).unwrap().into_raw()
        }
        _ => CString::new("").unwrap().into_raw(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn imkey_clear_err() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

#[no_mangle]
pub unsafe extern "C" fn imkey_get_last_err_message() -> *const c_char {
    LAST_ERROR.with(|e| {
        if let Some(ref err) = *e.borrow() {
            let rsp = ErrorResponse {
                is_success: false,
                error: err.to_string(),
            };
            let rsp_bytes = encode_message(rsp).expect("encode error");
            let ret_str = hex::encode(rsp_bytes);
            CString::new(ret_str).unwrap().into_raw()
        } else {
            CString::new("").unwrap().into_raw()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::derive_accounts_param::Derivation;
    use crate::api::{CommonResponse, DeriveAccountsParam, DeriveAccountsResult};
    use ikc_device::device_binding::DeviceManage;
    use ikc_device::deviceapi::{BindAcquireReq, BindCheckRes};
    use ikc_transport::hid_api::hid_connect;
    use prost::Message;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    fn _to_c_char(str: &str) -> *const c_char {
        CString::new(str).unwrap().into_raw()
    }

    fn _to_str(json_str: *const c_char) -> &'static str {
        let json_c_str = unsafe { CStr::from_ptr(json_str) };
        json_c_str.to_str().unwrap()
    }

    #[test]
    #[ignore]
    fn call_api() {
        // let param = TcxAction {
        //     method: method.to_string(),
        //     param: Some(::prost_types::Any {
        //         type_url: "imtoken".to_string(),
        //         value: encode_message(msg).unwrap(),
        //     }),
        // };

        // let err_bytes = hex::decode("1233e69caae883bde5ae8ce68890e6938de4bd9ce38082efbc88746f6b656e2e4170694572726f72e99499e8afaf31e38082efbc89").unwrap();
        // let err: ErrorResponse = ErrorResponse::decode(err_bytes.as_slice()).unwrap();
        // assert_eq!("err", err.error);

        // assert_eq!(true, is_valid_hex("0x9d30F9D302989cA1df6e4DB8361fc2535997Cfb7f7e98fc1-2bb1-4588-9803-5f409ce7e3a2"), "is invalid hex");
        // let param = hex::decode("124263616c6c65642060526573756c743a3a756e77726170282960206f6e20616e2060457272602076616c75653a20496d6b6579557365724e6f74436f6e6669726d6564").unwrap();
        // let action: ImkeyAction = ImkeyAction::decode(param.as_slice()).unwrap();
        // let param: SignParam =
        //     SignParam::decode(action.param.unwrap().value.as_slice()).unwrap();
        // assert_eq!("action", param.chain_type);

        // let param: AppDownloadReq = AppDownloadReq::decode(err.param.unwrap().value.as_slice()).unwrap();
        // assert_eq!("action", param.app_name);
        // let param: AppDownloadReq = AppDownloadReq {
        //     app_name: "FILECOIN".to_string()
        // };
        // let action: ImkeyAction = ImkeyAction {
        //     method: "app_download".to_string(),
        //     param: Some(::prost_types::Any {
        //         type_url: "deviceapi.AppDownloadReq".to_string(),
        //         value: encode_message(param).unwrap(),
        //     })
        // };
        // assert_eq!("", hex::encode(encode_message(action).unwrap()));
        let _ = unsafe { imkey_clear_err() };
        // let param_bytes = encode_message(param).unwrap();
        // let param_bytes = hex::decode("0a0c636865636b5f757064617465").unwrap();
        // let param_hex = hex::encode(param_bytes);
        assert!(hid_connect("imKey Pro").is_ok());
        let _check_result =
            DeviceManage::bind_check(&"../test-data".to_string()).unwrap_or_default();
        // DeviceManage::bind_acquire(&"".to_string()).unwrap();
        // device::device_manager::app_delete("BCH");
        // device::device_manager::app_download("BTC");
        let ret_hex = unsafe {
            _to_str(call_imkey_api(_to_c_char(&"0a077369676e5f747812e6030a10636f6d6d6f6e2e5369676e506172616d12d1030a0b424954434f494e4341534812116d2f3434272f313435272f30272f302f301a074d41494e4e455422b2020a19627463666f726b6170692e427463466f726b5478496e7075741294020a2a71707a36376763776139616738346c6a6d6d6e33753774636a6d39726b63326a66636a6b32717a66637510a08d061aaa010a4061346439666561373337636236633030326337613833666235383531613366373566306163646437626237663137373232633162323465653765306232336461100018c09a0c222a7171687979616a75323270637967783870683035716a6e787978616c686d65736b796371706d67786e302a323736613931343265343237363563353238333832323063373064646634303461363632316262666265663330623138386163320020c6032801322a7171687979616a75323270637967783870683035716a6e787978616c686d65736b796371706d67786e303a044e4f4e452a09302e30303120424348322a71707a36376763776139616738346c6a6d6d6e33753774636a6d39726b63326a66636a6b32717a6663753a2a7171687979616a75323270637967783870683035716a6e787978616c686d65736b796371706d67786e30420e302e303030303034353420424348")))
        };
        let err = unsafe { _to_str(imkey_get_last_err_message()) };
        if !err.is_empty() {
            let err_bytes = hex::decode(err).unwrap();
            let err_ret: ErrorResponse = ErrorResponse::decode(err_bytes.as_slice()).unwrap();
            assert_eq!("err", err_ret.error)
        } else {
            let ret_bytes = hex::decode(ret_hex).unwrap();

            let ret: CommonResponse = CommonResponse::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!("ret", ret.result)
        }
    }

    #[test]
    fn test_derive_accounts() {
        assert!(hid_connect("imKey Pro").is_ok());
        let action: ImkeyAction = ImkeyAction {
            method: "bind_check".to_string(),
            param: None,
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        let bind_result: BindCheckRes = BindCheckRes::decode(ret_bytes.as_slice()).unwrap();
        if "bound_other".eq(&bind_result.bind_status) {
            let param = BindAcquireReq {
                bind_code: "7FVRAJJ7".to_string(),
            };
            let action: ImkeyAction = ImkeyAction {
                method: "bind_acquire".to_string(),
                param: Some(::prost_types::Any {
                    type_url: "deviceapi.bind_acquire".to_string(),
                    value: encode_message(param).unwrap(),
                }),
            };
            let action = hex::encode(encode_message(action).unwrap());
            let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
            let ret_bytes = hex::decode(ret_hex).unwrap();
            let bind_result: BindCheckRes = BindCheckRes::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!("success", bind_result.bind_status);
        }

        let derivations = vec![
            Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/44'/2'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/49'/2'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/49'/1'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "NERVOS".to_string(),
                path: "m/44'/309'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "m/44'/461'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "EOS".to_string(),
                path: "m/44'/194'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/44'/0'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/49'/0'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "m/44'/434'/0'/0'/0'".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "ed25519".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "POLKADOT".to_string(),
                path: "m/44'/354'/0'/0'/0'".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "ed25519".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOINCASH".to_string(),
                path: "m/44'/145'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "NERVOS".to_string(),
                path: "m/44'/309'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
        ];
        let param = DeriveAccountsParam { derivations };
        let action: ImkeyAction = ImkeyAction {
            method: "derive_accounts".to_string(),
            param: Some(::prost_types::Any {
                type_url: "deviceapi.derive_accounts".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        let derived_accounts: DeriveAccountsResult =
            DeriveAccountsResult::decode(ret_bytes.as_slice()).unwrap();

        assert_eq!(
            "Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP",
            derived_accounts.accounts[0].address
        );
        assert_eq!(
            "0x0289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7b",
            derived_accounts.accounts[0].public_key
        );
        assert_eq!("xpub6D3MqTwuLWB5veAfhDjPu1oHfS6L1imVbf22zQFWJW9EtnSmYYqiGMGkW1MCsT2HmkW872tefMY9deewW6DGd8zE7RcXVv8wKhZnbJeidjT", derived_accounts.accounts[0].extended_public_key);
        assert_eq!("MwDMFXVWDEuWvBogeW1v/MOMFDnGnnflm2JAPvJaJZO4HXp8fCsWETA7u8MzOW3KaPksglpUHLN3xkDr2QWMEQq0TewFZoZ3KsjmLW0KGMRN7XQKqo/omkSEsPfalVnp9Zxm2lpxVmIacqvlernVSg==", derived_accounts.accounts[0].encrypted_extended_public_key);

        assert_eq!(
            "MQHaFwU3DiWQoz48TqZHtZ4jF7tFDj9yQF",
            derived_accounts.accounts[1].address
        );
        assert_eq!(
            "0x03ace3b0da84c9944a077d62fc839c95324c2bdaa01786353f5538f89fbc24f428",
            derived_accounts.accounts[1].public_key
        );
        assert_eq!("ypub6Y37Xmn4afXWyQduPKYWPXSbX6YUCewxo4qKJqqtKsGJzPnS95QNT261uvzfQJH95CeuGn3xEysWHau3knBKxy1tNs21HipL9cpG1LJy4Wc", derived_accounts.accounts[1].extended_public_key);
        assert_eq!("ypB3aQxsFPVl6EJAnDGiGh6UaUrh1bXsGFG7teh1fOJdkdcjq8vNCNh1f4MDYrjt71xA9cZ9y2iTRuSGdU0doLJkqdQ/VkRaGOlN4fsO2L+oBqUwxKQc0iHxsjrrNEBcge//2RglytnelFnGJHmzVw==", derived_accounts.accounts[1].encrypted_extended_public_key);

        assert_eq!(
            "mpke4CzhBTV2dFZpnABT9EN1kPc4vDWZxw",
            derived_accounts.accounts[2].address
        );
        assert_eq!(
            "0x031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc",
            derived_accounts.accounts[2].public_key
        );
        assert_eq!("upub5E4woDJohDBJ2trk6HqhsvEeZXtjjWMAbHV4LWRhfR9thcpfkjJbBRnvBS21L2JjsZAGC6LhkqAoYgD5VHSXBRNW7gszbiGJP7B6CR35QhD", derived_accounts.accounts[2].extended_public_key);
        assert_eq!("ZDxvs7NEiNuUO/iXWvB2WvWmxXmQ+eP2qrEZe165dWLBm0PJpeRncYu+mZVUJJe0o6QUbnVop5TRqUBmRUzcxPioSmOVlzRpxOeUBZmaUi48hIwid1ouBZZ1zakxGLLnK4DyJN9NkyNDllKqxVhpdg==", derived_accounts.accounts[2].encrypted_extended_public_key);

        assert_eq!(
            "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2",
            derived_accounts.accounts[3].address
        );
        assert_eq!(
            "0x037b5253c24ce2a293566f9e066051366cda5073e4a43b25f07c990d7c9ac0aab5",
            derived_accounts.accounts[3].public_key
        );
        assert_eq!("tpubDCxD6k9PreNhSacpfSZ3iErESZnncY1n7qU7e3stZXLPh84xVVt5ERMAqKeefUU8jswx2GpCkQpeYow4xH3PGx2iim6ftPa32GNvTKAtknz", derived_accounts.accounts[3].extended_public_key);
        assert_eq!("A6SCjz/iYksc/3pnVnMIzXimsQAm2p4EUJ1T6fRYkeHSqtSuBcF7O2Fyt3lYbiD4RoL1wf6VfknDiLdS1mcJyD09kXl5s+fuBaklKAZ2Dh6YuGlPGJqaGnrQ/rsTJ+Adb0ZRO3F3xGadXjiGb3hTSA==", derived_accounts.accounts[3].encrypted_extended_public_key);

        assert_eq!(
            "ckt1qyqtr684u76tu7r8efkd24hw8922xfvhnazskzdzy6",
            derived_accounts.accounts[4].address
        );
        assert_eq!(
            "0x03554851980004ff256888612bf0d64d9b1002bf82331450fd5a7405d1b23cc5bd",
            derived_accounts.accounts[4].public_key
        );
        assert_eq!("tpubDDMZ3uNczagkRgAQBT6vmHFwM6Tc8RwYKU4ufqywmZEUNVfYNNyrVyXgmSpDTVsthVEbEzH5QjhxQPExpjBtVXVWZinpdRjiRGtpXuALuND", derived_accounts.accounts[4].extended_public_key);
        assert_eq!("VXhh0t5/x2aZJI0mKfkYREXX/VWw7PVEz4Gyf1bj9DS9ETRShdPA519gJMrbw8XJVk/p8X+ixbYras39ITKtl7KOSaE+E2T126r2NAR0gXRWOLIp2rrpnVWerlBkzjkoJ1KOKIPIIYhZYP7kn+tbSQ==", derived_accounts.accounts[4].encrypted_extended_public_key);

        assert_eq!(
            "t12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey",
            derived_accounts.accounts[5].address
        );
        assert_eq!(
            "0x03bd460186d29fd9ac68ee88b110c3acc4a4443648a1ec7607af9ce306ad76f785",
            derived_accounts.accounts[5].public_key
        );
        assert_eq!("tpubDDaEZaaDDmwnZTP6u7m3yTKFgnbSx2uTaxp1hKM5oiVZo6iBB46rWnWpdkpbPxtfdYiyLbyhqgbXRXYff3LfW4rCpYyfpb5pC67CPZdKkZB", derived_accounts.accounts[5].extended_public_key);
        assert_eq!("PRImz4qL7pDJsEtqNVzVG9llzx+DN1XFbucDahOvyQ9g9yc5HWMdH6jAx4Mc/syseMWHLj9Y17Mfqib3sl88Ddgs3tTXhJq6vWToyXlQ6t9yg/LX1qKzLKcXLD+W0872G5m1urk//YOLIyhPkaLV2g==", derived_accounts.accounts[5].encrypted_extended_public_key);

        assert_eq!(
            "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992",
            derived_accounts.accounts[6].address
        );
        assert_eq!(
            "0x0232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d65",
            derived_accounts.accounts[6].public_key
        );
        assert_eq!("xpub6CrWRZY39gj49G1ipdmcVunEnb5RoTGf9o6QnJQp8c4b84V2piN1Rdy1xWVJ4P7VXNx5Ckg6rZcvSNvJtvWz8zs3RkPayHn9vMMuK9ERrFr", derived_accounts.accounts[6].extended_public_key);
        assert_eq!("rJQ+jO02Yn+Rdfjn5QbStU/2aS0T5zW5HU83JoHLBZHafsr8FSdG7lPV59XAw1LwuUCMCtRBueG1iJ2AsA76PP1zyVzj0LxDIq3iHAOxBdwIZDP5C1sY+RMGwXk+6a2OwmYN/zF/q2SL8D6aeGyD9g==", derived_accounts.accounts[6].encrypted_extended_public_key);

        assert_eq!(
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
            derived_accounts.accounts[7].address
        );
        assert_eq!(
            "0x03aaf80e479aac0813b17950c390a16438b307aee9a814689d6706be4fb4a4e30a",
            derived_accounts.accounts[7].public_key
        );
        assert_eq!("xpub6CUtvjXi3yjmhjaC2GxjiWE9FbQs1TrtqAgRDhB2gmDBsPzTfwqZ7MvGGYScKiVx8PBNFSmHm4mCnFDCaX23c1nJS4p8ynR2wnGne4qEEX9", derived_accounts.accounts[7].extended_public_key);
        assert_eq!("jSPl9msMWjfMrj/09dRJ/epEWFnjjNHoOfro8xVrvcmhTnTC0iK+RDXXJ7iI2UpIa3ckFw7g2QGaVgODFQVLrEboEysXX5YMsPczdAUrdKh27vx5A3KMFylw2kVrUmSdoMDID8wlVfqkteyIHED0iQ==", derived_accounts.accounts[7].encrypted_extended_public_key);

        assert_eq!(
            "0x6031564e7b2F5cc33737807b2E58DaFF870B590b",
            derived_accounts.accounts[8].address
        );
        assert_eq!(
            "0x0280c98b8ea7cab630defb0c09a4295c2193cdee016c1d5b9b0cb18572b9c370fe",
            derived_accounts.accounts[8].public_key
        );
        assert_eq!("tpubDCvte6zYB6DKMaEy4fwyoXpuExA4ery3Hu6dVSBZeY9Rg57VKFLwNPMfywWtqRFM1Df5gQJTu42RaaNCgVEyngdVfnYRh9Kb1UCoEYojURc", derived_accounts.accounts[8].extended_public_key);
        assert_eq!("w6s0ZvUoPPSiEi1xDMKy5X9+qwhcX4u3e3LOBosJaOSro2ny9jppDxcczZfrhe29n9H3UkmgNoecq/85xfXkGDtH8PMR9iclK5WrcUtkgjXsBcrR6JF0j58i4W9x3y539vXOsLMifCmUr2RcqknDgw==", derived_accounts.accounts[8].encrypted_extended_public_key);

        assert_eq!(
            "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
            derived_accounts.accounts[9].address
        );
        assert_eq!(
            "0x026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            derived_accounts.accounts[9].public_key
        );
        assert_eq!("xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8", derived_accounts.accounts[9].extended_public_key);
        assert_eq!("BdgvWHN/Uh/K526q/+CdpGwEPZ41SvZHHGSgiSqhFesjErdbo6UnJMIoDOHV94qW8fd2KBW18UG3nTzDwS7a5oArqPtv+2aE9+1bNvCdtYoAx3979N3vbX4Xxn/najTABykXrJDjgpoaXxSo/xTktQ==", derived_accounts.accounts[9].encrypted_extended_public_key);

        assert_eq!(
            "3JmreiUEKn8P3SyLYmZ7C1YCd4r2nFy3Dp",
            derived_accounts.accounts[10].address
        );
        assert_eq!(
            "0x03036695c5f3de2e2792b170f59679d4db88a8516728012eaa42a22ce6f8bf593b",
            derived_accounts.accounts[10].public_key
        );
        assert_eq!("ypub6Wdz1gzMKLnPxXti2GbSjQGXSqrA5NMKNP3C5JS2ZJKRDEecuZH8AhSvYQs4dZHi7b6Yind7bLekuTH9fNbJcH1MXMy9meoifu2wST55sav", derived_accounts.accounts[10].extended_public_key);
        assert_eq!("8mPByX5qAwVJ2bVNqDrm6Jx19osoWZwplnAESPaN//Gx3Q9Gp2Q2bqkaDsxlYaYsUKN6FRzwrJHaSKD2A9aWJ3RoTWJ9zY9g21zW4ttsXFl1CAZNIlFCC9CnXd2b89vDgqCQC/foz50TV4PUikR+/g==", derived_accounts.accounts[10].encrypted_extended_public_key);

        assert_eq!(
            "Fde6T2hDvbvuQrRizcjPoQNZTxuVSbTp78zwFcxzUb86xXS",
            derived_accounts.accounts[11].address
        );
        assert_eq!(
            "0x873cf8e52a7b93a55197ef2846e9627a6f105b0a06c86659c813f1a50438b479",
            derived_accounts.accounts[11].public_key
        );
        assert_eq!("", derived_accounts.accounts[11].extended_public_key);
        assert_eq!(
            "",
            derived_accounts.accounts[11].encrypted_extended_public_key
        );

        assert_eq!(
            "16NhUkUTkYsYRjMD22Sop2DF8MAXUsjPcYtgHF3t1ccmohx1",
            derived_accounts.accounts[12].address
        );
        assert_eq!(
            "0xedb9955556c8e07287df95ad77fad826168f8a50488cce0d738df3769e24613a",
            derived_accounts.accounts[12].public_key
        );
        assert_eq!("", derived_accounts.accounts[12].extended_public_key);
        assert_eq!(
            "",
            derived_accounts.accounts[12].encrypted_extended_public_key
        );

        assert_eq!(
            "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r",
            derived_accounts.accounts[13].address
        );
        assert_eq!(
            "0x0251492dfb299f21e426307180b577f927696b6df0b61883215f88eb9685d3d449",
            derived_accounts.accounts[13].public_key
        );
        assert_eq!("xpub6Bmkv3mmRZZWoFSBdj9vDMqR2PCPSP6DEj8u3bBuv44g3Ncnro6cPVqZAw6wTEcxHQuodkuJG4EmAinqrrRXGsN3HHnRRMtAvzfYTiBATV1", derived_accounts.accounts[13].extended_public_key);

        assert_eq!(
            "ckb1qyqtr684u76tu7r8efkd24hw8922xfvhnazst8nagx",
            derived_accounts.accounts[14].address
        );
        assert_eq!(
            "0x03554851980004ff256888612bf0d64d9b1002bf82331450fd5a7405d1b23cc5bd",
            derived_accounts.accounts[14].public_key
        );
        assert_eq!("xpub6CyvXfYwHJjJ9syYjG7qZMva1yMx93SUmqUcKHvoReUadCzqJA8mMXrrXQjRvzveuahgdQmCsdsuiCkMRsLec63DW83Wwu5UqKJQmsonKpo", derived_accounts.accounts[14].extended_public_key);
    }
}
