use crate::api::{AddressParam, ErrorResponse, ExternalAddressParam, ImkeyAction, PubKeyParam};
use failure::Error;
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
pub mod tezos_address;
pub mod tezos_signer;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate failure;
use crate::error_handling::{landingpad, LAST_BACKTRACE, LAST_ERROR};
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
    CStr::from_ptr(s);
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
                _ => Err(format_err!("get_address unsupported_chain")),
            }
        }),

        "get_pub_key" => landingpad(|| {
            let param: PubKeyParam = PubKeyParam::decode(action.param.unwrap().value.as_slice())
                .expect("imkey_illegal_param");
            match param.chain_type.as_str() {
                "EOS" => eos_pubkey::get_eos_pubkey(&param),
                "TEZOS" => tezos_address::get_pub_key(&param),
                "COSMOS" => cosmos_address::get_cosmos_pub_key(&param),
                _ => Err(format_err!("get_pub_key unsupported_chain")),
            }
        }),

        "register_pub_key" => landingpad(|| {
            let param: PubKeyParam = PubKeyParam::decode(action.param.unwrap().value.as_slice())
                .expect("imkey_illegal_param");
            match param.chain_type.as_str() {
                "EOS" => eos_pubkey::display_eos_pubkey(&param),
                _ => Err(format_err!("register_pub_key unsupported_chain")),
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
                _ => Err(format_err!("register_address unsupported_chain")),
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
                _ => Err(format_err!("sign_tx unsupported_chain")),
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
                _ => Err(format_err!(
                    "sign message is not supported the chain {}",
                    param.chain_type
                )),
            }
        }),

        "batch_sign_message" => landingpad(|| {
            let param: SignParam = SignParam::decode(action.param.unwrap().value.as_slice())
                .expect("unpack sign_message param error");
            match param.chain_type.as_str() {
                "ETHEREUM" => ethereum_signer::sign_eth_message(
                    param.clone().input.unwrap().value.as_slice(),
                    &param,
                ),
                _ => Err(format_err!(
                    "batch sign message is not supported the chain {}",
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
                _ => Err(format_err!("only support calc bitcoin external address")),
            }
        }),

        "btc_get_xpub" => landingpad(|| btc_address::get_btc_xpub(&action.param.unwrap().value)),

        _ => landingpad(|| Err(format_err!("unsupported_method"))),
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
    LAST_BACKTRACE.with(|e| {
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
    use error_handling::Result;
    use std::ffi::{CStr, CString};
    use std::fs::remove_file;
    use std::os::raw::c_char;
    use std::panic;
    use std::path::Path;

    use prost::Message;

    use crate::api::CommonResponse;
    use ikc_device::device_binding::DeviceManage;
    use ikc_device::deviceapi::{AppDownloadReq, BindAcquireReq};
    use ikc_transport::hid_api::hid_connect;
    use std::fs;

    fn _to_c_char(str: &str) -> *const c_char {
        CString::new(str).unwrap().into_raw()
    }

    fn _to_str(json_str: *const c_char) -> &'static str {
        let json_c_str = unsafe { CStr::from_ptr(json_str) };
        json_c_str.to_str().unwrap()
    }

    fn teardown() {
        let p = Path::new("/tmp/imtoken/wallets");
        let walk_dir = std::fs::read_dir(p).expect("read dir");
        for entry in walk_dir {
            let entry = entry.expect("DirEntry");
            let fp = entry.path();
            if !fp
                .file_name()
                .expect("file_name")
                .to_str()
                .expect("file_name str")
                .ends_with(".json")
            {
                continue;
            }

            remove_file(fp.as_path()).expect("should remove file");
        }
    }

    // fn run_test<T>(test: T) -> ()
    //     where
    //         T: FnOnce() -> () + panic::UnwindSafe,
    // {
    //     setup();
    //     let result = panic::catch_unwind(|| test());
    //     teardown();
    //     assert!(result.is_ok())
    // }

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
        hid_connect("imKey Pro").is_ok();
        let check_result =
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
}
