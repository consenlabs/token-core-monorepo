#![feature(more_qualified_paths)]

use std::ffi::{CStr, CString};

use std::os::raw::c_char;

use anyhow::anyhow;
use handler::{backup, sign_bls_to_execution_change};
use migration::{mark_identity_wallets, read_legacy_keystore_mnemonic_path};
use prost::Message;

pub mod api;

use crate::api::{GeneralResult, TcxAction};

pub mod error_handling;
pub mod handler;
pub mod migration;
pub mod reset_password;
use anyhow::Error;
use std::result;

use crate::error_handling::{landingpad, LAST_ERROR};
#[cfg(feature = "cache_dk")]
use crate::handler::get_derived_key;
#[cfg(feature = "test_api")]
use crate::handler::unlock_then_crash;
use crate::handler::{
    create_keystore, decrypt_data_from_ipfs, delete_keystore, derive_accounts, derive_sub_accounts,
    encode_message, encrypt_data_to_ipfs, eth_batch_personal_sign, exists_json, exists_mnemonic,
    exists_private_key, export_json, export_mnemonic, export_private_key, get_extended_public_keys,
    get_public_keys, import_json, import_mnemonic, import_private_key, mnemonic_to_public,
    scan_keystores, sign_authentication_message, sign_hashes, sign_message, sign_psbt, sign_psbts,
    sign_tx, verify_password,
};
use crate::migration::{migrate_keystore, scan_legacy_keystores};

pub mod filemanager;
// mod identity;
mod macros;

use parking_lot::RwLock;
use tcx_common::{FromHex, ToHex};

extern crate serde_json;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref IS_DEBUG: RwLock<bool> = RwLock::new(false);
}

pub type Result<T> = result::Result<T, Error>;

/// # Safety
///
/// `s` must be null or a pointer returned by this library from `CString::into_raw`.
/// Each non-null pointer must be released exactly once.
#[no_mangle]
pub unsafe extern "C" fn free_const_string(s: *const c_char) {
    if s.is_null() {
        return;
    }
    let _ = CString::from_raw(s as *mut c_char);
}

unsafe fn parse_tcx_action(hex_str: *const c_char) -> Result<TcxAction> {
    if hex_str.is_null() {
        return Err(anyhow!("invalid_tcx_param:null_pointer"));
    }

    let hex_str = CStr::from_ptr(hex_str)
        .to_str()
        .map_err(|_| anyhow!("invalid_tcx_param:invalid_utf8"))?;
    let data = Vec::from_hex(hex_str).map_err(|_| anyhow!("invalid_tcx_param:invalid_hex"))?;
    TcxAction::decode(data.as_slice()).map_err(|_| anyhow!("invalid_tcx_param:invalid_protobuf"))
}

fn action_param_value(action: &TcxAction) -> Result<&[u8]> {
    action
        .param
        .as_ref()
        .map(|param| param.value.as_slice())
        .ok_or_else(|| anyhow!("invalid_tcx_param:missing_param"))
}

fn dispatch_tcx_action(action: &TcxAction) -> Result<Vec<u8>> {
    match action.method.to_lowercase().as_str() {
        "init_token_core_x" => {
            handler::init_token_core_x(action_param_value(action)?)?;
            Ok(vec![])
        }
        "scan_legacy_keystores" => {
            let ret = scan_legacy_keystores()?;
            encode_message(ret)
        }
        "scan_keystores" => {
            let ret = scan_keystores()?;
            encode_message(ret)
        }
        "read_keystore_mnemonic_path" => {
            read_legacy_keystore_mnemonic_path(action_param_value(action)?)
        }
        "create_keystore" => create_keystore(action_param_value(action)?),
        "import_mnemonic" => import_mnemonic(action_param_value(action)?),
        "export_mnemonic" => export_mnemonic(action_param_value(action)?),
        "derive_accounts" => derive_accounts(action_param_value(action)?),
        "import_private_key" => import_private_key(action_param_value(action)?),
        "export_private_key" => export_private_key(action_param_value(action)?),
        "verify_password" => verify_password(action_param_value(action)?),
        "delete_keystore" => delete_keystore(action_param_value(action)?),
        "exists_mnemonic" => exists_mnemonic(action_param_value(action)?),
        "exists_private_key" => exists_private_key(action_param_value(action)?),
        "derive_sub_accounts" => derive_sub_accounts(action_param_value(action)?),
        "sign_tx" | "sign_transaction" => sign_tx(action_param_value(action)?),
        "sign_msg" | "sign_message" => sign_message(action_param_value(action)?),
        "exists_json" => exists_json(action_param_value(action)?),
        "import_json" => import_json(action_param_value(action)?),
        "export_json" => export_json(action_param_value(action)?),
        "backup" => backup(action_param_value(action)?),

        #[cfg(feature = "cache_dk")]
        "get_derived_key" => get_derived_key(action_param_value(action)?),
        #[cfg(feature = "test_api")]
        "unlock_then_crash" => unlock_then_crash(action_param_value(action)?),

        "encrypt_data_to_ipfs" => encrypt_data_to_ipfs(action_param_value(action)?),
        "decrypt_data_from_ipfs" => decrypt_data_from_ipfs(action_param_value(action)?),
        "sign_authentication_message" => sign_authentication_message(action_param_value(action)?),
        "migrate_keystore" => migrate_keystore(action_param_value(action)?),
        "get_extended_public_keys" => get_extended_public_keys(action_param_value(action)?),
        "get_public_keys" => get_public_keys(action_param_value(action)?),
        "sign_hashes" | "sign_raw_hashes" => sign_hashes(action_param_value(action)?),
        "mnemonic_to_public" => mnemonic_to_public(action_param_value(action)?),
        "sign_bls_to_execution_change" => sign_bls_to_execution_change(action_param_value(action)?),
        "eth_batch_personal_sign" => eth_batch_personal_sign(action_param_value(action)?),
        "mark_identity_wallets" => mark_identity_wallets(action_param_value(action)?),
        "sign_psbt" => sign_psbt(action_param_value(action)?),
        "sign_psbts" => sign_psbts(action_param_value(action)?),
        _ => Err(anyhow!("unsupported_method")),
    }
}

fn empty_c_string() -> *const c_char {
    CString::new("")
        .expect("static empty string contains no NUL byte")
        .into_raw()
}

/// # Safety
///
/// `hex_str` must be null or a valid pointer to a NUL-terminated C string for
/// the duration of this call. The returned pointer must be released exactly
/// once with `free_const_string`.
#[no_mangle]
pub unsafe extern "C" fn call_tcx_api(hex_str: *const c_char) -> *const c_char {
    clear_err();
    let reply = landingpad(|| {
        let action = parse_tcx_action(hex_str)?;
        dispatch_tcx_action(&action)
    });
    match reply {
        Ok(reply) => {
            let ret_str = reply.to_hex();
            CString::new(ret_str)
                .expect("hex output contains no NUL byte")
                .into_raw()
        }
        Err(_) => empty_c_string(),
    }
}

/// # Safety
///
#[no_mangle]
pub unsafe extern "C" fn clear_err() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

/// # Safety
///
#[no_mangle]
pub unsafe extern "C" fn get_last_err_message() -> *const c_char {
    LAST_ERROR.with(|e| {
        if let Some(ref err) = *e.borrow() {
            let rsp = GeneralResult {
                is_success: false,
                error: err.to_string(),
            };
            let rsp_bytes = encode_message(rsp).expect("encode error");
            let ret_str = rsp_bytes.to_hex();
            CString::new(ret_str).unwrap().into_raw()
        } else {
            CString::new("").unwrap().into_raw()
        }
    })
}

#[cfg(test)]
mod ffi_tests {
    use super::*;

    unsafe fn take_c_string(ptr: *const c_char) -> String {
        assert!(!ptr.is_null());
        let value = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        free_const_string(ptr);
        value
    }

    unsafe fn last_error() -> String {
        let error_hex = take_c_string(get_last_err_message());
        let bytes = Vec::from_hex(&error_hex).expect("last error must be hex encoded");
        GeneralResult::decode(bytes.as_slice())
            .expect("last error must be a GeneralResult")
            .error
    }

    unsafe fn call_raw(ptr: *const c_char) -> String {
        take_c_string(call_tcx_api(ptr))
    }

    fn action_hex(method: &str, with_param: bool) -> CString {
        let action = TcxAction {
            method: method.to_string(),
            param: with_param.then(|| prost_types::Any {
                type_url: "imtoken".to_string(),
                value: vec![],
            }),
        };
        CString::new(action.encode_to_vec().to_hex()).unwrap()
    }

    #[test]
    fn malformed_ffi_input_returns_stable_errors_without_panicking() {
        let cases = [
            (None, "invalid_tcx_param:null_pointer"),
            (
                Some(CString::new(vec![0xff]).unwrap()),
                "invalid_tcx_param:invalid_utf8",
            ),
            (
                Some(CString::new("zz").unwrap()),
                "invalid_tcx_param:invalid_hex",
            ),
            (
                Some(CString::new("0aff").unwrap()),
                "invalid_tcx_param:invalid_protobuf",
            ),
        ];

        for (input, expected_error) in cases {
            let ptr = input
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr());
            assert_eq!(unsafe { call_raw(ptr) }, "");
            assert_eq!(unsafe { last_error() }, expected_error);
        }
    }

    #[test]
    fn missing_param_and_unknown_method_have_distinct_errors() {
        let missing_param = action_hex("create_keystore", false);
        assert_eq!(unsafe { call_raw(missing_param.as_ptr()) }, "");
        assert_eq!(unsafe { last_error() }, "invalid_tcx_param:missing_param");

        let unknown_method = action_hex("unknown_method", false);
        assert_eq!(unsafe { call_raw(unknown_method.as_ptr()) }, "");
        assert_eq!(unsafe { last_error() }, "unsupported_method");
    }

    #[test]
    fn free_const_string_accepts_null() {
        unsafe { free_const_string(std::ptr::null()) };
    }
}
