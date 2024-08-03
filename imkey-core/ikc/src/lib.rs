use crate::api::{AddressParam, ErrorResponse, ExternalAddressParam, ImkeyAction, PubKeyParam};
use anyhow::{anyhow, Error};
use handler::derive_sub_accounts;
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
use crate::handler::{derive_accounts, get_extended_public_keys, get_public_keys, sign_psbt};
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
    unsafe {
        message::set_apdu(unsafe { apdu });
    }
}

#[no_mangle]
pub extern "C" fn get_apdu_return() -> *const c_char {
    message::get_apdu_return()
}

#[no_mangle]
pub extern "C" fn set_apdu_return(apdu_return: *const c_char) {
    unsafe {
        message::set_apdu_return(unsafe { apdu_return });
    }
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
        "derive_sub_accounts" => landingpad(|| derive_sub_accounts(&action.param.unwrap().value)),
        "get_public_keys" => landingpad(|| get_public_keys(&action.param.unwrap().value)),
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
                    &param.clone().input.unwrap().value,
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
                "TRON" => tron_signer::sign_message(
                    &param.clone().input.unwrap().value,
                    &param
                ),
                "BITCOIN" => btc_signer::btc_sign_message(&param.clone().input.unwrap().value, &param),
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

        "get_extended_public_keys" => {
            landingpad(|| get_extended_public_keys(&action.param.unwrap().value))
        }

        "sign_psbt" => landingpad(|| sign_psbt(&action.param.unwrap().value)),

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
    use crate::api::{
        DeriveAccountsParam, DeriveAccountsResult, DeriveSubAccountsParam, DeriveSubAccountsResult,
        GetExtendedPublicKeysParam, GetExtendedPublicKeysResult, GetPublicKeysParam,
        GetPublicKeysResult, PublicKeyDerivation,
    };

    use bitcoin::Address;
    use coin_bitcoin::btcapi::{BtcMessageInput, BtcMessageOutput, BtcTxExtra, BtcTxInput, BtcTxOutput, PsbtInput, PsbtOutput, Utxo};
    use ikc_device::deviceapi::{BindAcquireReq, BindCheckRes};
    use ikc_transport::hid_api::hid_connect;
    use prost::Message;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::str::FromStr;

    fn _to_c_char(str: &str) -> *const c_char {
        CString::new(str).unwrap().into_raw()
    }

    fn _to_str(json_str: *const c_char) -> &'static str {
        let json_c_str = unsafe { CStr::from_ptr(json_str) };
        json_c_str.to_str().unwrap()
    }

    #[test]
    fn test_derive_accounts() {
        connect_and_bind();

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
            Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "m/44'/461'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/44'/0'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/49'/0'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            },
            Derivation {
                chain_type: "EOS".to_string(),
                path: "m/44'/194'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
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
        assert_eq!("xpub6DCrE779Ryz387SnYxktBSM6M8Q2G2xTsxK6XSwzwrtRwHyCtREopxRstj35QPdDfZY6XJTPnKWxQJHV35mKAjLHWXKahozqstkccmHvUgG", derived_accounts.accounts[1].extended_public_key);
        assert_eq!("ZVejk1prSEDaxjlIH9Uk9wZXWW2GX4MqfWQ92Rmulh64ORupkjCfxIZRatgvQGneupHpw31REz+gjt1qOCeundhrpv2IlgIu51EDv5bp9hsEeON1vnKjC2rx+CezkwAOf15cMt59bXZM6fQSeIgJnA==", derived_accounts.accounts[1].encrypted_extended_public_key);

        assert_eq!(
            "mpke4CzhBTV2dFZpnABT9EN1kPc4vDWZxw",
            derived_accounts.accounts[2].address
        );
        assert_eq!(
            "0x031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc",
            derived_accounts.accounts[2].public_key
        );
        assert_eq!("tpubDCwNET9ErXmBracx3ZBfi6rXQZRjYkpitFe23FAW9M3RcCw4aveNC4SAV5yYrFDjtP3b46eFfv4VtiYP3EXoTZsbnJia2yNznExS8EEcACv", derived_accounts.accounts[2].extended_public_key);
        assert_eq!("6lm577UNC0reTJjrMYWZm2GBjYqUjKWI1Y8X5hZ3XdSrsvEcjhO/m6bFUu3b21KDWDCe850mbUMi7U0Dx+Bt2ahFczqmgdCA3CnJPz4XUn5aNi/1kQpJSm7x92JJCWA3twQ0BSrg6HV+zYHm7voWKg==", derived_accounts.accounts[2].encrypted_extended_public_key);

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

        assert_eq!("", derived_accounts.accounts[7].address);
        assert_eq!(
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
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
        assert_eq!("xpub6Boii2KSAfEv7EhbBuopXKB2Gshi8kMpTGWyHuY9BHwYA8qPeu7ZYdnnXCuUdednhwyjyK2Z8gJD2AfawgBHp3Kkf2GjBjzEQAyJ3uJ4SuG", derived_accounts.accounts[10].extended_public_key);
        assert_eq!("CPEZEgxonR02LextSVWxqQmH7zSjfNN44+0KYuTJ4ezARna34lG4YcX7nR5xvSrMhuRv4eI8BG+2h3Zz4523lNPp8Y6pEEtdJHSvTzS/APQYtdpHB3Hye+kQ+D7YuJ7Ps+LxoxFAwpic7a3CS+R+cw==", derived_accounts.accounts[10].encrypted_extended_public_key);

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

        assert_eq!(
            "f12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey",
            derived_accounts.accounts[15].address
        );
        assert_eq!(
            "0x03bd460186d29fd9ac68ee88b110c3acc4a4443648a1ec7607af9ce306ad76f785",
            derived_accounts.accounts[15].public_key
        );
        assert_eq!("xpub6DCc3LkXWVzLHfCFSvmxmXytMfVnxeQQ3LDiLmHwTojg3p3U6qFmNLqzPijosTwRqeC4j2TqJamUjM44GBVRcdPukxEN94Rac8WndUhfYEK", derived_accounts.accounts[15].extended_public_key);
        assert_eq!("/zWESZN6UDRR8xZp/+puhlD0WsPheWx1+FILE+g3Ayilu3wk8L7HqErnFoOwFbH2q/VajmUM9nauncSyKs9RyO91oVoKV6Z1xOuS7nUHS3tJZHDbf2grG2Hrcoh2SiZpDycFxEPWpHCfD6cias4vLQ==", derived_accounts.accounts[15].encrypted_extended_public_key);

        assert_eq!(
            "mhW3n3x8rvB5MmPXsbYDyfAGs8mhw9GGaW",
            derived_accounts.accounts[16].address
        );
        assert_eq!(
            "0x026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            derived_accounts.accounts[16].public_key
        );
        assert_eq!("tpubDDDcs8o1LaKXKXaPTEVBUZJYTgNAte4xj24MtFCMsfrHku93ZZjy87CGyz93dcocR6x6JHdusHodD9EVcSQuDbmkAWznWZtvyqyMDqS6VK4", derived_accounts.accounts[16].extended_public_key);
        assert_eq!("KN9qVdfibQ6+qM/gpglypnGYL0A5Wsu/hm7q5QHoAzUNRQUmKOmyQquyka2FNzSEIfBp/3PZemS/uhEEbbpJfSh7mhbKDQfNQHRalWLEXrfZvOk3Aaej7cxtMnm0UdzNQlYlbeCo/E43kcfCnlsKBw==", derived_accounts.accounts[16].encrypted_extended_public_key);

        assert_eq!(
            "2NAL4iTQFwEdjFEbtDuAyoxXTqR4Cd8qtSx",
            derived_accounts.accounts[17].address
        );
        assert_eq!(
            "0x03036695c5f3de2e2792b170f59679d4db88a8516728012eaa42a22ce6f8bf593b",
            derived_accounts.accounts[17].public_key
        );
        assert_eq!("tpubDCBMEG97swCNP2tSe6nujEWPbzoN88rszu7GeTbHXChRuRW6j7xeh5TcmEzGA9b2VrWeatYRfn8FiMACLY2XhUn3id22sGeTz8ZhounC4Wa", derived_accounts.accounts[17].extended_public_key);
        assert_eq!("LtJEXs9Hqofmtz+0eVqUcdnrX4Ax41/LFjPXVWr2zg/LSL9mbj09oVo4I8mmID2xm4Q+cCjMfmroYTUFJKJxZQ2jQwmbQP+eVlcFtmKzafaUEen+rbchlWbWRKLzyVFLBNT72I0SjplHi2f5QHKauA==", derived_accounts.accounts[17].encrypted_extended_public_key);

        assert_eq!(
            "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992",
            derived_accounts.accounts[18].address
        );
        assert_eq!(
            "0x0232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d65",
            derived_accounts.accounts[18].public_key
        );
        assert_eq!("tpubDDE8woMirxgWR4CaGpkhhq7c7iB5nqmihRgi8rTxUWpUsM9jtwD6a5drCYa5at4jKHUypLByPfSy8ZQvHnNE2SKLVM8tepSPWJxK59Eegmh", derived_accounts.accounts[18].extended_public_key);
        assert_eq!("BgtriGuk6ykY4ESnLsjreJCKdGcV/5evGC3/F1afYvIYvNkpdk4bTNf/Bpy3aQCabifcQtoDL6hc+wEFbEJ/xu2pxcmP8Qiu/tU70IlTMUoItYRIOc+qs3cJHOsIPB5jqfnpSNuJWHTEFgPSj8swmw==", derived_accounts.accounts[18].encrypted_extended_public_key);

        assert_eq!("", derived_accounts.accounts[19].address);
        assert_eq!(
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
            derived_accounts.accounts[19].public_key
        );
        assert_eq!("tpubDCrXSyMPmFhDyXm3UTwpvRZWaiWWzrMxNoGiaFEB2fy5cgfAkAgeFob6WaXPrDTBvHiGs2HAJAbFURhoyNsHVTEbVfZSfK5GXjsCQ3kYMcy", derived_accounts.accounts[19].extended_public_key);
        assert_eq!("GmqrouLXtLQX0uCLHClBSkupGErjvRRkcooO0xLJWE04j14KZeadxrAsJD4nqRPxbM99rzybs9FRY2jkqfR1OyEP3XDx7Vmn0iuYt/0y7aLsiAsma3iM5CwaXKuXFM3bFAuBRHUk3Meqhx2F8zmCBQ==", derived_accounts.accounts[19].encrypted_extended_public_key);
    }

    #[test]
    fn test_ethereum_derive_sub_accounts() {
        let mut derivation = Derivation {
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            bech32_prefix: "".to_string(),
        };
        let derived_accounts_result = derive_account(derivation.clone());
        let mut derive_sub_accounts_param = DeriveSubAccountsParam {
            chain_type: "ETHEREUM".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: derived_accounts_result.accounts[0]
                .extended_public_key
                .to_string(),
        };
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "0x6031564e7b2F5cc33737807b2E58DaFF870B590b",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x0280c98b8ea7cab630defb0c09a4295c2193cdee016c1d5b9b0cb18572b9c370fe",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "xpub6CZG7sArTpFs5n47cUxtbcVXuq4QfUTykGWL8t8RJdPXvnSnF2VrDwgqjuS7JvJ7DK8B4pnbMxCNtPsbHdPjuFBCcBo81cfMRWcPUXWND3e",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "NgtbCRYto2FQ0yESmBA1NU1djYyJjSVdMq4qW+J1BrGBRAX0PUte5WoNtgmB9/XA+tGrQjkzovKH6WT963PcqJNlyBmAyjeKmL26+zKGa03+ropCiSLHqVZsVR1V/Cq6Ppz3meBvQRglORyZeE+98g==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "0x80427Ae1f55bCf60ee4CD2db7549b8BC69a74303",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x02ce64a99db44c98016264dc1c0748a1abf6df33035f8006b33f5fff68e26997b2",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.network = "TESTNET".to_string();
        let derived_accounts_result = derive_account(derivation);
        derive_sub_accounts_param.network = "TESTNET".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "0x6031564e7b2F5cc33737807b2E58DaFF870B590b",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x0280c98b8ea7cab630defb0c09a4295c2193cdee016c1d5b9b0cb18572b9c370fe",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDCvte6zYB6DKMaEy4fwyoXpuExA4ery3Hu6dVSBZeY9Rg57VKFLwNPMfywWtqRFM1Df5gQJTu42RaaNCgVEyngdVfnYRh9Kb1UCoEYojURc",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "w6s0ZvUoPPSiEi1xDMKy5X9+qwhcX4u3e3LOBosJaOSro2ny9jppDxcczZfrhe29n9H3UkmgNoecq/85xfXkGDtH8PMR9iclK5WrcUtkgjXsBcrR6JF0j58i4W9x3y539vXOsLMifCmUr2RcqknDgw==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "0x80427Ae1f55bCf60ee4CD2db7549b8BC69a74303",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x02ce64a99db44c98016264dc1c0748a1abf6df33035f8006b33f5fff68e26997b2",
            derived_sub_accounts.accounts[1].public_key
        );
    }

    #[test]
    fn test_litecoin_derive_sub_accounts() {
        let mut derivation = Derivation {
            chain_type: "LITECOIN".to_string(),
            path: "m/44'/2'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            bech32_prefix: "".to_string(),
        };
        let derived_accounts_result = derive_account(derivation.clone());
        let mut derive_sub_accounts_param = DeriveSubAccountsParam {
            chain_type: "LITECOIN".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: derived_accounts_result.accounts[0]
                .extended_public_key
                .to_string(),
        };
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x0289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7b",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "xpub6D3MqTwuLWB5veAfhDjPu1oHfS6L1imVbf22zQFWJW9EtnSmYYqiGMGkW1MCsT2HmkW872tefMY9deewW6DGd8zE7RcXVv8wKhZnbJeidjT",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "MwDMFXVWDEuWvBogeW1v/MOMFDnGnnflm2JAPvJaJZO4HXp8fCsWETA7u8MzOW3KaPksglpUHLN3xkDr2QWMEQq0TewFZoZ3KsjmLW0KGMRN7XQKqo/omkSEsPfalVnp9Zxm2lpxVmIacqvlernVSg==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "LavE5eHDvw9VDiNifbraR7GyY8MRvcQSLQ",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x03d90fc13842832d95b599fde757c716982815d828f24ab7a76a9a15913ab9d8ec",
            derived_sub_accounts.accounts[1].public_key
        );
        derivation.network = "MAINNET".to_string();
        derivation.seg_wit = "P2WPKH".to_string();
        let derived_accounts_result = derive_account(derivation.clone());
        derive_sub_accounts_param.seg_wit = "P2WPKH".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x0289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7b",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "MwDMFXVWDEuWvBogeW1v/MOMFDnGnnflm2JAPvJaJZO4HXp8fCsWETA7u8MzOW3KaPksglpUHLN3xkDr2QWMEQq0TewFZoZ3KsjmLW0KGMRN7XQKqo/omkSEsPfalVnp9Zxm2lpxVmIacqvlernVSg==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "MBDVivYGGiXzn2dP9Js3xtVViuQS3dyDwM",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x03d90fc13842832d95b599fde757c716982815d828f24ab7a76a9a15913ab9d8ec",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.network = "TESTNET".to_string();
        derivation.seg_wit = "P2WPKH".to_string();
        let derived_accounts_result = derive_account(derivation.clone());
        derive_sub_accounts_param.network = "TESTNET".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "QLfctE6KMv3ZzQod6UA37w3EPTuLS4tg1T",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x0289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7b",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDDQzMhmb3n8YCSMX9QiV6w8ezZBz17GZ9HcLLxJeeQu8e57UcmgoQnwak3RzPwyXZf32icQXCTNCKq9Ytx4WWaSXB2MqBSoAufACMGXurct",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "k4GbrxWCcsrGokCos50O69Wg9reixsDqPHkciU4xeUi9dpICotcOMQSgTgRd7XtGXXjdV/SUuTBkPXNQikqORvvW2CnHNe7+iJsTdHebynq2Y3ZXMFUWt8WJkgB5NotqkjOik89LvJBKYKvnon2B0g==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "QPvKbnvZxAF1KVk5LfXbqtfnkwTymMf2Xu",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x03d90fc13842832d95b599fde757c716982815d828f24ab7a76a9a15913ab9d8ec",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.seg_wit = "NONE".to_string();
        derivation.network = "TESTNET".to_string();
        let derived_accounts_result = derive_account(derivation.clone());
        derive_sub_accounts_param.seg_wit = "NONE".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "myxdgXjCRgAskD2g1b6WJttJbuv67hq6sQ",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x0289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7b",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDDQzMhmb3n8YCSMX9QiV6w8ezZBz17GZ9HcLLxJeeQu8e57UcmgoQnwak3RzPwyXZf32icQXCTNCKq9Ytx4WWaSXB2MqBSoAufACMGXurct",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "k4GbrxWCcsrGokCos50O69Wg9reixsDqPHkciU4xeUi9dpICotcOMQSgTgRd7XtGXXjdV/SUuTBkPXNQikqORvvW2CnHNe7+iJsTdHebynq2Y3ZXMFUWt8WJkgB5NotqkjOik89LvJBKYKvnon2B0g==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "mwDE7V4NfJLgk2ABD2qey1RYBuarjJvT7E",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x03d90fc13842832d95b599fde757c716982815d828f24ab7a76a9a15913ab9d8ec",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.seg_wit = "NONE".to_string();
        derivation.network = "TESTNET".to_string();
        derivation.path = "m/49'/2'/0'/0/0".to_string();
        let derived_accounts_result = derive_account(derivation.clone());
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "n4LXNPmmpMzGfeftriMfJrKDojno8krTPE",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x03ace3b0da84c9944a077d62fc839c95324c2bdaa01786353f5538f89fbc24f428",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDDaUkLvq9FwVPude19jyPMgTgFVgFRTXRauPt119HmeKgaduxe5tyQ6i8m7rvtaTTU518syGKRM16Un6RwcZ4Anaa84tPLf5TrM2NkJqcFR",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "uxVleeSObdFyxAmXftrBg/hxO6fZufUues2Lh9IrMD+rdYjvJ7wKeXaa2sBtklP9vKRa8RpDDC4odNghyTNS9Bt5y98GL7rXOknJIdBONKyBpcQ9spRibfge2OYAHzqQ/B409Ja3RqoIh9jezhHEwg==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "mmMJYEkfiUNbSKcBt6oUGLLbNd51PsuD5A",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x027768573bc46ee4997262ceb327019c3808ae0ae995befc42f721875bd9ec4097",
            derived_sub_accounts.accounts[1].public_key
        );
    }

    #[test]
    fn test_tron_derive_sub_accounts() {
        let derivation = Derivation {
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            bech32_prefix: "".to_string(),
        };
        let derived_accounts_result = derive_account(derivation);
        let derive_sub_accounts_param = DeriveSubAccountsParam {
            chain_type: "TRON".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: derived_accounts_result.accounts[0]
                .extended_public_key
                .to_string(),
        };
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param);
        assert_eq!(
            "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x037b5253c24ce2a293566f9e066051366cda5073e4a43b25f07c990d7c9ac0aab5",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDCxD6k9PreNhSacpfSZ3iErESZnncY1n7qU7e3stZXLPh84xVVt5ERMAqKeefUU8jswx2GpCkQpeYow4xH3PGx2iim6ftPa32GNvTKAtknz",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "A6SCjz/iYksc/3pnVnMIzXimsQAm2p4EUJ1T6fRYkeHSqtSuBcF7O2Fyt3lYbiD4RoL1wf6VfknDiLdS1mcJyD09kXl5s+fuBaklKAZ2Dh6YuGlPGJqaGnrQ/rsTJ+Adb0ZRO3F3xGadXjiGb3hTSA==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "TC1nbfByaLWHvK8haEFTkMZJBNxsnKfqKh",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x03f6a261f3b4d7c24014f2026b09ad409076c566b39b99b8e0a7196f391caec508",
            derived_sub_accounts.accounts[1].public_key
        );
    }

    #[test]
    fn test_nervos_derive_sub_accounts() {
        let mut derivation = Derivation {
            chain_type: "NERVOS".to_string(),
            path: "m/44'/309'/0'/0/0".to_string(),
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            bech32_prefix: "".to_string(),
        };
        let derived_accounts_result = derive_account(derivation.clone());
        let mut derive_sub_accounts_param = DeriveSubAccountsParam {
            chain_type: "NERVOS".to_string(),
            curve: "secp256k1".to_string(),
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: derived_accounts_result.accounts[0]
                .extended_public_key
                .to_string(),
        };

        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "ckt1qyqtr684u76tu7r8efkd24hw8922xfvhnazskzdzy6",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x03554851980004ff256888612bf0d64d9b1002bf82331450fd5a7405d1b23cc5bd",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDDMZ3uNczagkRgAQBT6vmHFwM6Tc8RwYKU4ufqywmZEUNVfYNNyrVyXgmSpDTVsthVEbEzH5QjhxQPExpjBtVXVWZinpdRjiRGtpXuALuND",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "VXhh0t5/x2aZJI0mKfkYREXX/VWw7PVEz4Gyf1bj9DS9ETRShdPA519gJMrbw8XJVk/p8X+ixbYras39ITKtl7KOSaE+E2T126r2NAR0gXRWOLIp2rrpnVWerlBkzjkoJ1KOKIPIIYhZYP7kn+tbSQ==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "ckt1qyqtg4mjvamq80xvwyv5kf2hqelmxcwpuzfsknt33c",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x02adb93db516b607059d2d09976b1ed1fce2d71b2343964477438ab63d7f42b61a",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.network = "MAINNET".to_string();
        let derived_accounts_result = derive_account(derivation);
        derive_sub_accounts_param.network = "MAINNET".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param);
        assert_eq!(
            "ckb1qyqtr684u76tu7r8efkd24hw8922xfvhnazst8nagx",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x03554851980004ff256888612bf0d64d9b1002bf82331450fd5a7405d1b23cc5bd",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "xpub6CyvXfYwHJjJ9syYjG7qZMva1yMx93SUmqUcKHvoReUadCzqJA8mMXrrXQjRvzveuahgdQmCsdsuiCkMRsLec63DW83Wwu5UqKJQmsonKpo",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "51mAHL9xbvjj1yDQ+MyohjLrWVTT2dkWegGfzoDN09qJ2mvCABLYgzyRTEwfTL7Eygd+KH3DyGp6DwhoVOgj02ISYLmsFysI3sqdEWd+7IId0m9xgym75Gl2nKeoH+WVPKOsPLf+w+cbyXRsnA6/3w==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "ckb1qyqtg4mjvamq80xvwyv5kf2hqelmxcwpuzfstk4way",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x02adb93db516b607059d2d09976b1ed1fce2d71b2343964477438ab63d7f42b61a",
            derived_sub_accounts.accounts[1].public_key
        );
    }

    #[test]
    fn test_filecoin_derive_sub_accounts() {
        let mut derivation = Derivation {
            chain_type: "FILECOIN".to_string(),
            path: "m/44'/461'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            bech32_prefix: "".to_string(),
        };
        let derived_accounts_result = derive_account(derivation.clone());
        let mut derive_sub_accounts_param = DeriveSubAccountsParam {
            chain_type: "FILECOIN".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: derived_accounts_result.accounts[0]
                .extended_public_key
                .to_string(),
        };
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "f12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x03bd460186d29fd9ac68ee88b110c3acc4a4443648a1ec7607af9ce306ad76f785",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "xpub6DCc3LkXWVzLHfCFSvmxmXytMfVnxeQQ3LDiLmHwTojg3p3U6qFmNLqzPijosTwRqeC4j2TqJamUjM44GBVRcdPukxEN94Rac8WndUhfYEK",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "/zWESZN6UDRR8xZp/+puhlD0WsPheWx1+FILE+g3Ayilu3wk8L7HqErnFoOwFbH2q/VajmUM9nauncSyKs9RyO91oVoKV6Z1xOuS7nUHS3tJZHDbf2grG2Hrcoh2SiZpDycFxEPWpHCfD6cias4vLQ==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "f1kozkcmzqvmr2bael2m3pu54fc5gibmissybkxzi",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x030bdac51c69b728fc6965b07b1737c3ae3d41e3d31b377c9b5158510d98655b91",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.network = "TESTNET".to_string();
        let derived_accounts_result = derive_account(derivation);
        derive_sub_accounts_param.network = "TESTNET".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param);
        assert_eq!(
            "t12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x03bd460186d29fd9ac68ee88b110c3acc4a4443648a1ec7607af9ce306ad76f785",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDDaEZaaDDmwnZTP6u7m3yTKFgnbSx2uTaxp1hKM5oiVZo6iBB46rWnWpdkpbPxtfdYiyLbyhqgbXRXYff3LfW4rCpYyfpb5pC67CPZdKkZB",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "PRImz4qL7pDJsEtqNVzVG9llzx+DN1XFbucDahOvyQ9g9yc5HWMdH6jAx4Mc/syseMWHLj9Y17Mfqib3sl88Ddgs3tTXhJq6vWToyXlQ6t9yg/LX1qKzLKcXLD+W0872G5m1urk//YOLIyhPkaLV2g==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "t1kozkcmzqvmr2bael2m3pu54fc5gibmissybkxzi",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x030bdac51c69b728fc6965b07b1737c3ae3d41e3d31b377c9b5158510d98655b91",
            derived_sub_accounts.accounts[1].public_key
        );
    }

    #[test]
    fn test_bitcoin_derive_sub_accounts() {
        let mut derivation = Derivation {
            chain_type: "BITCOIN".to_string(),
            path: "m/44'/0'/0'/0/0".to_string(),
            network: "TESTNET".to_string(),
            seg_wit: "NONE".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            bech32_prefix: "".to_string(),
        };
        let derived_accounts_result = derive_account(derivation.clone());
        let mut derive_sub_accounts_param = DeriveSubAccountsParam {
            chain_type: "BITCOIN".to_string(),
            curve: "secp256k1".to_string(),
            network: "TESTNET".to_string(),
            seg_wit: "NONE".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: derived_accounts_result.accounts[0]
                .extended_public_key
                .to_string(),
        };
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "mhW3n3x8rvB5MmPXsbYDyfAGs8mhw9GGaW",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDDDcs8o1LaKXKXaPTEVBUZJYTgNAte4xj24MtFCMsfrHku93ZZjy87CGyz93dcocR6x6JHdusHodD9EVcSQuDbmkAWznWZtvyqyMDqS6VK4",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "KN9qVdfibQ6+qM/gpglypnGYL0A5Wsu/hm7q5QHoAzUNRQUmKOmyQquyka2FNzSEIfBp/3PZemS/uhEEbbpJfSh7mhbKDQfNQHRalWLEXrfZvOk3Aaej7cxtMnm0UdzNQlYlbeCo/E43kcfCnlsKBw==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "mobyyve7CppjKQGFy9j82P5Eccr4PxHeqS",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x024fb7df3961e08f01025e434ea19708a4317d2fe59775cddd38df6e8a2d30697d",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.network = "TESTNET".to_string();
        derivation.seg_wit = "P2WPKH".to_string();
        let derived_accounts_result = derive_account(derivation.clone());
        derive_sub_accounts_param.network = "TESTNET".to_string();
        derive_sub_accounts_param.seg_wit = "P2WPKH".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();

        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "2NCTX2isUH3bwkrSab6kJT1Eu9pWPqAStRp",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "tpubDDDcs8o1LaKXKXaPTEVBUZJYTgNAte4xj24MtFCMsfrHku93ZZjy87CGyz93dcocR6x6JHdusHodD9EVcSQuDbmkAWznWZtvyqyMDqS6VK4",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "KN9qVdfibQ6+qM/gpglypnGYL0A5Wsu/hm7q5QHoAzUNRQUmKOmyQquyka2FNzSEIfBp/3PZemS/uhEEbbpJfSh7mhbKDQfNQHRalWLEXrfZvOk3Aaej7cxtMnm0UdzNQlYlbeCo/E43kcfCnlsKBw==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "2NFVTYd5GHvFtC6KcHVRHUkHq5qepoRgtxA",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x024fb7df3961e08f01025e434ea19708a4317d2fe59775cddd38df6e8a2d30697d",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.network = "MAINNET".to_string();
        derivation.seg_wit = "NONE".to_string();
        let derived_accounts_result = derive_account(derivation.clone());
        derive_sub_accounts_param.network = "MAINNET".to_string();
        derive_sub_accounts_param.seg_wit = "NONE".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "BdgvWHN/Uh/K526q/+CdpGwEPZ41SvZHHGSgiSqhFesjErdbo6UnJMIoDOHV94qW8fd2KBW18UG3nTzDwS7a5oArqPtv+2aE9+1bNvCdtYoAx3979N3vbX4Xxn/najTABykXrJDjgpoaXxSo/xTktQ==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "1962gsZ8PoPUYHneFakkCTrukdFMVQ4i4T",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x024fb7df3961e08f01025e434ea19708a4317d2fe59775cddd38df6e8a2d30697d",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.network = "MAINNET".to_string();
        derivation.seg_wit = "P2WPKH".to_string();
        let derived_accounts_result = derive_account(derivation.clone());
        derive_sub_accounts_param.network = "MAINNET".to_string();
        derive_sub_accounts_param.seg_wit = "P2WPKH".to_string();
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param.clone());
        assert_eq!(
            "3LuJxywSfb6bZ4p2uy8Rq4FdwUJDxkwsmT",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "BdgvWHN/Uh/K526q/+CdpGwEPZ41SvZHHGSgiSqhFesjErdbo6UnJMIoDOHV94qW8fd2KBW18UG3nTzDwS7a5oArqPtv+2aE9+1bNvCdtYoAx3979N3vbX4Xxn/najTABykXrJDjgpoaXxSo/xTktQ==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "3PwFUt9EgTkXzJh4cMoQroJZsVSf3w65mN",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x024fb7df3961e08f01025e434ea19708a4317d2fe59775cddd38df6e8a2d30697d",
            derived_sub_accounts.accounts[1].public_key
        );

        derivation.path = "m/49'/0'/0'/0/0".to_string();
        let derived_accounts_result = derive_account(derivation);
        derive_sub_accounts_param.extended_public_key = derived_accounts_result.accounts[0]
            .extended_public_key
            .to_string();
        let derived_sub_accounts = derive_sub_account(derive_sub_accounts_param);
        assert_eq!(
            "3JmreiUEKn8P3SyLYmZ7C1YCd4r2nFy3Dp",
            derived_sub_accounts.accounts[0].address
        );
        assert_eq!(
            "0x03036695c5f3de2e2792b170f59679d4db88a8516728012eaa42a22ce6f8bf593b",
            derived_sub_accounts.accounts[0].public_key
        );
        assert_eq!(
            "xpub6Boii2KSAfEv7EhbBuopXKB2Gshi8kMpTGWyHuY9BHwYA8qPeu7ZYdnnXCuUdednhwyjyK2Z8gJD2AfawgBHp3Kkf2GjBjzEQAyJ3uJ4SuG",
            derived_sub_accounts.accounts[0].extended_public_key
        );
        assert_eq!(
            "CPEZEgxonR02LextSVWxqQmH7zSjfNN44+0KYuTJ4ezARna34lG4YcX7nR5xvSrMhuRv4eI8BG+2h3Zz4523lNPp8Y6pEEtdJHSvTzS/APQYtdpHB3Hye+kQ+D7YuJ7Ps+LxoxFAwpic7a3CS+R+cw==",
            derived_sub_accounts.accounts[0].encrypted_extended_public_key
        );
        assert_eq!(
            "33xJxujVGf4qBmPTnGW9P8wrKCmT7Nwt3t",
            derived_sub_accounts.accounts[1].address
        );
        assert_eq!(
            "0x0394f89191b900da3b605d0334a8fe7f3d4bad7031ebc2bdca36b32b929551fa9c",
            derived_sub_accounts.accounts[1].public_key
        );
    }

    #[test]
    fn test_get_extended_public_keys() {
        connect_and_bind();

        let derivations = vec![
            PublicKeyDerivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/44'/145'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/0/1".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/44'/145'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "FILECOIN".to_string(),
                path: "m/44'/461'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "EOS".to_string(),
                path: "m/44'/194'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "NERVOS".to_string(),
                path: "m/44'/309'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
        ];
        let param = GetExtendedPublicKeysParam { derivations };
        let action: ImkeyAction = ImkeyAction {
            method: "get_extended_public_keys".to_string(),
            param: Some(::prost_types::Any {
                type_url: "get_extended_public_keys".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        let extended_public_key: GetExtendedPublicKeysResult =
            GetExtendedPublicKeysResult::decode(ret_bytes.as_slice()).unwrap();
        assert_eq!(extended_public_key.extended_public_keys[0], "xpub6GZjFnyumLtEwC4KQkigvc3vXJdZvy71QxHTsFQQv1YtEUWNEwynKWsK2LBFZNLWdTk3w1Y9cRv4NN7V2pnDBoWgH3PkVE9r9Q2kSQL2zkH");
        assert_eq!(extended_public_key.extended_public_keys[1], "xpub6FmdMKZ36pLzf1iF7DLCzKtZms33cZ6mVjvBSy2dCPugFCH23cS3jgHfQ9PKmxs989ZyiyALuADMtLokCzpw7Fi35ap4uybfQAY5WVakan7");
        assert_eq!(extended_public_key.extended_public_keys[2], "xpub6AQmexrYd5utZNmD9Gnf4CjrzJ4kuvaxacLyuSD5sA34g4oKuzBpX5rhAZrCZoxkcqWLVyWSz1rEh5ECs4PDRN16PLfNKFftxm48y6zsWX3");
        assert_eq!(extended_public_key.extended_public_keys[3], "xpub6Bmkv3mmRZZWoFSBdj9vDMqR2PCPSP6DEj8u3bBuv44g3Ncnro6cPVqZAw6wTEcxHQuodkuJG4EmAinqrrRXGsN3HHnRRMtAvzfYTiBATV1");
        assert_eq!(extended_public_key.extended_public_keys[4], "xpub6CZG7sArTpFs5n47cUxtbcVXuq4QfUTykGWL8t8RJdPXvnSnF2VrDwgqjuS7JvJ7DK8B4pnbMxCNtPsbHdPjuFBCcBo81cfMRWcPUXWND3e");
        assert_eq!(extended_public_key.extended_public_keys[5], "xpub6CrWRZY39gj49G1ipdmcVunEnb5RoTGf9o6QnJQp8c4b84V2piN1Rdy1xWVJ4P7VXNx5Ckg6rZcvSNvJtvWz8zs3RkPayHn9vMMuK9ERrFr");
        assert_eq!(extended_public_key.extended_public_keys[6], "xpub6DCc3LkXWVzLHfCFSvmxmXytMfVnxeQQ3LDiLmHwTojg3p3U6qFmNLqzPijosTwRqeC4j2TqJamUjM44GBVRcdPukxEN94Rac8WndUhfYEK");
        assert_eq!(extended_public_key.extended_public_keys[7], "xpub6CaaaWKi9NRFAnRyDFZxWKWs7Sh8d9WiaCspHVpkDcaVwqQFRH2z5ygLbHZs8yWtwyR3QhJLDJzbrdSTZRC9PWaRfAMNCruoSJnWhKFFCWV");
        assert_eq!(extended_public_key.extended_public_keys[8], "xpub6CUtvjXi3yjmhjaC2GxjiWE9FbQs1TrtqAgRDhB2gmDBsPzTfwqZ7MvGGYScKiVx8PBNFSmHm4mCnFDCaX23c1nJS4p8ynR2wnGne4qEEX9");
        assert_eq!(extended_public_key.extended_public_keys[9], "xpub6CyvXfYwHJjJ9syYjG7qZMva1yMx93SUmqUcKHvoReUadCzqJA8mMXrrXQjRvzveuahgdQmCsdsuiCkMRsLec63DW83Wwu5UqKJQmsonKpo");
    }

    #[test]
    fn test_get_extended_public_keys_error_case() {
        connect_and_bind();

        let test_data = vec![
            vec![PublicKeyDerivation {
                chain_type: "POLKADOT".to_string(),
                path: "m/44'/354'/0'/0'/0'".to_string(),
                curve: "ed25519".to_string(),
            }],
            vec![PublicKeyDerivation {
                chain_type: "BITCOIN".to_string(),
                path: "".to_string(),
                curve: "secp256k1".to_string(),
            }],
            vec![PublicKeyDerivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/0".to_string(),
                curve: "secp256k1".to_string(),
            }],
        ];
        for i in 0..test_data.len() {
            let param = GetExtendedPublicKeysParam {
                derivations: test_data[i].clone(),
            };
            let action: ImkeyAction = ImkeyAction {
                method: "get_extended_public_keys".to_string(),
                param: Some(::prost_types::Any {
                    type_url: "get_extended_public_keys".to_string(),
                    value: encode_message(param).unwrap(),
                }),
            };
            let action = hex::encode(encode_message(action).unwrap());
            let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
            let err = unsafe { _to_str(imkey_get_last_err_message()) };
            assert!(!err.is_empty());
            let error_ret: ErrorResponse =
                ErrorResponse::decode(hex::decode(err).unwrap().as_slice()).unwrap();
            match i {
                0 => {
                    assert_eq!(error_ret.error, "unsupported_curve_type");
                }
                1 => {
                    assert_eq!(error_ret.error, "imkey_path_illegal");
                }
                2 => {
                    assert_eq!(error_ret.error, "imkey_path_illegal");
                }
                _ => {}
            };
        }
    }

    #[test]
    fn test_get_public_keys() {
        connect_and_bind();

        let derivations = vec![
            PublicKeyDerivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/44'/145'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "EOS".to_string(),
                path: "m/44'/194'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "BITCOINCASH".to_string(),
                path: "m/44'/145'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/44'/2'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "NERVOS".to_string(),
                path: "m/44'/309'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "POLKADOT".to_string(),
                path: "m/44'/354'/0'".to_string(),
                curve: "ed25519".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "KUSAMA".to_string(),
                path: "m/44'/434'/0'".to_string(),
                curve: "ed25519".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "FILECOIN".to_string(),
                path: "m/44'/461'/0'".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/0/0".to_string(),
                curve: "secp256k1".to_string(),
            },
            PublicKeyDerivation {
                chain_type: "POLKADOT".to_string(),
                path: "m/0'/0'".to_string(),
                curve: "ed25519".to_string(),
            },
        ];
        let param = GetPublicKeysParam { derivations };
        let action: ImkeyAction = ImkeyAction {
            method: "get_public_keys".to_string(),
            param: Some(::prost_types::Any {
                type_url: "get_public_keys".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        let result: GetPublicKeysResult =
            GetPublicKeysResult::decode(ret_bytes.as_slice()).unwrap();
        assert_eq!(
            result.public_keys[0],
            "0x0303f2f84851514bf2f40a46b5bb9dbf4e5913fbacde1a96968cda08f9fd882caa"
        );
        assert_eq!(
            result.public_keys[1],
            "0x03f3175613d999d15e6fde436825a3cc2c568f8f5082275f06eb4bd6e561f503ac"
        );
        assert_eq!(
            result.public_keys[2],
            "EOS7ik8DKrvmBBKZHePgRSJiFhKoG1r3w8wNBwtRE9rTntW8yYmSk"
        );
        assert_eq!(
            result.public_keys[3],
            "0x03cca080a087467a703b01a1f87a65f3e4e566508c6f85f5582a6973a77c80c35e"
        );
        assert_eq!(
            result.public_keys[4],
            "0x0303f2f84851514bf2f40a46b5bb9dbf4e5913fbacde1a96968cda08f9fd882caa"
        );
        assert_eq!(
            result.public_keys[5],
            "0x02c7709248e6205fefa7366efb0269021f1f2f1e04fdc334fe7c7fd2628d7451e8"
        );
        assert_eq!(
            result.public_keys[6],
            "0x03349ff19e96c1aa7f568e493f85fa506320410245b4e69146bb0d3d8b5df3b901"
        );
        assert_eq!(
            result.public_keys[7],
            "0x03ad9d0e2d9181e23c7075a56ed4f10e249aaf38a2bb7aa0cb604f8b768ea84b86"
        );
        assert_eq!(
            result.public_keys[8],
            "0x2d9aecea337e9eee9d9a86f2d81aadafa88557fe5fb49efa187ce8ca3bc4e2a2"
        );
        assert_eq!(
            result.public_keys[9],
            "0x5fcd1bec698400671d396c7f3507441a9b62340731b53aebf0a58c57512b5c45"
        );
        assert_eq!(
            result.public_keys[10],
            "0x02611325073f61ae5feb6c8dce96857d007cdb765937e53e43e6f91374dac62edb"
        );
        assert_eq!(
            result.public_keys[11],
            "0x0330f3b39c1a4278db118d2a8e8cd1fd5bd574d6fac43040f5ec514ad6cc776892"
        );
        assert_eq!(
            result.public_keys[12],
            "0x4f3f24c064893a591d5a5b31990de9d12ed9da0c8650bcf98ede27e3da141401"
        );
    }

    #[test]
    fn test_get_public_keys_error_case() {
        connect_and_bind();

        let derivations = vec![PublicKeyDerivation {
            chain_type: "POLKADOT".to_string(),
            path: "m/44'/354'/0'/0'/0'".to_string(),
            curve: "sr25519".to_string(),
        }];
        let param = GetPublicKeysParam { derivations };
        let action: ImkeyAction = ImkeyAction {
            method: "get_public_keys".to_string(),
            param: Some(::prost_types::Any {
                type_url: "get_public_keys".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let _ = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let err = unsafe { _to_str(imkey_get_last_err_message()) };
        assert!(!err.is_empty());
        let error_ret: ErrorResponse =
            ErrorResponse::decode(hex::decode(err).unwrap().as_slice()).unwrap();
        assert_eq!(error_ret.error, "unsupported_curve_type");
    }

    fn derive_account(derivation: Derivation) -> DeriveAccountsResult {
        connect_and_bind();

        let derivations = vec![derivation];
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
        DeriveAccountsResult::decode(ret_bytes.as_slice()).unwrap()
    }

    fn derive_sub_account(param: DeriveSubAccountsParam) -> DeriveSubAccountsResult {
        let action: ImkeyAction = ImkeyAction {
            method: "derive_sub_accounts".to_string(),
            param: Some(::prost_types::Any {
                type_url: "deviceapi.derive_sub_accounts".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        DeriveSubAccountsResult::decode(ret_bytes.as_slice()).unwrap()
    }

    fn connect_and_bind() {
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
                bind_code: "5PJT7223".to_string(),
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
    }

    #[test]
    fn test_bitcoin_sign_no_opreturn() {
        connect_and_bind();
        let unspents = vec![Utxo {
            tx_hash: "64381306678c6a868e8778adee1ee9d1746e5e8dd3535fcbaa1a25baab49f015".to_string(),
            vout: 1,
            amount: 100000,
            address: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            script_pub_key: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derived_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];
        let tx_input = BtcTxInput {
            to: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
            amount: 30000,
            fee: 8000,
            change_address_index: Some(0),
            unspents,
            seg_wit: "VERSION_0".to_string(),
            protocol: "".to_string(),
            extra: None,
        };
        let input_value = encode_message(tx_input).unwrap();
        let param = SignParam {
            chain_type: "BITCOIN".to_string(),
            path: "m/49'/1'/0'".to_string(),
            network: "TESTNET".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imkey".to_string(),
                value: input_value.clone(),
            }),
            payment: "30000".to_string(),
            receiver: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
            sender: "".to_string(),
            fee: "8000".to_string(),
            seg_wit: "".to_string(),
        };
        let action: ImkeyAction = ImkeyAction {
            method: "sign_tx".to_string(),
            param: Some(::prost_types::Any {
                type_url: "deviceapi.sign_tx".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        let sign_result = BtcTxOutput::decode(ret_bytes.as_slice()).unwrap();
        assert_eq!(
            "0200000000010115f049abba251aaacb5f53d38d5e6e74d1e91eeead78878e866a8c67061338640100000000ffffffff0230750000000000001976a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac30f2000000000000160014622347653655d57ee8e8f25983f646bcdf9c503202483045022100bc0e5f620554681ccd336cd9e12a244abd40d374a3a7668671a73edfb561a7900220534617da8eb8636f2db8bdb6191323bb766d534235d97ad08935a05ffb8b81010121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.signature
        );
        assert_eq!(
            "eb3ea0d4b360a304849b90baf49197eb449ca746febd60f8f29cd279c966a3ea",
            sign_result.tx_hash
        );
        assert_eq!(
            "0f538a5808dfc78124ad7de1ff81ededb94d0e8aabd057d46af46459582673e9",
            sign_result.wtx_hash
        );
    }

    #[test]
    fn test_bitcoin_sign_with_opreturn() {
        connect_and_bind();
        let unspents = vec![
            Utxo {
                tx_hash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pub_key: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derived_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                tx_hash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf".to_string(),
                script_pub_key: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
                derived_path: "m/49'/1'/0'/0/1".to_string(),
                sequence: 0,
            },
        ];
        let extra = BtcTxExtra {
            op_return: "1234".to_string(),
            property_id: 0,
            fee_mode: "".to_string(),
        };
        let tx_input = BtcTxInput {
            to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
            amount: 88000,
            fee: 10000,
            change_address_index: Some(0),
            unspents,
            seg_wit: "P2WPKH".to_string(),
            protocol: "".to_string(),
            extra: Some(extra),
        };
        let input_value = encode_message(tx_input).unwrap();
        let param = SignParam {
            chain_type: "BITCOIN".to_string(),
            path: "m/49'/1'/0'".to_string(),
            network: "TESTNET".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imkey".to_string(),
                value: input_value.clone(),
            }),
            payment: "88000".to_string(),
            receiver: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
            sender: "".to_string(),
            fee: "10000".to_string(),
            seg_wit: "".to_string(),
        };
        let action: ImkeyAction = ImkeyAction {
            method: "sign_tx".to_string(),
            param: Some(::prost_types::Any {
                type_url: "deviceapi.sign_tx".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        let sign_result = BtcTxOutput::decode(ret_bytes.as_slice()).unwrap();
        assert_eq!(
            "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff03c05701000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e87d00700000000000017a914755fba51b5c443b9f16b1f86665dec10dd7a25c5870000000000000000046a02123402483045022100c5c33638f7a93094f4c5f30e384ed619f1818ee5095f6c892909b1fde0ec3d45022078d4c458e05d7ffee8dc7807d4b1b576c2ba1311b05d1e6f4c41775da77deb4d0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc0247304402201d0b9fd415cbe3af809709fea17dfab49291d5f9e42c2ec916dc547b8819df8d02203281c5a742093d46d6b681afc837022ae33c6ff3839ac502bb6bf443782f8010012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000",
            sign_result.signature
        );
        assert_eq!(
            "dc021850ca46b2fdc3f278020ac4e27ee18d9753dd07cbd97b84a2a0a2af3940",
            sign_result.tx_hash
        );
        assert_eq!(
            "4eede542b9da11500d12f38b81c3728ae6cd094b866bc9629cbb2c6ab0810914",
            sign_result.wtx_hash
        );
    }

    #[test]
    fn test_psbt_sign() {
        connect_and_bind();
        let psbt_input = PsbtInput{
            psbt: "70736274ff01005e02000000012bd2f6479f3eeaffe95c03b5fdd76a873d346459114dec99c59192a0cb6409e90000000000ffffffff01409c000000000000225120677cc88dc36a75707b370e27efff3e454d446ad55004dac1685c1725ee1a89ea000000000001012b50c3000000000000225120a9a3350206de400f09a73379ec1bcfa161fc11ac095e5f3d7354126f0ec8e87f6215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0d2956573f010fa1a3c135279c5eb465ec2250205dcdfe2122637677f639b1021356c963cd9c458508d6afb09f3fa2f9b48faec88e75698339a4bbb11d3fc9b0efd570120aff94eb65a2fe773a57c5bd54e62d8436a5467573565214028422b41bd43e29bad200aee0509b16db71c999238a4827db945526859b13c95487ab46725357c9a9f25ac20113c3a32a9d320b72190a04a020a0db3976ef36972673258e9a38a364f3dc3b0ba2017921cf156ccb4e73d428f996ed11b245313e37e27c978ac4d2cc21eca4672e4ba203bb93dfc8b61887d771f3630e9a63e97cbafcfcc78556a474df83a31a0ef899cba2040afaf47c4ffa56de86410d8e47baa2bb6f04b604f4ea24323737ddc3fe092dfba2079a71ffd71c503ef2e2f91bccfc8fcda7946f4653cef0d9f3dde20795ef3b9f0ba20d21faf78c6751a0d38e6bd8028b907ff07e9a869a43fc837d6b3f8dff6119a36ba20f5199efae3f28bb82476163a7e458c7ad445d9bffb0682d10d3bdb2cb41f8e8eba20fa9d882d45f4060bdb8042183828cd87544f1ea997380e586cab77d5fd698737ba569cc001172050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00000".to_string(),
            auto_finalize: true,
        };
        let input_value = encode_message(psbt_input).unwrap();
        let param = SignParam {
            chain_type: "BITCOIN".to_string(),
            path: "m/86'/1'/0'".to_string(),
            network: "MAINNET".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imkey".to_string(),
                value: input_value.clone(),
            }),
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };
        let action: ImkeyAction = ImkeyAction {
            method: "sign_psbt".to_string(),
            param: Some(::prost_types::Any {
                type_url: "deviceapi.sign_psbt".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        let sign_result = PsbtOutput::decode(ret_bytes.as_slice()).unwrap();

        assert!(sign_result.psbt.len() > 0);
    }

    #[test]
    fn test_btc_sign_message() {
        connect_and_bind();
        let input = BtcMessageInput{
            message: "hello world".to_string(),
        };
        let input_value = encode_message(input).unwrap();
        let param = SignParam {
            chain_type: "BITCOIN".to_string(),
            path: "m/44'/0'/0'".to_string(),
            network: "MAINNET".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imkey".to_string(),
                value: input_value.clone(),
            }),
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let action: ImkeyAction = ImkeyAction {
            method: "sign_message".to_string(),
            param: Some(::prost_types::Any {
                type_url: "signapi.sign_message".to_string(),
                value: encode_message(param).unwrap(),
            }),
        };
        let action = hex::encode(encode_message(action).unwrap());
        let ret_hex = unsafe { _to_str(call_imkey_api(_to_c_char(action.as_str()))) };
        let ret_bytes = hex::decode(ret_hex).unwrap();
        let sign_result = BtcMessageOutput::decode(ret_bytes.as_slice()).unwrap();
        assert_eq!(sign_result.signature, "02483045022100dbbdfedfb1902ca12c6cba14d4892a98f77c434daaa4f97fd35e618374c908f602206527ff2b1ce550c16c836c2ce3508bfae543fa6c11759d2f4966cc0d3552c4430121026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868");
    }
}
