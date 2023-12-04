use std::ffi::{CStr, CString};

use std::os::raw::c_char;

use handler::{
    calc_external_address, decrypt_data_from_ipfs, encrypt_data_to_ipfs, migrate_keystore,
    remove_wallets, sign_authentication_message, sign_message,
};
// use handler::{eth_v3keystore_export, eth_v3keystore_import};
use prost::Message;

pub mod api;

use crate::api::{Response, TcxAction};

pub mod error_handling;
pub mod handler;
use failure::Error;
use std::result;

use crate::error_handling::{landingpad, LAST_BACKTRACE, LAST_ERROR};
#[allow(deprecated)]
use crate::handler::{
    encode_message, export_mnemonic, export_private_key, get_derived_key, hd_store_create,
    hd_store_export, hd_store_import, keystore_common_accounts, keystore_common_delete,
    keystore_common_derive, keystore_common_exists, keystore_common_verify,
    private_key_store_export, private_key_store_import, sign_tron_message_legacy, sign_tx,
    unlock_then_crash, zksync_private_key_from_seed, zksync_private_key_to_pubkey_hash,
    zksync_sign_musig,
};

mod filemanager;
// mod identity;
mod macros;

// use crate::identity::{
//     create_identity, decrypt_data_from_ipfs, encrypt_data_to_ipfs, export_identity,
//     get_current_identity, recover_identity, remove_identity, sign_authentication_message,
// };

use crate::handler::{
    eth_recover_address, export_substrate_keystore, generate_mnemonic, get_extended_public_keys,
    get_public_key, get_public_keys, import_substrate_keystore, sign_bls_to_execution_change,
    sign_hashes, substrate_keystore_exists,
};

use parking_lot::RwLock;

extern crate serde_json;

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref IS_DEBUG: RwLock<bool> = RwLock::new(false);
}

pub type Result<T> = result::Result<T, Error>;

#[no_mangle]
pub unsafe extern "C" fn free_const_string(s: *const c_char) {
    if s.is_null() {
        return;
    }
    let _ = CStr::from_ptr(s);
}

/// dispatch protobuf rpc call
///
#[allow(deprecated)]
#[no_mangle]
pub unsafe extern "C" fn call_tcx_api(hex_str: *const c_char) -> *const c_char {
    let hex_c_str = CStr::from_ptr(hex_str);
    let hex_str = hex_c_str.to_str().expect("parse_arguments to_str");

    let data = hex::decode(hex_str).expect("parse_arguments hex decode");
    let action: TcxAction = TcxAction::decode(data.as_slice()).expect("decode tcx api");
    let reply: Result<Vec<u8>> = match action.method.to_lowercase().as_str() {
        "init_token_core_x" => landingpad(|| {
            handler::init_token_core_x(&action.param.unwrap().value).unwrap();
            Ok(vec![])
        }),
        "scan_keystores" => landingpad(|| {
            handler::scan_keystores().unwrap();
            Ok(vec![])
        }),
        "hd_store_create" => landingpad(|| hd_store_create(&action.param.unwrap().value)),
        "hd_store_import" => landingpad(|| hd_store_import(&action.param.unwrap().value)),
        "hd_store_export" => landingpad(|| hd_store_export(&action.param.unwrap().value)),
        "export_mnemonic" => landingpad(|| export_mnemonic(&action.param.unwrap().value)),
        "keystore_common_derive" => {
            landingpad(|| keystore_common_derive(&action.param.unwrap().value))
        }
        "private_key_store_import" => {
            landingpad(|| private_key_store_import(&action.param.unwrap().value))
        }
        "private_key_store_export" => {
            landingpad(|| private_key_store_export(&action.param.unwrap().value))
        }
        "export_private_key" => landingpad(|| export_private_key(&action.param.unwrap().value)),
        "keystore_common_verify" => {
            landingpad(|| keystore_common_verify(&action.param.unwrap().value))
        }
        "keystore_common_delete" => {
            landingpad(|| keystore_common_delete(&action.param.unwrap().value))
        }
        "keystore_common_exists" => {
            landingpad(|| keystore_common_exists(&action.param.unwrap().value))
        }
        "keystore_common_accounts" => {
            landingpad(|| keystore_common_accounts(&action.param.unwrap().value))
        }
        "calc_external_address" => {
            landingpad(|| calc_external_address(&action.param.unwrap().value))
        }
        "sign_tx" => landingpad(|| sign_tx(&action.param.unwrap().value)),
        "get_public_key" => landingpad(|| get_public_key(&action.param.unwrap().value)),
        // use the sign_msg instead
        "tron_sign_msg" => landingpad(|| sign_tron_message_legacy(&action.param.unwrap().value)),
        "sign_msg" => landingpad(|| sign_message(&action.param.unwrap().value)),

        "substrate_keystore_exists" => {
            landingpad(|| substrate_keystore_exists(&action.param.unwrap().value))
        }

        "substrate_keystore_import" => {
            landingpad(|| import_substrate_keystore(&action.param.unwrap().value))
        }

        "substrate_keystore_export" => {
            landingpad(|| export_substrate_keystore(&action.param.unwrap().value))
        }

        // !!! WARNING !!! used for `cache_dk` feature
        "get_derived_key" => landingpad(|| get_derived_key(&action.param.unwrap().value)),
        // !!! WARNING !!! used for test only
        "unlock_then_crash" => landingpad(|| unlock_then_crash(&action.param.unwrap().value)),
        "zksync_private_key_from_seed" => {
            landingpad(|| zksync_private_key_from_seed(&action.param.unwrap().value))
        }
        "zksync_sign_musig" => landingpad(|| zksync_sign_musig(&action.param.unwrap().value)),
        "zksync_private_key_to_pubkey_hash" => {
            landingpad(|| zksync_private_key_to_pubkey_hash(&action.param.unwrap().value))
        }
        "sign_bls_to_execution_change" => {
            landingpad(|| sign_bls_to_execution_change(&action.param.unwrap().value))
        }
        "generate_mnemonic" => landingpad(|| generate_mnemonic()),
        // "create_identity" => landingpad(|| create_identity(&action.param.unwrap().value)),
        // "get_current_identity" => landingpad(|| get_current_identity()),
        // "recover_identity" => landingpad(|| recover_identity(&action.param.unwrap().value)),
        // "export_identity" => landingpad(|| export_identity(&action.param.unwrap().value)),
        "remove_wallets" => landingpad(|| remove_wallets(&action.param.unwrap().value)),
        // "eth_ec_sign" => landingpad(|| eth_ec_sign(&action.param.unwrap().value)),
        // "eth_recover_address" => landingpad(|| eth_recover_address(&action.param.unwrap().value)),
        // "eos_update_account" => landingpad(|| eos_update_account(&action.param.unwrap().value)),
        // "eth_keystore_import" => landingpad(|| eth_v3keystore_import(&action.param.unwrap().value)),
        // "eth_keystore_export" => landingpad(|| eth_v3keystore_export(&action.param.unwrap().value)),
        "encrypt_data_to_ipfs" => landingpad(|| encrypt_data_to_ipfs(&action.param.unwrap().value)),
        "decrypt_data_from_ipfs" => {
            landingpad(|| decrypt_data_from_ipfs(&action.param.unwrap().value))
        }
        "sign_authentication_message" => {
            landingpad(|| sign_authentication_message(&action.param.unwrap().value))
        }
        "migrate_keystore" => landingpad(|| migrate_keystore(&action.param.unwrap().value)),
        "eth_recover_address" => landingpad(|| eth_recover_address(&action.param.unwrap().value)),

        "get_extended_public_key_poc" => {
            landingpad(|| get_extended_public_keys(&action.param.unwrap().value))
        }
        "get_public_keys" => landingpad(|| get_public_keys(&action.param.unwrap().value)),
        "sign_hashes" => landingpad(|| sign_hashes(&action.param.unwrap().value)),

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
pub unsafe extern "C" fn clear_err() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
    LAST_BACKTRACE.with(|e| {
        *e.borrow_mut() = None;
    });
}

#[no_mangle]
pub unsafe extern "C" fn get_last_err_message() -> *const c_char {
    LAST_ERROR.with(|e| {
        if let Some(ref err) = *e.borrow() {
            let rsp = Response {
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
    use crate::filemanager::KEYSTORE_MAP;
    use api::sign_param::Key;
    use error_handling::Result;
    use std::ffi::{CStr, CString};
    use std::fs::remove_file;
    use std::os::raw::c_char;
    use std::panic;
    use std::path::Path;
    use tcx_atom::transaction::{AtomTxInput, AtomTxOutput};

    use crate::api::keystore_common_derive_param::Derivation;
    use crate::api::{
        sign_param, AccountResponse, AccountsResponse, CalcExternalAddressParam,
        CalcExternalAddressResult, DecryptDataFromIpfsParam, DecryptDataFromIpfsResult,
        DerivedKeyResult, EncryptDataToIpfsParam, EncryptDataToIpfsResult, ExportPrivateKeyParam,
        GenerateMnemonicResult, HdStoreCreateParam, HdStoreImportParam, IdentityResult,
        InitTokenCoreXParam, KeyType, KeystoreCommonAccountsParam, KeystoreCommonDeriveParam,
        KeystoreCommonExistsParam, KeystoreCommonExistsResult, KeystoreCommonExportResult,
        KeystoreMigrationParam, PrivateKeyStoreExportParam, PrivateKeyStoreImportParam,
        PublicKeyParam, PublicKeyResult, RemoveWalletsParam, RemoveWalletsResult, Response,
        SignAuthenticationMessageParam, SignAuthenticationMessageResult, SignParam,
        V3KeystoreExportInput, V3KeystoreExportOutput, V3KeystoreImportInput, WalletKeyParam,
        WalletResult, ZksyncPrivateKeyFromSeedParam, ZksyncPrivateKeyFromSeedResult,
        ZksyncPrivateKeyToPubkeyHashParam, ZksyncPrivateKeyToPubkeyHashResult,
        ZksyncSignMusigParam, ZksyncSignMusigResult,
    };
    use crate::handler::hd_store_import;
    use crate::handler::{encode_message, private_key_store_import};
    use prost::Message;
    use tcx_constants::{sample_key, CurveType};
    use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{Keystore, Source};
    // use tcx_identity::{constants, model};

    use std::fs;
    use tcx_btc_kin::transaction::BtcKinTxInput;

    use sp_core::ByteArray;
    use sp_runtime::traits::Verify;
    use std::fs::File;
    use std::io::Read;
    use tcx_btc_kin::Utxo;
    use tcx_ckb::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};
    use tcx_constants::sample_key::MNEMONIC;
    use tcx_eth::transaction::{
        AccessList, EthMessageInput, EthMessageOutput, EthRecoverAddressInput,
        EthRecoverAddressOutput, EthTxInput, EthTxOutput,
    };
    use tcx_eth2::transaction::{SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult};
    use tcx_filecoin::{SignedMessage, UnsignedMessage};
    // use tcx_identity::wallet_api::{
    //     CreateIdentityParam, CreateIdentityResult, ExportIdentityParam, ExportIdentityResult,
    //     GenerateMnemonicResult, GetCurrentIdentityResult, RecoverIdentityParam,
    //     RecoverIdentityResult, RemoveIdentityParam, RemoveIdentityResult, V3KeystoreExportInput,
    //     V3KeystoreExportOutput, V3KeystoreImportInput,
    // };
    use tcx_substrate::{
        ExportSubstrateKeystoreResult, SubstrateKeystore, SubstrateKeystoreParam, SubstrateRawTxIn,
        SubstrateTxOut,
    };
    use tcx_tezos::transaction::{TezosRawTxIn, TezosTxOut};
    use tcx_tron::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};

    static OTHER_MNEMONIC: &'static str =
        "calm release clay imitate top extend close draw quiz refuse shuffle injury";

    fn _to_c_char(str: &str) -> *const c_char {
        CString::new(str).unwrap().into_raw()
    }

    fn _to_str(json_str: *const c_char) -> &'static str {
        let json_c_str = unsafe { CStr::from_ptr(json_str) };
        json_c_str.to_str().unwrap()
    }

    fn setup() {
        let p = Path::new("/tmp/imtoken/wallets");
        if !p.exists() {
            fs::create_dir_all(p).expect("shoud create filedir");
        }

        let param = InitTokenCoreXParam {
            file_dir: "/tmp/imtoken/wallets".to_string(),
            xpub_common_key: "B888D25EC8C12BD5043777B1AC49F872".to_string(),
            xpub_common_iv: "9C0C30889CBCC5E01AB5B2BB88715799".to_string(),
            is_debug: false,
        };

        handler::init_token_core_x(&encode_message(param).unwrap()).expect("should init tcx");
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

    fn run_test<T>(test: T) -> ()
    where
        T: FnOnce() -> () + panic::UnwindSafe,
    {
        setup();
        let result = panic::catch_unwind(|| test());
        teardown();
        assert!(result.is_ok())
    }

    fn import_default_wallet() -> WalletResult {
        let param = HdStoreImportParam {
            mnemonic: TEST_MNEMONIC.to_string(),
            // mnemonic: TEST_MNEMONIC.to_string(),
            password: TEST_PASSWORD.to_string(),
            source: "MNEMONIC".to_string(),
            name: "test-wallet".to_string(),
            password_hint: "imtoken".to_string(),
            overwrite: true,
        };
        let ret = hd_store_import(&encode_message(param).unwrap()).unwrap();
        WalletResult::decode(ret.as_slice()).unwrap()
    }

    fn import_default_pk_store() -> WalletResult {
        let param: PrivateKeyStoreImportParam = PrivateKeyStoreImportParam {
            private_key: "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB".to_string(),
            password: TEST_PASSWORD.to_string(),
            name: "import_default_pk_store".to_string(),
            password_hint: "".to_string(),
            overwrite: true,
            encoding: "".to_string(),
        };

        let ret = private_key_store_import(&encode_message(param).unwrap()).unwrap();
        WalletResult::decode(ret.as_slice()).unwrap()
    }

    fn import_filecoin_pk_store() -> WalletResult {
        let param: PrivateKeyStoreImportParam = PrivateKeyStoreImportParam {
            private_key: "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a"
                .to_string(),
            password: TEST_PASSWORD.to_string(),
            name: "import_filecoin_pk_store".to_string(),
            password_hint: "".to_string(),
            overwrite: true,
            encoding: "".to_string(),
        };

        let ret = private_key_store_import(&encode_message(param).unwrap()).unwrap();
        WalletResult::decode(ret.as_slice()).unwrap()
    }

    fn import_and_derive(derivation: Derivation) -> WalletResult {
        let mut wallet = import_default_wallet();

        let param = KeystoreCommonDeriveParam {
            id: wallet.id.to_string(),
            password: TEST_PASSWORD.to_string(),
            derivations: vec![derivation],
        };

        let ret = call_api("keystore_common_derive", param).unwrap();
        let accounts: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

        wallet.accounts = accounts.accounts.clone();

        wallet
    }

    fn import_pk_and_derive(derivation: Derivation) -> WalletResult {
        let mut wallet = import_default_pk_store();

        let param = KeystoreCommonDeriveParam {
            id: wallet.id.to_string(),
            password: TEST_PASSWORD.to_string(),
            derivations: vec![derivation],
        };

        let ret = call_api("keystore_common_derive", param).unwrap();
        let accounts: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

        wallet.accounts = accounts.accounts.clone();

        wallet
    }

    fn call_api(method: &str, msg: impl Message) -> Result<Vec<u8>> {
        let param = TcxAction {
            method: method.to_string(),
            param: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: encode_message(msg).unwrap(),
            }),
        };
        let _ = unsafe { clear_err() };
        let param_bytes = encode_message(param).unwrap();
        let param_hex = hex::encode(param_bytes);
        let ret_hex = unsafe { _to_str(call_tcx_api(_to_c_char(&param_hex))) };
        let err = unsafe { _to_str(get_last_err_message()) };
        if !err.is_empty() {
            let err_bytes = hex::decode(err).unwrap();
            let err_ret: Response = Response::decode(err_bytes.as_slice()).unwrap();
            Err(format_err!("{}", err_ret.error))
        } else {
            Ok(hex::decode(ret_hex).unwrap())
        }
    }

    #[test]
    fn test_call_tcx_api() {
        run_test(|| {
            let _import_param = HdStoreImportParam {
                mnemonic: TEST_MNEMONIC.to_string(),
                password: TEST_PASSWORD.to_string(),
                source: "MNEMONIC".to_string(),
                name: "call_tcx_api".to_string(),
                password_hint: "".to_string(),
                overwrite: true,
            };
            // let ret_bytes = call_api("hd_store_import", import_param).unwrap();
            let ret_bytes = hex::decode("0a2434656239623136392d323237392d343439332d616535342d62396233643761303630323512036161611a084d4e454d4f4e494328e9a1a2f305").unwrap();
            let ret: WalletResult = WalletResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(ret.accounts.is_empty())
        });
    }

    #[test]
    pub fn test_scan_keystores() {
        let param = InitTokenCoreXParam {
            file_dir: "../test-data".to_string(),
            xpub_common_key: "B888D25EC8C12BD5043777B1AC49F872".to_string(),
            xpub_common_iv: "9C0C30889CBCC5E01AB5B2BB88715799".to_string(),
            is_debug: true,
        };

        handler::init_token_core_x(&encode_message(param).unwrap()).expect("should init tcx");

        let keystore_count;
        {
            let mut map = KEYSTORE_MAP.write();
            keystore_count = map.len();
            map.clear();
            assert_eq!(0, map.len());
        }
        let empty = WalletKeyParam {
            id: "".to_string(),
            password: "".to_string(),
        };
        let _ = call_api("scan_keystores", empty);
        {
            let map = KEYSTORE_MAP.write();

            assert_eq!(keystore_count, map.len());
        }
    }

    #[test]
    pub fn test_hd_store_create() {
        run_test(|| {
            let param = HdStoreCreateParam {
                password: TEST_PASSWORD.to_string(),
                password_hint: "".to_string(),
                name: "aaa".to_string(),
                source: "MNEMONIC".to_string(),
            };

            let ret = call_api("hd_store_create", param).unwrap();
            let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();

            assert!(import_result.accounts.is_empty());
            assert_eq!(import_result.name, "aaa");
            assert_eq!(import_result.source, "MNEMONIC");
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_hd_store_import() {
        run_test(|| {
            let import_result: WalletResult = import_default_wallet();
            assert_eq!(import_result.source, "MNEMONIC");
            let derivation = Derivation {
                chain_type: "BITCOINCASH".to_string(),
                path: "m/44'/145'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param).unwrap();
            let result: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();
            assert_eq!(result.accounts.first().unwrap().chain_type, "BITCOINCASH");
            assert_eq!(
                result.accounts.first().unwrap().address,
                "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r"
            );
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_hd_store_import_invalid_params() {
        run_test(|| {
            let invalid_mnemonics = vec![
                "inject kidney empty canal shadow pact comfort wife crush horse",
                "inject kidney empty canal shadow pact comfort wife crush horse wife wife",
                "inject kidney empty canal shadow pact comfort wife crush horse hello",
            ];
            for mn in invalid_mnemonics {
                let param = HdStoreImportParam {
                    mnemonic: mn.to_string(),
                    password: TEST_PASSWORD.to_string(),
                    source: "MNEMONIC".to_string(),
                    name: "test-wallet".to_string(),
                    password_hint: "imtoken".to_string(),
                    overwrite: true,
                };

                let ret = call_api("hd_store_import", param);
                assert!(ret.is_err());
            }
        })
    }

    #[test]
    pub fn test_hd_store_import_ltc() {
        run_test(|| {
            let import_result: WalletResult = import_default_wallet();

            let derivation = Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/44'/1'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param).unwrap();
            let result: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();
            assert_eq!(result.accounts.first().unwrap().chain_type, "LITECOIN");
            assert_eq!(
                result.accounts.first().unwrap().address,
                "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN"
            );

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_hd_store_export() {
        run_test(|| {
            let wallet = import_default_wallet();

            let param = WalletKeyParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
            };
            let ret = call_api("hd_store_export", param).unwrap();
            let result: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(ret.as_slice()).unwrap();

            assert_eq!(result.r#type, KeyType::Mnemonic as i32);
            assert_eq!(result.value, TEST_MNEMONIC);
        })
    }

    #[test]
    pub fn test_export_mnemonic() {
        run_test(|| {
            let wallet = import_default_wallet();

            let param = WalletKeyParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
            };
            let ret = call_api("export_mnemonic", param).unwrap();
            let result: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(ret.as_slice()).unwrap();

            assert_eq!(result.r#type, KeyType::Mnemonic as i32);
            assert_eq!(result.value, TEST_MNEMONIC);

            let wallet = import_default_pk_store();

            let param = WalletKeyParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
            };
            unsafe { clear_err() };
            let ret = call_api("export_mnemonic", param);
            assert!(ret.is_err());
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "private_keystore_cannot_export_mnemonic"
            );
        })
    }

    #[test]
    pub fn test_keystore_common_store_derive() {
        run_test(|| {
            let param = HdStoreImportParam {
                mnemonic: OTHER_MNEMONIC.to_string(),
                password: TEST_PASSWORD.to_string(),
                source: "MNEMONIC".to_string(),
                name: "test-wallet".to_string(),
                password_hint: "imtoken".to_string(),
                overwrite: true,
            };
            let ret = call_api("hd_store_import", param).unwrap();
            let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();

            let derivations = vec![
                Derivation {
                    chain_type: "LITECOIN".to_string(),
                    path: "m/44'/2'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "LITECOIN".to_string(),
                    path: "m/49'/2'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "P2WPKH".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "LITECOIN".to_string(),
                    path: "m/49'/1'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "TRON".to_string(),
                    path: "m/44'/195'/0'/0/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "NERVOS".to_string(),
                    path: "m/44'/309'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "KUSAMA".to_string(),
                    path: "//kusama//imToken/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "POLKADOT".to_string(),
                    path: "//polkadot//imToken/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "FILECOIN".to_string(),
                    path: "m/44'/461'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "SECP256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "FILECOIN".to_string(),
                    path: "m/12381/461/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "BLS".to_string(),
                    bech32_prefix: "".to_string(),
                },
                // Derivation {
                //     chain_type: "ETHEREUM2".to_string(),
                //     path: "m/12381/3600/0/0".to_string(),
                //     network: "MAINNET".to_string(),
                //     seg_wit: "".to_string(),
                //     chain_id: "".to_string(),
                //     curve: "BLS".to_string(),
                //     bech32_prefix: "".to_string(),
                // },
                Derivation {
                    chain_type: "COSMOS".to_string(),
                    path: "m/44'/118'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "SECP256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "EOS".to_string(),
                    path: "m/44'/194'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "SECP256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];

            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(12, derived_accounts.accounts.len());
            assert_eq!(
                "LQ3JqCohgLQ3x1CJXYERnJTy1ySaqr1E32",
                derived_accounts.accounts[0].address
            );
            assert_eq!("/EhDRyPFcj1UGx8i+WiJSIeBSyaN0pX7Oq3wXqwO5M9T1aRhfLpsNPGAPLf07K+p+B0OdQW1ogVbDQCWkIwVXZLPY+njp9LjXaICiWGEeidR1TwBZSwOMRKE68wJWH/7puxYfY/Rq1+d2GFv6NxSCw==", derived_accounts.accounts[0].extended_xpub_key);

            assert_eq!(
                "MQUu6P7wsLQZfVZMuFWB7UXiheuVTM7RYF",
                derived_accounts.accounts[1].address
            );
            assert_eq!("A5LUzJcPB4r54wqr8EjFh9fe0L87spIN9KJKtzHV6QJXBH6GEAiYT57uftpJITx613HdIXXzi8VJ30TmG8erBF30oD1DnbDmGmDo4sdRTdQSsp9NuprhZ3Y3PR9+xzdc2tKDblRL5dLZswaPxCOQcw==", derived_accounts.accounts[1].extended_xpub_key);

            assert_eq!(
                "mvdDMnRsqjqzvCyYyRXpvscmnU1FxodhkE",
                derived_accounts.accounts[2].address
            );
            assert_eq!("eZIL4e0a8qw18Pve92iLfehteHDA+kqjwv91aKE+2hNN3arkq20yY2Mx6q4WAowFv0QRfIi6QlrhafJKUpjiC469NNZagCSHLaECYliEwmwTgC97zXmVJDB6MJi79y+mznf8G7Few8+u6UfiXELN5g==", derived_accounts.accounts[2].extended_xpub_key);

            assert_eq!(
                "TLZnqkrSNLUWNrZMug8u9b6pJ3XcTGbzDV",
                derived_accounts.accounts[3].address
            );
            assert_eq!("Sla41n5BdHqc1QmqA9DXjWNx13Fpq18u19jCaMbYbxClsPr7cr/gzXsbE+08wfNLuGgtVVY4/prpnv3/pdJ8KA/I/iOKvelKxuJgN9n2O5Q54CmObc0qJVZxcAQM0PbrKE9YJyGDkJNMLM+OmjEwjg==", derived_accounts.accounts[3].extended_xpub_key);

            assert_eq!(
                "ckt1qyqgkffut7e7md39tp5ts9vxssj7wdw8z4cquyflka",
                derived_accounts.accounts[4].address
            );

            assert_eq!(
                "HFEP5ePp69xrCLTYcDnzqJTgmH87RUKprkoRUuEmu9Tk49s",
                derived_accounts.accounts[5].address
            );
            assert_eq!(
                "13GVaZUS28zTCroTPq8dyppfm8F4cAvoJsSZ3yvmtyRYLSLJ",
                derived_accounts.accounts[6].address
            );
            assert_eq!(
                "t1k7yhkb42jhgrsx4nhr7rfkxfiahmkyxq5cw74ry",
                derived_accounts.accounts[7].address
            );
            // assert_eq!(
            //     "t3virna6zi3ju2kxsd4zcvlzk7hemm6dsfq47ikggpnmpu43sqzt6yi5remdrt3j62nex7vx254d3767fot7jq",
            //     derived_accounts.accounts[8].address
            // );
            assert_eq!(
                "a9bedcb23b8ea49d9171a75eacaa90733df0c5e92be5298c2e2e3d001afc0a9ba99e146796cf1d6e93b1778c3e89edac",
                derived_accounts.accounts[9].address
            );

            assert_eq!(
                "cosmos1m566v5rcklnac8vc0dftfu4lnvznhlu7d3f404",
                derived_accounts.accounts[10].address
            );

            assert_eq!("", derived_accounts.accounts[11].address);
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_hd_store_derive_invalid_param() {
        run_test(|| {
            let import_result: WalletResult = import_default_wallet();

            let invalid_derivations = vec![
                Derivation {
                    chain_type: "WRONG_CHAIN_TYPE".to_string(),
                    path: "m/44'/2'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "LITECOIN".to_string(),
                    path: "WRONG/PATH".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "P2WPKH".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "LITECOIN".to_string(),
                    path: "49'/1'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];
            for derivation in invalid_derivations {
                let param = KeystoreCommonDeriveParam {
                    id: import_result.id.to_string(),
                    password: TEST_PASSWORD.to_string(),
                    derivations: vec![derivation],
                };
                let ret = call_api("keystore_common_derive", param);
                assert!(ret.is_err());
            }

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_private_key_store_import() {
        run_test(|| {
            let import_result: WalletResult = import_default_pk_store();

            assert_eq!(0, import_result.accounts.len());

            let derivations = vec![
                Derivation {
                    chain_type: "LITECOIN".to_string(),
                    path: "m/44'/2'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "LITECOIN".to_string(),
                    path: "m/49'/2'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "P2WPKH".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "LITECOIN".to_string(),
                    path: "m/49'/1'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "TRON".to_string(),
                    path: "m/44'/195'/0'/0/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "NERVOS".to_string(),
                    path: "m/44'/309'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(5, derived_accounts.accounts.len());
            assert_eq!(
                "LgGNTHMkgETS7oQcoekvACJQcH355xECog",
                derived_accounts.accounts[0].address
            );
            assert_eq!("", derived_accounts.accounts[0].extended_xpub_key);

            assert_eq!(
                "MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW",
                derived_accounts.accounts[1].address
            );
            assert_eq!("", derived_accounts.accounts[1].extended_xpub_key);

            assert_eq!(
                "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6",
                derived_accounts.accounts[2].address
            );
            assert_eq!("", derived_accounts.accounts[2].extended_xpub_key);

            assert_eq!(
                "TXo4VDm8Qc5YBSjPhu8pMaxzTApSvLshWG",
                derived_accounts.accounts[3].address
            );
            assert_eq!("", derived_accounts.accounts[3].extended_xpub_key);

            assert_eq!(
                "ckt1qyqpavderq5jjxh6qhxeks4t706kglffkyassx7h5z",
                derived_accounts.accounts[4].address
            );

            //            assert_eq!(
            //                "ckt1qyqpavderq5jjxh6qhxeks4t706kglffkyassx7h5z",
            //                derived_accounts.accounts[5].address
            //            );

            // pk rederive
            let derivations = vec![Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/44'/2'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(
                "LgGNTHMkgETS7oQcoekvACJQcH355xECog",
                derived_accounts.accounts[0].address
            );
            assert_eq!("", derived_accounts.accounts[0].extended_xpub_key);

            let param = KeystoreCommonAccountsParam {
                id: import_result.id.to_string(),
            };
            let accounts_ret = call_api("keystore_common_accounts", param).unwrap();
            let ret = AccountsResponse::decode(accounts_ret.as_slice()).unwrap();
            assert_eq!(5, ret.accounts.len());

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_tezos_private_key_store_import_export() {
        run_test(|| {
            let param: PrivateKeyStoreImportParam = PrivateKeyStoreImportParam {
                private_key: "edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_tezos_private_key_store_import_export".to_string(),
                password_hint: "".to_string(),
                overwrite: true,
                encoding: "TEZOS".to_string(),
            };

            let ret = private_key_store_import(&encode_message(param).unwrap()).unwrap();
            let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();
            assert_eq!(0, import_result.accounts.len());

            let derivations = vec![Derivation {
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(
                "tz1QSHaKpTFhgHLbqinyYRjxD5sLcbfbzhxy",
                derived_accounts.accounts[0].address
            );

            let param: KeystoreCommonExistsParam = KeystoreCommonExistsParam {
                r#type: KeyType::PrivateKey as i32,
                value: "edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH"
                    .to_string(),
                encoding: "TEZOS".to_string(),
            };

            let ret_bytes = call_api("keystore_common_exists", param).unwrap();
            let result: KeystoreCommonExistsResult =
                KeystoreCommonExistsResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, import_result.id);

            let param: PrivateKeyStoreExportParam = PrivateKeyStoreExportParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "TEZOS".to_string(),
                network: "MAINNET".to_string(),
            };
            let ret_bytes = call_api("private_key_store_export", param).unwrap();
            let export_result: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH",
                export_result.value
            );

            let param: PublicKeyParam = PublicKeyParam {
                id: import_result.id.to_string(),
                chain_type: "TEZOS".to_string(),
                address: "tz1QSHaKpTFhgHLbqinyYRjxD5sLcbfbzhxy".to_string(),
            };
            let ret_bytes = call_api("get_public_key", param).unwrap();
            let public_key_result: PublicKeyResult =
                PublicKeyResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "edpkvQtuhdZQmjdjVfaY9Kf4hHfrRJYugaJErkCGvV3ER1S7XWsrrj",
                public_key_result.public_key
            );
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_tezos_hd_private_key_import_export() {
        run_test(|| {
            let import_result: WalletResult = import_default_pk_store();

            assert_eq!(0, import_result.accounts.len());

            let derivations = vec![Derivation {
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(
                "tz1RTCY2tQdBCWYacqmV18UYy5YMBdCgcpL1",
                derived_accounts.accounts[0].address
            );

            let export_param = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "TEZOS".to_string(),
                network: "".to_string(),
                main_address: derived_accounts.accounts[0].address.to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
            };

            let export_pk_bytes = call_api("export_private_key", export_param).unwrap();
            let export_pk: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(export_pk_bytes.as_slice()).unwrap();
            println!("{:#?}", export_pk.value);
            // assert_eq!(
            //     export_pk.value,
            //     "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f354a6754767776725a774c5061513758326d4b4c6a386e4478634e685a6b537667315564434a317866593d227d"
            // );
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_filecoin_private_key_secp256k1_import() {
        run_test(|| {
            let param: PrivateKeyStoreImportParam = PrivateKeyStoreImportParam {
                private_key: "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f354a6754767776725a774c5061513758326d4b4c6a386e4478634e685a6b537667315564434a317866593d227d"
                    .to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_filecoin_private_key_store_import".to_string(),
                password_hint: "".to_string(),
                overwrite: true,
                encoding: "".to_string(),
            };

            let ret = private_key_store_import(&encode_message(param).unwrap()).unwrap();
            let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();

            assert_eq!(0, import_result.accounts.len());

            let derivations = vec![Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "SECP256k1".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();

            assert_eq!(1, derived_accounts.accounts.len());

            assert_eq!(
                "t1zerdvi3fx2lrcslsqdewpadzzm2hefpn6ixew3i",
                derived_accounts.accounts[0].address
            );

            let export_param = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "FILECOIN".to_string(),
                network: "".to_string(),
                main_address: "t1zerdvi3fx2lrcslsqdewpadzzm2hefpn6ixew3i".to_string(),
                path: "".to_string(),
            };

            let export_pk_bytes = call_api("export_private_key", export_param).unwrap();
            let export_pk: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(export_pk_bytes.as_slice()).unwrap();
            assert_eq!(
                export_pk.value,
                "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f354a6754767776725a774c5061513758326d4b4c6a386e4478634e685a6b537667315564434a317866593d227d"
            );

            remove_created_wallet(&import_result.id);
        });
    }

    #[test]
    pub fn test_filecoin_private_key_bls_import() {
        run_test(|| {
            let param: PrivateKeyStoreImportParam = PrivateKeyStoreImportParam {
                private_key: "7b2254797065223a22626c73222c22507269766174654b6579223a2269376b4f2b7a78633651532b7637597967636d555968374d55595352657336616e6967694c684b463830383d227d"
                    .to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_filecoin_private_key_store_import".to_string(),
                password_hint: "".to_string(),
                overwrite: true,
                encoding: "".to_string(),
            };

            let ret = private_key_store_import(&encode_message(param).unwrap()).unwrap();
            let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();

            assert_eq!(0, import_result.accounts.len());

            let derivations = vec![Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "BLS".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(1, derived_accounts.accounts.len());

            assert_eq!(
                "t3qdyntx5snnwgmjkp2ztd6tf6hhcmurxfj53zylrqyympwvzvbznx6vnvdqloate5eviphnzrkupno4wheesa",
                derived_accounts.accounts[0].address
            );

            let export_param = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "FILECOIN".to_string(),
                network: "".to_string(),
                main_address: "t3qdyntx5snnwgmjkp2ztd6tf6hhcmurxfj53zylrqyympwvzvbznx6vnvdqloate5eviphnzrkupno4wheesa".to_string(),
                path: "".to_string(),
            };

            let export_pk_bytes = call_api("export_private_key", export_param).unwrap();
            let export_pk: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(export_pk_bytes.as_slice()).unwrap();
            assert_eq!(
                export_pk.value,
                "7b2254797065223a22626c73222c22507269766174654b6579223a2269376b4f2b7a78633651532b7637597967636d555968374d55595352657336616e6967694c684b463830383d227d"
            );

            remove_created_wallet(&import_result.id);
        });
    }

    #[test]
    pub fn test_64bytes_private_key_store_import() {
        run_test(|| {
            let param: PrivateKeyStoreImportParam = PrivateKeyStoreImportParam {
                private_key: "416c696365202020202020202020202020202020202020202020202020202020d172a74cda4c865912c32ba0a80a57ae69abae410e5ccb59dee84e2f4432db4f"
                    .to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_64bytes_private_key_store_import".to_string(),
                password_hint: "".to_string(),
                overwrite: true,
                encoding: "".to_string(),
            };

            let ret = private_key_store_import(&encode_message(param).unwrap()).unwrap();
            let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();

            assert_eq!(0, import_result.accounts.len());

            let derivations = vec![Derivation {
                chain_type: "POLKADOT".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(1, derived_accounts.accounts.len());

            assert_eq!(
                "133smEABgtt8FRkZGrZfAzCV522bxo2y5FwVoTcSaY8z1nEq",
                derived_accounts.accounts[0].address
            );

            let export_param = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "POLKADOT".to_string(),
                network: "".to_string(),
                main_address: "133smEABgtt8FRkZGrZfAzCV522bxo2y5FwVoTcSaY8z1nEq".to_string(),
                path: "".to_string(),
            };

            let export_pk_bytes = call_api("export_private_key", export_param).unwrap();
            let export_pk: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(export_pk_bytes.as_slice()).unwrap();
            assert_eq!(
                export_pk.value,
                "416c696365202020202020202020202020202020202020202020202020202020d172a74cda4c865912c32ba0a80a57ae69abae410e5ccb59dee84e2f4432db4f"
            );
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_private_key_store_export() {
        run_test(|| {
            let import_result: WalletResult = import_default_pk_store();
            let param: PrivateKeyStoreExportParam = PrivateKeyStoreExportParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "BITCOINCASH".to_string(),
                network: "MAINNET".to_string(),
            };
            let ret_bytes = call_api("private_key_store_export", param).unwrap();
            let export_result: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB",
                export_result.value
            );
            assert_eq!(KeyType::PrivateKey as i32, export_result.r#type);

            let param: PrivateKeyStoreExportParam = PrivateKeyStoreExportParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "BITCOINCASH".to_string(),
                network: "TESTNET".to_string(),
            };
            let ret_bytes = call_api("private_key_store_export", param).unwrap();
            let export_result: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "cT4fTJyLd5RmSZFHnkGmVCzXDKuJLbyTt7cy77ghTTCagzNdPH1j",
                export_result.value
            );
            assert_eq!(KeyType::PrivateKey as i32, export_result.r#type);

            let param: PrivateKeyStoreExportParam = PrivateKeyStoreExportParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "TRON".to_string(),
                network: "".to_string(),
            };
            let ret_bytes = call_api("private_key_store_export", param).unwrap();
            let export_result: KeystoreCommonExportResult =
                KeystoreCommonExportResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
                export_result.value
            );
            assert_eq!(KeyType::PrivateKey as i32, export_result.r#type);
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_export_private_key() {
        run_test(|| {
            let derivations = vec![
                Derivation {
                    chain_type: "BITCOINCASH".to_string(),
                    path: "".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOINCASH".to_string(),
                    path: "".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "TRON".to_string(),
                    path: "".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "FILECOIN".to_string(),
                    path: "".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "SECP256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];
            let pks = vec![
                "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB",
                "cT4fTJyLd5RmSZFHnkGmVCzXDKuJLbyTt7cy77ghTTCagzNdPH1j",
                "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
                "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f354a6754767776725a774c5061513758326d4b4c6a386e4478634e685a6b537667315564434a317866593d227d",
            ];

            for idx in 0..4 {
                let import_result: WalletResult = import_pk_and_derive(derivations[idx].clone());
                let acc = import_result.accounts.first().unwrap().clone();
                let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                    id: import_result.id.to_string(),
                    password: TEST_PASSWORD.to_string(),
                    chain_type: acc.chain_type.to_string(),
                    network: derivations[idx].network.to_string(),
                    main_address: acc.address.clone(),
                    path: "".to_string(),
                };
                let ret_bytes = call_api("export_private_key", param).unwrap();
                let export_result: KeystoreCommonExportResult =
                    KeystoreCommonExportResult::decode(ret_bytes.as_slice()).unwrap();

                // test export as mainnet
                assert_eq!(pks[idx], export_result.value);
                assert_eq!(KeyType::PrivateKey as i32, export_result.r#type);
                remove_created_wallet(&import_result.id);
            }

            let wallet = import_default_pk_store();
            let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "LITECOIN".to_string(),
                network: "MAINNET".to_string(),
                main_address: "Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP".to_string(),
                path: "".to_string(),
            };
            let ret = call_api("export_private_key", param);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "account_not_found");
        })
    }

    #[test]
    pub fn test_export_private_key_from_hd_store() {
        run_test(|| {
            let derivations = vec![
                Derivation {
                    chain_type: "BITCOINCASH".to_string(),
                    path: "m/44'/145'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOINCASH".to_string(),
                    path: "m/44'/145'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOINCASH".to_string(),
                    path: "m/44'/1'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "TRON".to_string(),
                    path: "m/44'/195'/0'/0/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "FILECOIN".to_string(),
                    path: "m/44'/461'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "SECP256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];

            let pks = vec![
                "L39VXyorp19JfsEJfbD7Tfr4pBEX93RJuVXW7E13C51ZYAhUWbYa",
                "KyLGdagds7tY1vupT5Kf8C1Cc5wkzzWRK51e4vsh1svCSvYk4Abo",
                "cN4b1V3cicEexrYXiEhaWEdURyhZiVX6PzAZNFSzZaWfSNZG2cJX",
                "685634d212eabe016a1cb09d9f1ea1ea757ebe590b9a097d7b1c9379ad280171",
                "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a222f5059574777574e577a58614d5675437a613958502b314b4a695a4474696f4c76777863754268783041553d227d",
            ];
            let export_paths = vec![
                "m/44'/145'/0'/0/0",
                "m/44'/145'/0'/0/1",
                "m/44'/1'/0'/0/1",
                "m/44'/195'/0'/0/1",
                "m/44'/461'/0'/0/0",
            ];

            for idx in 0..derivations.len() {
                let import_result: WalletResult = import_and_derive(derivations[idx].clone());
                let acc = import_result.accounts.first().unwrap().clone();
                let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                    id: import_result.id.to_string(),
                    password: TEST_PASSWORD.to_string(),
                    chain_type: acc.chain_type.to_string(),
                    network: derivations[idx].network.to_string(),
                    main_address: acc.address.to_string(),
                    path: export_paths[idx].to_string(),
                };
                let ret_bytes = call_api("export_private_key", param).unwrap();
                let export_result: KeystoreCommonExportResult =
                    KeystoreCommonExportResult::decode(ret_bytes.as_slice()).unwrap();

                assert_eq!(pks[idx], export_result.value);
                assert_eq!(KeyType::PrivateKey as i32, export_result.r#type);
                remove_created_wallet(&import_result.id);
            }

            let import_result: WalletResult = import_default_wallet();

            let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "LITECOIN".to_string(),
                network: "MAINNET".to_string(),
                main_address: "Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP".to_string(),
                path: "m/44'/2'/0'/0/0".to_string(),
            };
            let ret = call_api("export_private_key", param);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "account_not_found");
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_chain_cannot_export_private_key() {
        run_test(|| {
            let derivations = vec![Derivation {
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "SECP256k1".to_string(),
                bech32_prefix: "".to_string(),
            }];

            let export_paths = vec!["m/44'/118'/0'/0/0"];

            for idx in 0..derivations.len() {
                let import_result: WalletResult = import_and_derive(derivations[idx].clone());
                let acc = import_result.accounts.first().unwrap().clone();
                let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                    id: import_result.id.to_string(),
                    password: TEST_PASSWORD.to_string(),
                    chain_type: acc.chain_type.to_string(),
                    network: derivations[idx].network.to_string(),
                    main_address: acc.address.to_string(),
                    path: export_paths[idx].to_string(),
                };
                let ret = call_api("export_private_key", param);

                assert_eq!(
                    "chain_cannot_export_private_key",
                    format!("{}", ret.err().unwrap())
                );
                remove_created_wallet(&import_result.id);
            }
        })
    }

    #[test]
    pub fn test_import_to_pk_which_from_hd() {
        run_test(|| {
            let param: PrivateKeyStoreImportParam = PrivateKeyStoreImportParam {
                private_key: "L39VXyorp19JfsEJfbD7Tfr4pBEX93RJuVXW7E13C51ZYAhUWbYa".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_import_to_pk_which_from_hd".to_string(),
                password_hint: "".to_string(),
                overwrite: true,
                encoding: "".to_string(),
            };

            let ret = private_key_store_import(&encode_message(param).unwrap()).unwrap();
            let wallet: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();

            let derivation = Derivation {
                chain_type: "BITCOINCASH".to_string(),
                path: "".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let derive_param = KeystoreCommonDeriveParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };
            let ret_bytes = keystore_common_derive(&encode_message(derive_param).unwrap()).unwrap();
            let ret: AccountsResponse = AccountsResponse::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r",
                ret.accounts.first().unwrap().address
            );
            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    pub fn test_keystore_common_verify() {
        run_test(|| {
            let wallets = vec![import_default_pk_store(), import_default_wallet()];
            for wallet in wallets {
                let param: WalletKeyParam = WalletKeyParam {
                    id: wallet.id.to_string(),
                    password: TEST_PASSWORD.to_string(),
                };

                let ret_bytes = call_api("keystore_common_verify", param).unwrap();
                let result: Response = Response::decode(ret_bytes.as_slice()).unwrap();
                assert!(result.is_success);

                let param: WalletKeyParam = WalletKeyParam {
                    id: wallet.id.to_string(),
                    password: "WRONG PASSWORD".to_string(),
                };

                let ret = call_api("keystore_common_verify", param);
                assert!(ret.is_err());
                assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");
            }
        })
    }

    #[test]
    pub fn test_keystore_common_delete() {
        run_test(|| {
            let param: PrivateKeyStoreImportParam = PrivateKeyStoreImportParam {
                private_key: "5JZc7wGRUr4J1RHDcM9ySWKLfQ2xjRUEo612qC4RLJ3G7jzJ4qx".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_keystore_common_delete".to_string(),
                password_hint: "".to_string(),
                overwrite: true,
                encoding: "".to_string(),
            };

            let ret_bytes = private_key_store_import(&encode_message(param).unwrap()).unwrap();
            let import_result: WalletResult = WalletResult::decode(ret_bytes.as_slice()).unwrap();

            let param: WalletKeyParam = WalletKeyParam {
                id: import_result.id.to_string(),
                password: "WRONG PASSWORD".to_string(),
            };

            let ret = call_api("keystore_common_delete", param);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

            let param: WalletKeyParam = WalletKeyParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
            };

            let ret_bytes = call_api("keystore_common_delete", param).unwrap();
            let ret: Response = Response::decode(ret_bytes.as_slice()).unwrap();
            assert!(ret.is_success);

            let param: KeystoreCommonExistsParam = KeystoreCommonExistsParam {
                r#type: KeyType::PrivateKey as i32,
                value: "5JZc7wGRUr4J1RHDcM9ySWKLfQ2xjRUEo612qC4RLJ3G7jzJ4qx".to_string(),
                encoding: "".to_string(),
            };

            let ret_bytes = call_api("keystore_common_exists", param).unwrap();
            let ret: KeystoreCommonExistsResult =
                KeystoreCommonExistsResult::decode(ret_bytes.as_slice()).unwrap();

            assert_eq!(false, ret.is_exists);
        })
    }

    #[test]
    pub fn test_keystore_common_exists() {
        run_test(|| {
            let wallet = import_default_wallet();
            let param: KeystoreCommonExistsParam = KeystoreCommonExistsParam {
                r#type: KeyType::Mnemonic as i32,
                value: format!("{}", TEST_MNEMONIC).to_string(),
                encoding: "".to_string(),
            };

            let ret_bytes = call_api("keystore_common_exists", param).unwrap();
            let result: KeystoreCommonExistsResult =
                KeystoreCommonExistsResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, wallet.id);

            let wallet = import_default_pk_store();
            let param: KeystoreCommonExistsParam = KeystoreCommonExistsParam {
                r#type: KeyType::PrivateKey as i32,
                value: "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB".to_string(),
                encoding: "".to_string(),
            };

            let ret_bytes = call_api("keystore_common_exists", param).unwrap();
            let result: KeystoreCommonExistsResult =
                KeystoreCommonExistsResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, wallet.id);

            let param: KeystoreCommonExistsParam = KeystoreCommonExistsParam {
                r#type: KeyType::PrivateKey as i32,
                value: "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6"
                    .to_string(),
                encoding: "".to_string(),
            };

            let ret_bytes = call_api("keystore_common_exists", param).unwrap();
            let result: KeystoreCommonExistsResult =
                KeystoreCommonExistsResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, wallet.id);

            let wallet = import_default_wallet();
            let param: KeystoreCommonExistsParam = KeystoreCommonExistsParam {
                r#type: KeyType::Mnemonic as i32,
                value: format!("{}", " inject  kidney  empty canal shadow  pact comfort  wife crush horse wife sketch  ").to_string(),//Badly formatted mnemonic
                encoding: "".to_string(),
            };

            let ret_bytes = call_api("keystore_common_exists", param).unwrap();
            let result: KeystoreCommonExistsResult =
                KeystoreCommonExistsResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, wallet.id);

            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    pub fn test_keystore_common_accounts() {
        run_test(|| {
            let wallet = import_default_wallet();

            let param: KeystoreCommonAccountsParam = KeystoreCommonAccountsParam {
                id: wallet.id.to_string(),
            };

            let ret_bytes = call_api("keystore_common_accounts", param).unwrap();
            let result: AccountsResponse = AccountsResponse::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(0, result.accounts.len());

            let derivations = vec![Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/44'/2'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = KeystoreCommonDeriveParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations,
            };
            let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
            let derived_accounts: AccountsResponse =
                AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(1, derived_accounts.accounts.len());
            assert_eq!(
                "Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP",
                derived_accounts.accounts[0].address
            );

            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    pub fn test_sign_ckb_tx() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "NERVOS".to_string(),
                path: "m/44'/309'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);
            let out_points = vec![
                OutPoint {
                    tx_hash: "0xfb9c020db967e84af1fbd755df5bc23427e2ed70f73e07895a0c394f6195f083"
                        .to_owned(),
                    index: 0,
                },
                OutPoint {
                    tx_hash: "0xfb9c020db967e84af1fbd755df5bc23427e2ed70f73e07895a0c394f6195f083"
                        .to_owned(),
                    index: 1,
                },
            ];

            let code_hash =
                "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8".to_owned();

            let input = CkbTxInput {
                inputs: vec![
                    CellInput {
                        previous_output: Some(out_points[0].clone()),
                        since: "".to_string(),
                    },
                    CellInput {
                        previous_output: Some(out_points[1].clone()),
                        since: "".to_string(),
                    },
                ],
                witnesses: vec![Witness::default(), Witness::default()],
                cached_cells: vec![
                    CachedCell {
                        capacity: 0,
                        lock: Some(Script {
                            hash_type: "type".to_string(),
                            code_hash: code_hash.clone(),
                            args: "0xb45772677603bccc71194b2557067fb361c1e093".to_owned(),
                        }),
                        out_point: Some(out_points[0].clone()),
                        derived_path: "0/1".to_string(),
                    },
                    CachedCell {
                        capacity: 0,
                        lock: Some(Script {
                            hash_type: "type".to_string(),
                            code_hash: code_hash.clone(),
                            args: "0x2d79d9ed37184c1136bcfbe229947a137f80dec0".to_owned(),
                        }),
                        out_point: Some(out_points[1].clone()),
                        derived_path: "1/0".to_string(),
                    },
                ],
                tx_hash: "0x102b8e88daadf1b035577b4d5ea4f604be965df6a918e72daeff6c0c40753401"
                    .to_owned(),
            };

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "NERVOS".to_string(),
                path: "m/44'/309'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1.as_str().to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input).unwrap(),
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let output: CkbTxOutput = CkbTxOutput::decode(ret.as_slice()).unwrap();
            assert_eq!("0x5500000010000000550000005500000041000000776e010ac7e7166afa50fe54cfecf0a7106a2f11e8110e071ccab67cb30ed5495aa5c5f5ca2967a2fe4a60d5ad8c811382e51d8f916ba2911552bef6dedeca8a00", output.witnesses[0]);
            assert_eq!("0x5500000010000000550000005500000041000000914591d8abd5233740207337b0588fec58cad63143ddf204970526022b6db26d68311e9af49e1625e3a90e8a66eb1694632558d561d1e5d02cc7c7254e2d546100", output.witnesses[1]);

            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    pub fn test_sign_tron_tx() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);

            let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
            let input = TronTxInput { raw_data };
            let input_value = encode_message(input).unwrap();
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password("WRONG PASSWORD".to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TRON1".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_chain");

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let output: TronTxOutput = TronTxOutput::decode(ret.as_slice()).unwrap();
            let expected_sign = "bbf5ce0549490613a26c3ac4fc8574e748eabda05662b2e49cea818216b9da18691e78cd6379000e9c8a35c13dfbf620f269be90a078b58799b56dc20da3bdf200";
            assert_eq!(expected_sign, output.signatures[0]);
            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    pub fn test_sign_cosmos_tx() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "SECP256k1".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);

            let raw_data = "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201".to_string();
            let input = AtomTxInput { raw_data };
            let input_value = encode_message(input).unwrap();
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password("WRONG PASSWORD".to_string())),
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "COSMOS1".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_chain");

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let output: AtomTxOutput = AtomTxOutput::decode(ret.as_slice()).unwrap();
            let expected_sig = "355fWQ00dYitAZj6+EmnAgYEX1g7QtUrX/kQIqCbv05TCz0dfsWcMgXWVnr1l/I2hrjjQkiLRMoeRrmnqT2CZA==";
            assert_eq!(expected_sig, output.signature);
            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    pub fn test_get_public_key() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "EOS".to_string(),
                path: "m/44'/194'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "SECP256k1".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);

            let param: PublicKeyParam = PublicKeyParam {
                id: wallet.id.to_string(),
                chain_type: "EOS".to_string(),
                address: "".to_string(),
            };
            let ret_bytes = call_api("get_public_key", param).unwrap();
            let public_key_result: PublicKeyResult =
                PublicKeyResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
                public_key_result.public_key
            );
        })
    }

    // #[test]
    // pub fn test_sign_substrate_tx() {
    //     run_test(|| {
    //         let derivation = Derivation {
    //             chain_type: "KUSAMA".to_string(),
    //             path: "//kusama//imToken/0".to_string(),
    //             network: "".to_string(),
    //             seg_wit: "".to_string(),
    //             chain_id: "".to_string(),
    //         };
    //
    //         let wallet = import_and_derive(derivation);
    //
    //         let input = SubstrateTxIn {
    //             method: "transfer".to_string(),
    //             address: "EwDXBhgNrcNvMVhm9fRq5YCTdAsPRBPo3t4tUZ85Q9ydKNs".to_string(),
    //             amount: 10000000000,
    //             era: Some(ExtrinsicEra {
    //                 current: 1202925,
    //                 period: 2400,
    //             }),
    //             nonce: 5,
    //             tip: 10000000000,
    //             sepc_version: 1045,
    //             genesis_hash: "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe"
    //                 .to_string(),
    //             block_hash: "790628ced8e0649883f3dd20344d9e6b014f076e788742f0925cf3875997e883"
    //                 .to_string(),
    //         };
    //
    //         let input_value = encode_message(input).unwrap();
    //         let tx = SignParam {
    //             id: wallet.id.to_string(),
    //             password: TEST_PASSWORD.to_string(),
    //             chain_type: "KUSAMA".to_string(),
    //             address: wallet.accounts.first().unwrap().address.to_string(),
    //             input: Some(::prost_types::Any {
    //                 type_url: "imtoken".to_string(),
    //                 value: input_value.clone(),
    //             }),
    //         };
    //
    //         let ret = call_api("sign_tx", tx).unwrap();
    //         let output: SubstrateTxOut = SubstrateTxOut::decode(&ret).unwrap();
    //
    //         let expected_ret_before_sig =
    //             "550284ffce9e36de55716d91b1c50caa36a58cee6d28e532a710df0cf90609363947dd7801";
    //         let expected_ret_after_sig = "dbae140700e40b54020400ff68686f29461fcc99ab3538c391e42556e49efc1ffa7933da42335aa626fae25a0700e40b5402";
    //
    //         assert_eq!(
    //             output.signature[0..74].to_string(),
    //             expected_ret_before_sig,
    //             "before sig"
    //         );
    //         assert_eq!(
    //             output.signature[202..].to_string(),
    //             expected_ret_after_sig,
    //             "after sig"
    //         );
    //
    //         let sig_bytes = hex::decode(output.signature[74..202].to_string()).unwrap();
    //         let signature = sp_core::sr25519::Signature::from_slice(&sig_bytes);
    //
    //         let pub_key =
    //             hex::decode("ce9e36de55716d91b1c50caa36a58cee6d28e532a710df0cf90609363947dd78")
    //                 .unwrap();
    //         let singer = sp_core::sr25519::Public::from_slice(&pub_key);
    //         let msg = hex::decode("0400ff68686f29461fcc99ab3538c391e42556e49efc1ffa7933da42335aa626fae25a0700e40b5402dbae140700e40b540215040000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe790628ced8e0649883f3dd20344d9e6b014f076e788742f0925cf3875997e883").unwrap();
    //
    //         assert!(
    //             sp_core::sr25519::Signature::verify(&signature, msg.as_slice(), &singer),
    //             "assert sig"
    //         );
    //
    //         remove_created_wallet(&wallet.id);
    //     })
    // }

    #[test]
    pub fn test_import_substrate_keystore() {
        run_test(|| {
            let wrong_keystore_str: &str = r#"{
  "address": "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS",
  "encoded": "0xf7e7e89d3016c9b4d93bb1129adf69e5949ca1fb58c29da4591ddc72c52238a35835e3f2ae023f9867ff301bc4132463527ac03525eaac54664a7cb658eae68a0bbc99354222c194d6100b2bf3a492639229077a2e2818d8196e002f0b5556104be23b11633858259dbbd3f91ea1d34d6ce182b62d8381af1ef3c35e9ab1583267cfa41aa58bfd64435c2b5047baf9052f0953d9f7854d2d396dfcad13",
  "encoding": {
    "content": [
      "pkcs8",
      "sr25519"
    ],
    "type": "",
    "version": "2"
  },
  "meta": {
    "genesisHash": "0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
    "name": "i_can_save_name",
    "tags": [],
    "whenCreated": 1593591324334
  }
}"#;

            let param = SubstrateKeystoreParam {
                keystore: wrong_keystore_str.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "KUSAMA".to_string(),
                overwrite: true,
            };
            // let param_bytes = encode_message(param).unwrap();

            let ret = call_api("substrate_keystore_exists", param.clone());

            // let ret: Response = Response::decode(ret_bytes.as_slice()).unwrap();

            assert!(ret.is_err());
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "invalid_keystore# only support xsalsa20-poly1305"
            );

            let keystore_str: &str = r#"{
  "address": "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS",
  "encoded": "0xf7e7e89d3016c9b4d93bb1129adf69e5949ca1fb58c29da4591ddc72c52238a35835e3f2ae023f9867ff301bc4132463527ac03525eaac54664a7cb658eae68a0bbc99354222c194d6100b2bf3a492639229077a2e2818d8196e002f0b5556104be23b11633858259dbbd3f91ea1d34d6ce182b62d8381af1ef3c35e9ab1583267cfa41aa58bfd64435c2b5047baf9052f0953d9f7854d2d396dfcad13",
  "encoding": {
    "content": [
      "pkcs8",
      "sr25519"
    ],
    "type": "xsalsa20-poly1305",
    "version": "2"
  },
  "meta": {
    "genesisHash": "0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
    "name": "i_can_save_name",
    "tags": [],
    "whenCreated": 1593591324334
  }
}"#;

            let param = SubstrateKeystoreParam {
                keystore: keystore_str.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "KUSAMA".to_string(),
                overwrite: true,
            };
            // let param_bytes = encode_message(param).unwrap();

            let ret_bytes = call_api("substrate_keystore_exists", param.clone()).unwrap();

            let exists_result: KeystoreCommonExistsResult =
                KeystoreCommonExistsResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(!exists_result.is_exists);

            let ret_bytes = call_api("substrate_keystore_import", param.clone()).unwrap();
            let wallet_ret: WalletResult = WalletResult::decode(ret_bytes.as_slice()).unwrap();

            let ret_bytes = call_api("substrate_keystore_exists", param.clone()).unwrap();
            let exists_result: KeystoreCommonExistsResult =
                KeystoreCommonExistsResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(exists_result.is_exists);

            let derivation = Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let param = KeystoreCommonDeriveParam {
                id: wallet_ret.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param).unwrap();
            let accounts: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

            assert_eq!(
                accounts.accounts[0].address,
                "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS"
            );

            let export_param = ExportPrivateKeyParam {
                id: wallet_ret.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "KUSAMA".to_string(),
                network: "".to_string(),
                main_address: "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS".to_string(),
                path: "".to_string(),
            };
            let ret = call_api("substrate_keystore_export", export_param).unwrap();
            let keystore_ret: ExportSubstrateKeystoreResult =
                ExportSubstrateKeystoreResult::decode(ret.as_slice()).unwrap();

            let keystore: SubstrateKeystore = serde_json::from_str(&keystore_ret.keystore).unwrap();
            assert!(keystore.validate().is_ok());
            assert_eq!(
                keystore.address,
                "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS"
            );
            assert_eq!(keystore.meta.name, "i_can_save_name");
            assert!(keystore.meta.when_created > 1594102917);

            // assert_eq!(keystore_ret.fixtures, "");
            remove_created_wallet(&wallet_ret.id);
        })
    }

    #[test]
    pub fn test_export_hd_polkadot_keystore() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };
            let wallet = import_and_derive(derivation);
            assert_eq!(
                wallet.accounts[0].address,
                "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS"
            );

            let export_param = ExportPrivateKeyParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "KUSAMA".to_string(),
                network: "".to_string(),
                main_address: "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS".to_string(),
                path: "".to_string(),
            };
            let ret = call_api("substrate_keystore_export", export_param);
            assert!(ret.is_err());
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "hd_wallet_cannot_export_keystore"
            );

            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    pub fn test_import_multi_curve() {
        run_test(|| {
            let keystore_str: &str = r#"{
  "address": "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS",
  "encoded": "0xf7e7e89d3016c9b4d93bb1129adf69e5949ca1fb58c29da4591ddc72c52238a35835e3f2ae023f9867ff301bc4132463527ac03525eaac54664a7cb658eae68a0bbc99354222c194d6100b2bf3a492639229077a2e2818d8196e002f0b5556104be23b11633858259dbbd3f91ea1d34d6ce182b62d8381af1ef3c35e9ab1583267cfa41aa58bfd64435c2b5047baf9052f0953d9f7854d2d396dfcad13",
  "encoding": {
    "content": [
      "pkcs8",
      "sr25519"
    ],
    "type": "xsalsa20-poly1305",
    "version": "2"
  },
  "meta": {
    "genesisHash": "0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
    "name": "keystore_import",
    "tags": [],
    "whenCreated": 1593591324334
  }
}"#;

            let param = SubstrateKeystoreParam {
                keystore: keystore_str.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "KUSAMA".to_string(),
                overwrite: true,
            };
            // let param_bytes = encode_message(param).unwrap();
            let ret_bytes = call_api("substrate_keystore_import", param).unwrap();
            let wallet_ret: WalletResult = WalletResult::decode(ret_bytes.as_slice()).unwrap();
            let derivation = Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let param = KeystoreCommonDeriveParam {
                id: wallet_ret.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param).unwrap();
            let accounts: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

            assert_eq!(
                accounts.accounts[0].address,
                "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS"
            );

            let derivation = Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let param = KeystoreCommonDeriveParam {
                id: wallet_ret.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param);
            assert!(ret.is_err());
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "pkstore_can_not_add_other_curve_account"
            );

            remove_created_wallet(&wallet_ret.id);
        })
    }

    #[test]
    pub fn test_sign_substrate_raw_tx() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "//kusama//imToken/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);

            let unsigned_msg = "0x0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7";
            let input = SubstrateRawTxIn {
                raw_data: unsigned_msg.to_string(),
            };

            let input_value = encode_message(input).unwrap();
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "KUSAMA".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let output: SubstrateTxOut = SubstrateTxOut::decode(ret.as_slice()).unwrap();

            assert_eq!(output.signature[0..4].to_string(), "0x01",);

            let sig_bytes = hex::decode(output.signature[4..].to_string()).unwrap();
            let signature = sp_core::sr25519::Signature::from_slice(&sig_bytes).unwrap();

            let pub_key =
                hex::decode("90742a577c8515391a46b7881c98c80ec92fe04255bb5b5fec862c7d633ada21")
                    .unwrap();
            let singer = sp_core::sr25519::Public::from_slice(&pub_key).unwrap();
            let msg = hex::decode("0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7").unwrap();

            assert!(
                sp_core::sr25519::Signature::verify(&signature, msg.as_slice(), &singer),
                "assert sig"
            );

            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    pub fn test_sign_tron_tx_by_pk() {
        run_test(|| {
            let import_result = import_default_pk_store();

            let derivation = Derivation {
                chain_type: "TRON".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param).unwrap();
            let rsp: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

            let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
            let input = TronTxInput { raw_data };
            let tx = SignParam {
                id: import_result.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input).unwrap(),
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let output: TronTxOutput = TronTxOutput::decode(ret.as_slice()).unwrap();
            let expected_sign = "7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001";
            assert_eq!(expected_sign, output.signatures[0]);
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_sign_filecoin_bls() {
        run_test(|| {
            let import_result = import_filecoin_pk_store();

            let derivation = Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "BLS".to_string(),
                bech32_prefix: "".to_string(),
            };
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param).unwrap();
            let rsp: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

            let message = UnsignedMessage {
                to: "t12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey".to_string(),
                from: "t3r52r4c7dxhzuhubdenjuxgfak5tbmb3pbcv35wngm6qgvo7bwmvbuuw274rwyhcp53ydtt3ugexjnltnk75q".to_string(),
                nonce: 0,
                value: "100000".to_string(),
                gas_limit: 10000,
                gas_fee_cap: "20000".to_string(),
                gas_premium: "20000".to_string(),
                method: 0,
                params: "".to_string()
            };

            let tx = SignParam {
                id: import_result.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "FILECOIN".to_string(),
                path: "m/44'/461'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(message).unwrap(),
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let signed = SignedMessage::decode(ret.as_slice()).unwrap();
            let expected_sign = "r+CN2nhRN7d23jTFDvescYjkqg6iFwlcb2yZugewBsLko96E+UEYuSuhheaSGu1SDU7gYx54tsxYC/Zq3Pk0gfTAHPC2Ui9P5oNE3hNtb0mHO7D4ZHID2I4RxKFTAY8N" ;
            assert_eq!(expected_sign, signed.signature.unwrap().data);

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_sign_filecoin_secp256k1() {
        run_test(|| {
            let import_result = import_default_pk_store();

            let derivation = Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "SECP256k1".to_string(),
                bech32_prefix: "".to_string(),
            };
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param).unwrap();
            let rsp: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

            let message = UnsignedMessage {
                to: "t12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey".to_string(),
                from: "t1zerdvi3fx2lrcslsqdewpadzzm2hefpn6ixew3i".to_string(),
                nonce: 0,
                value: "100000".to_string(),
                gas_limit: 10000,
                gas_fee_cap: "20000".to_string(),
                gas_premium: "20000".to_string(),
                method: 0,
                params: "".to_string(),
            };

            let tx = SignParam {
                id: import_result.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "FILECOIN".to_string(),
                path: "m/44'/461'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(message).unwrap(),
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let signed = SignedMessage::decode(ret.as_slice()).unwrap();
            let expected_sign = "YJLfRrV7WovsWUY4nhKRp8Vs9AGC9J61zV8InwWM6IwxBVhtc20mJC7cxWdVMBQ45Mem2yS7bqQe7alkSxQvpwA=" ;
            assert_eq!(expected_sign, signed.signature.unwrap().data);

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_sign_by_dk_in_pk_store() {
        run_test(|| {
            let import_result = import_default_pk_store();

            let derivation = Derivation {
                chain_type: "TRON".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };
            let param = KeystoreCommonDeriveParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                derivations: vec![derivation],
            };

            let ret = call_api("keystore_common_derive", param).unwrap();
            let rsp: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
            };
            let ret_bytes = get_derived_key(&encode_message(param).unwrap()).unwrap();
            let ret: DerivedKeyResult = DerivedKeyResult::decode(ret_bytes.as_slice()).unwrap();
            let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
            let input = TronTxInput { raw_data };
            let tx = SignParam {
                id: import_result.id.to_string(),
                key: Some(Key::DerivedKey(ret.derived_key)),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input.clone()).unwrap(),
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let output: TronTxOutput = TronTxOutput::decode(ret.as_slice()).unwrap();
            let expected_sign = "7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001";
            assert_eq!(expected_sign, output.signatures[0]);

            let tx = SignParam {
                id: import_result.id.to_string(),
                key: Some(Key::DerivedKey("7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001".to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input.clone()).unwrap(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!("derived_key_not_matched", format!("{}", ret.err().unwrap()));

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    fn test_sign_message() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };
            let wallet = import_and_derive(derivation);

            let input_expects = vec![
                (TronMessageInput {
                    value: "645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                        .to_string(),
                    is_tron_header: true,
                }, "16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b"),
                (TronMessageInput {
                    value: "0x645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                        .to_string(),
                    is_tron_header: true,
                }, "16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b"),
                (TronMessageInput {
                    value: "645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                        .to_string(),
                    is_tron_header: false,
                }, "06ff3c5f98b8e8e257f47a66ce8e953c7a7d0f96eb6687da6a98b66a36c2a725759cab3df94d014bd17760328adf860649303c68c4fa6644d9f307e2f32cc3311c"),
                (TronMessageInput {
                    value: "abcdef"
                        .to_string(),
                    is_tron_header: true,
                }, "a87eb6ae7e97621b6ba2e2f70db31fe0c744c6adcfdc005044026506b70ac11a33f415f4478b6cf84af32b3b5d70a13a77e53287613449b345bb16fe012c04081b"),
            ];
            for (input, expected) in input_expects {
                let tx = SignParam {
                    id: wallet.id.to_string(),
                    key: Some(Key::Password(TEST_PASSWORD.to_string())),
                    chain_type: "TRON".to_string(),
                    path: "m/44'/195'/0'/0/0".to_string(),
                    curve: "SECP256k1".to_string(),
                    input: Some(::prost_types::Any {
                        type_url: "imtoken".to_string(),
                        value: encode_message(input).unwrap(),
                    }),
                };

                let sign_result = call_api("tron_sign_msg", tx).unwrap();
                let ret: TronMessageOutput =
                    TronMessageOutput::decode(sign_result.as_slice()).unwrap();
                assert_eq!(expected, ret.signature);
            }
            //            let input = TronMessageInput {
            //                value: "645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
            //                    .to_string(),
            //                is_hex: true,
            //                is_tron_header: true,
            //            };
        });
    }

    #[test]
    fn test_sign_by_dk_hd_store() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };
            let wallet = import_and_derive(derivation);

            let input = TronMessageInput {
                value: "645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                    .to_string(),
                is_tron_header: true,
            };

            let dk_param = WalletKeyParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
            };

            let ret_bytes = get_derived_key(&encode_message(dk_param).unwrap()).unwrap();
            let ret: DerivedKeyResult = DerivedKeyResult::decode(ret_bytes.as_slice()).unwrap();

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::DerivedKey(ret.derived_key)),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input.clone()).unwrap(),
                }),
            };

            let sign_result = call_api("tron_sign_msg", tx).unwrap();
            let ret: TronMessageOutput = TronMessageOutput::decode(sign_result.as_slice()).unwrap();
            assert_eq!("16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b", ret.signature);

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::DerivedKey("7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001".to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input).unwrap(),
                }),
            };

            let ret = call_api("tron_sign_msg", tx);
            assert!(ret.is_err());
            assert_eq!("derived_key_not_matched", format!("{}", ret.err().unwrap()));

            remove_created_wallet(&wallet.id);
        });
    }

    #[test]
    pub fn test_sign_btc_fork_invalid_address() {
        run_test(|| {
            //            let chain_types = vec!["BITCOINCASH", "LITECOIN"];
            let chain_types = vec!["BITCOIN", "LITECOIN", "BITCOINCASH"];

            let import_result: WalletResult = import_default_wallet();

            for chain_type in chain_types {
                let derivation = Derivation {
                    chain_type: chain_type.to_string(),
                    path: "m/44'/0'/0'/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "".to_string(),
                    bech32_prefix: "".to_string(),
                };
                let param = KeystoreCommonDeriveParam {
                    id: import_result.id.to_string(),
                    password: TEST_PASSWORD.to_string(),
                    derivations: vec![derivation],
                };

                let ret = call_api("keystore_common_derive", param).unwrap();
                let rsp: AccountsResponse = AccountsResponse::decode(ret.as_slice()).unwrap();

                let inputs = vec![Utxo {
                    tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                        .to_string(),
                    vout: 0,
                    amount: 1000000,
                    address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                    derived_path: "0/0".to_string(),
                }];
                let tx_input = BtcKinTxInput {
                    inputs,
                    to: "invalid_address".to_string(),
                    amount: 500000,
                    fee: 100000,
                    change_address_index: Some(1u32),
                    op_return: None,
                };
                let input_value = encode_message(tx_input).unwrap();
                let tx = SignParam {
                    id: import_result.id.to_string(),
                    key: Some(Key::Password(TEST_PASSWORD.to_string())),
                    chain_type: chain_type.to_string(),
                    path: "m/44'/0'/0'/0/0".to_string(),
                    curve: "SECP256k1".to_string(),
                    input: Some(::prost_types::Any {
                        type_url: "imtoken".to_string(),
                        value: input_value.clone(),
                    }),
                };

                let ret = call_api("sign_tx", tx);
                assert!(ret.is_err());
                assert_eq!(format!("{}", ret.err().unwrap()), "address_invalid");
            }

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    pub fn test_lock_after_sign() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);

            let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
            let input = TronTxInput { raw_data };
            let input_value = encode_message(input).unwrap();

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
            };
            {
                let map = KEYSTORE_MAP.read();
                let keystore: &Keystore = map.get(&wallet.id).unwrap();
                assert!(keystore.is_locked());
            }

            let ret = call_api("sign_tx", tx).unwrap();
            let output: TronTxOutput = TronTxOutput::decode(ret.as_slice()).unwrap();
            let expected_sign = "bbf5ce0549490613a26c3ac4fc8574e748eabda05662b2e49cea818216b9da18691e78cd6379000e9c8a35c13dfbf620f269be90a078b58799b56dc20da3bdf200";
            assert_eq!(expected_sign, output.signatures[0]);

            {
                let map = KEYSTORE_MAP.read();
                let keystore: &Keystore = map.get(&wallet.id).unwrap();
                assert!(keystore.is_locked());
            }

            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    fn test_get_derived_key() {
        let param = InitTokenCoreXParam {
            file_dir: "../test-data".to_string(),
            xpub_common_key: "B888D25EC8C12BD5043777B1AC49F872".to_string(),
            xpub_common_iv: "9C0C30889CBCC5E01AB5B2BB88715799".to_string(),
            is_debug: true,
        };

        handler::init_token_core_x(&encode_message(param).unwrap()).expect("should init tcx");

        let param = WalletKeyParam {
            id: "cb1ba2d7-7b89-4595-9753-d16b6e317c6b".to_string(),
            password: "WRONG PASSWORD".to_string(),
        };

        let ret = call_api("get_derived_key", param);
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

        let param = WalletKeyParam {
            id: "cb1ba2d7-7b89-4595-9753-d16b6e317c6b".to_string(),
            password: TEST_PASSWORD.to_string(),
        };

        let ret = call_api("get_derived_key", param).unwrap();
        let dk_ret: DerivedKeyResult = DerivedKeyResult::decode(ret.as_slice()).unwrap();
        assert_eq!(dk_ret.derived_key, "119a38ab626aaf8806e223833b29da7aa1d0623e282164d1dd73b0b5e0a88fb4b88937efadd9ca9d4ee931d7b2b33594d75ac4f4d651602819998237b27860fa");
    }
    //
    //    #[test]
    //    fn test_export_used_dk() {
    //        let param = InitTokenCoreXParam {
    //            file_dir: "../test-data".to_string(),
    //            xpub_common_key: "B888D25EC8C12BD5043777B1AC49F872".to_string(),
    //            xpub_common_iv: "9C0C30889CBCC5E01AB5B2BB88715799".to_string(),
    //            is_debug: true,
    //        };
    //
    //        handler::init_token_core_x(&encode_message(param).unwrap()).expect("should init tcx");
    //
    //        let param = PrivateKeyStoreExportParam {
    //            id: "cb1ba2d7-7b89-4595-9753-d16b6e317c6b".to_string(),
    //            password: "119a38ab626aaf8806e223833b29da7aa1d0623e282164d1dd73b0b5e0a88fb4b88937efadd9ca9d4ee931d7b2b33594d75ac4f4d651602819998237b27860fa".to_string(),
    //            chain_type: "TRON".to_string(),
    //            network: "".to_string()
    //        };
    //
    //        let ret = call_api("private_key_store_export", param).unwrap();
    //        let export_ret: KeystoreCommonExportResult =
    //            KeystoreCommonExportResult::decode(ret.as_slice()).unwrap();
    //        assert_eq!(
    //            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
    //            export_ret.value
    //        );
    //    }

    // #[test]
    // fn decode_error() {
    //     let param_hex = "0a166b657973746f72655f636f6d6d6f6e5f646572697665127a0a1d6170692e4b657973746f7265436f6d6d6f6e446572697665506172616d12590a2432303766353663652d306363302d343239352d626165632d353931366434653639353933120831323334313233341a270a0554455a4f5312116d2f3434272f31373239272f30272f30271a074d41494e4e455422002a00";
    //     let param_bytes = hex::decode(param_hex).unwrap();
    //     let action: TcxAction = TcxAction::decode(param_bytes.as_slice()).unwrap();
    //     let param: KeystoreCommonDeriveParam =
    //         KeystoreCommonDeriveParam::decode(action.param.unwrap().value.as_slice()).unwrap();
    //     assert_eq!("1", format!("{:?}", param))
    // }

    #[test]
    fn test_panic_keystore_locked() {
        run_test(|| {
            let wallet = import_default_wallet();
            let param = WalletKeyParam {
                id: wallet.id.to_string(),
                password: TEST_PASSWORD.to_string(),
            };
            let _ret = call_api("unlock_then_crash", param);
            let err = unsafe { _to_str(get_last_err_message()) };
            let err_bytes = hex::decode(err).unwrap();
            let rsp: Response = Response::decode(err_bytes.as_slice()).unwrap();
            assert!(!rsp.is_success);
            assert_eq!(rsp.error, "test_unlock_then_crash");
            let map = KEYSTORE_MAP.read();
            let keystore: &Keystore = map.get(&wallet.id).unwrap();
            assert!(keystore.is_locked())
        });
    }

    fn remove_created_wallet(wid: &str) {
        let full_file_path = format!("{}/{}.json", "/tmp/imtoken/wallets", wid);
        let p = Path::new(&full_file_path);
        remove_file(p).expect("should remove file");
    }

    #[test]
    pub fn test_sign_tezos_tx() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);

            let raw_data = "d3bdafa2e36f872e24f1ccd68dbdca4356b193823d0a6a54886d7641e532a2a26c00dedf1a2f428e5e85edf105cb3600949f3d0e8837c70cacb4e803e8528102c0843d0000dcdcf88d0cfb769e33b1888d6bdc351ee3277ea700".to_string();
            let input = TezosRawTxIn { raw_data };
            let input_value = encode_message(input).unwrap();
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password("WRONG PASSWORD".to_string())),
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TEZOS1".to_string(),
                path: "m/44'/1729'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_chain");

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();

            let output: TezosTxOut = TezosTxOut::decode(ret.as_slice()).unwrap();
            let expected_sign = "0df020458bdcfe24546488dd81e1bd7e2cb05379dc7c72ad626646ae22df5d3a652fdc4ffd2383dd5823a98fe158780928da07a3f0a234e23b759ce7b3a39a0c";
            assert_eq!(expected_sign, output.signature.as_str());
            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    fn test_zksync_api() {
        let input = ZksyncPrivateKeyFromSeedParam{
            seed: "9883e3c6e2558f8dc7ab8ad227059d5e59bd1933487372d8bb6c0039246760363762f694a5e43309d7b3a60abd4ac73bc493f899448d28ef29a4a2798e4edc4e1b".to_string(),
        };
        let ret = call_api("zksync_private_key_from_seed", input).unwrap();
        let output: ZksyncPrivateKeyFromSeedResult =
            ZksyncPrivateKeyFromSeedResult::decode(ret.as_slice()).unwrap();
        assert_eq!(
            output.priv_key,
            "052b33b8567fb0482aa42393daf76a8c9dd3da301358989e47ec26f60a68f37c".to_string()
        );

        let input = ZksyncSignMusigParam{
            priv_key: "052b33b8567fb0482aa42393daf76a8c9dd3da301358989e47ec26f60a68f37c".to_string(),
            bytes: "05000525e8da9bf8e3e67882ba59e291b6897e3db114cf6bdeda9bf8e3e67882ba59e291b6897e3db114cf6bde00289502f90005292e0000001a000000000000000000000000ffffffff".to_string()
        };
        let ret = call_api("zksync_sign_musig", input).unwrap();
        let output: ZksyncSignMusigResult = ZksyncSignMusigResult::decode(ret.as_slice()).unwrap();
        assert_eq!(output.signature, "c5cd3d01ed5ea20dd16732958c4e02d6c1c5f22544f20a459e609cb7bd6b002f1fbd87f2d94398756ffe7f63e462521ee852479163340c0f9ba0d6f0814eef2e50fd50d7e2314fa4be4590069fe73a8f94c93e81aaba6fd89329dda76f074501".to_string());

        let input = ZksyncPrivateKeyToPubkeyHashParam {
            priv_key: "052b33b8567fb0482aa42393daf76a8c9dd3da301358989e47ec26f60a68f37c"
                .to_string(),
        };
        let ret = call_api("zksync_private_key_to_pubkey_hash", input).unwrap();
        let output: ZksyncPrivateKeyToPubkeyHashResult =
            ZksyncPrivateKeyToPubkeyHashResult::decode(ret.as_slice()).unwrap();
        assert_eq!(
            output.pub_key_hash,
            "90bfd58db4742ce7803ed158f30266ac17b8a0b4".to_string()
        );
    }

    // #[test]
    // pub fn test_ethereum2_get_pubkey() {
    //     run_test(|| {
    //         let param = HdStoreImportParam {
    //             mnemonic: OTHER_MNEMONIC.to_string(),
    //             password: TEST_PASSWORD.to_string(),
    //             source: "MNEMONIC".to_string(),
    //             name: "test-wallet".to_string(),
    //             password_hint: "imtoken".to_string(),
    //             overwrite: true,
    //         };
    //         let ret = call_api("hd_store_import", param).unwrap();
    //         let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();

    //         let derivations = vec![Derivation {
    //             chain_type: "ETHEREUM2".to_string(),
    //             path: "m/12381/3600/0/0/0".to_string(),
    //             network: "MAINNET".to_string(),
    //             seg_wit: "".to_string(),
    //             chain_id: "".to_string(),
    //             curve: "BLS".to_string(),
    //             bech32_prefix: "".to_string(),
    //         }];

    //         let param = KeystoreCommonDeriveParam {
    //             id: import_result.id.to_string(),
    //             password: TEST_PASSWORD.to_string(),
    //             derivations,
    //         };
    //         let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
    //         let derived_accounts: AccountsResponse =
    //             AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
    //         assert_eq!(
    //             "941c2ab3d28b0fe37fde727e3178738a475696aed7335c7f4c2d91d06a1540acadb8042f119fb5f8029e7765de21fac2",
    //             derived_accounts.accounts[0].address
    //         );
    //         let param: PublicKeyParam = PublicKeyParam {
    //             id: import_result.id.to_string(),
    //             chain_type: "ETHEREUM2".to_string(),
    //             address: "941c2ab3d28b0fe37fde727e3178738a475696aed7335c7f4c2d91d06a1540acadb8042f119fb5f8029e7765de21fac2".to_string(),
    //         };
    //         let ret_bytes = call_api("get_public_key", param).unwrap();
    //         let public_key_result: PublicKeyResult =
    //             PublicKeyResult::decode(ret_bytes.as_slice()).unwrap();
    //         assert_eq!(
    //             "941c2ab3d28b0fe37fde727e3178738a475696aed7335c7f4c2d91d06a1540acadb8042f119fb5f8029e7765de21fac2",
    //             public_key_result.public_key
    //         );
    //         remove_created_wallet(&import_result.id);
    //     })
    // }

    // #[test]
    // pub fn test_sign_bls_to_execution_change() {
    //     run_test(|| {
    //         let param = HdStoreImportParam {
    //             mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art".to_string(),
    //             password: TEST_PASSWORD.to_string(),
    //             source: "MNEMONIC".to_string(),
    //             name: "test-wallet".to_string(),
    //             password_hint: "imtoken".to_string(),
    //             overwrite: true,
    //         };
    //         let ret = call_api("hd_store_import", param).unwrap();
    //         let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();

    //         let derivations = vec![Derivation {
    //             chain_type: "ETHEREUM2".to_string(),
    //             path: "m/12381/3600/0/0".to_string(),
    //             network: "MAINNET".to_string(),
    //             seg_wit: "".to_string(),
    //             chain_id: "".to_string(),
    //             curve: "BLS".to_string(),
    //             bech32_prefix: "".to_string(),
    //         }];

    //         let param = KeystoreCommonDeriveParam {
    //             id: import_result.id.to_string(),
    //             password: TEST_PASSWORD.to_string(),
    //             derivations,
    //         };
    //         let derived_accounts_bytes = call_api("keystore_common_derive", param).unwrap();
    //         let derived_accounts: AccountsResponse =
    //             AccountsResponse::decode(derived_accounts_bytes.as_slice()).unwrap();
    //         assert_eq!(1, derived_accounts.accounts.len());
    //         assert_eq!(
    //             "99b1f1d84d76185466d86c34bde1101316afddae76217aa86cd066979b19858c2c9d9e56eebc1e067ac54277a61790db",
    //             derived_accounts.accounts[0].address
    //         );

    //         let param = SignBlsToExecutionChangeParam {
    //             id: import_result.id.to_string(),
    //             password: TEST_PASSWORD.to_string(),
    //             genesis_fork_version: "0x03000000".to_string(),
    //             genesis_validators_root:
    //                 "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_string(),
    //             validator_index: vec![0],
    //             from_bls_pub_key: derived_accounts.accounts[0].clone().address,
    //             eth1_withdrawal_address: "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15".to_string(),
    //         };
    //         let ret_bytes = call_api("sign_bls_to_execution_change", param).unwrap();
    //         let result: SignBlsToExecutionChangeResult =
    //             SignBlsToExecutionChangeResult::decode(ret_bytes.as_slice()).unwrap();

    //         assert_eq!(result.signeds.get(0).unwrap().signature, "8c8ce9f8aedf380e47548501d348afa28fbfc282f50edf33555a3ed72eb24d710bc527b5108022cffb764b953941ec4014c44106d2708387d26cc84cbc5c546a1e6e56fdc194cf2649719e6ac149596d80c86bf6844b36bd47038ee96dd3962f");
    //         remove_created_wallet(&import_result.id);
    //     })
    // }

    #[test]
    pub fn test_generate_mnemonic() {
        run_test(|| {
            let generate_mnemonic_bytes = call_api("generate_mnemonic", ()).unwrap();
            let generate_mnemonic_result: GenerateMnemonicResult =
                GenerateMnemonicResult::decode(generate_mnemonic_bytes.as_slice()).unwrap();
            let split_result: Vec<&str> = generate_mnemonic_result
                .mnemonic
                .split_whitespace()
                .collect();
            assert_eq!(split_result.len(), 12);
        })
    }

    // #[test]
    // pub fn test_identity_wallet_create() {
    //     run_test(|| {
    //         let param = CreateIdentityParam {
    //             name: sample_key::NAME.to_string(),
    //             password: sample_key::PASSWORD.to_string(),
    //             password_hint: Some(sample_key::PASSWORD_HINT.to_string()),
    //             network: model::NETWORK_TESTNET.to_string(),
    //             seg_wit: None,
    //         };
    //         let ret = call_api("create_identity", param).unwrap();
    //         let create_result: CreateIdentityResult =
    //             CreateIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert!(create_result.ipfs_id.len() > 0);
    //         assert!(create_result.identifier.len() > 0);

    //         let param = CreateIdentityParam {
    //             name: sample_key::NAME.to_string(),
    //             password: sample_key::PASSWORD.to_string(),
    //             password_hint: None,
    //             network: model::NETWORK_TESTNET.to_string(),
    //             seg_wit: None,
    //         };
    //         let ret = call_api("create_identity", param).unwrap();
    //         let create_result: CreateIdentityResult =
    //             CreateIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert!(create_result.ipfs_id.len() > 0);
    //         assert!(create_result.identifier.len() > 0);
    //         assert_eq!(create_result.wallets.len(), 1);
    //         let wallets = create_result.wallets.get(0).unwrap();
    //         assert_eq!(wallets.chain_type, "ETHEREUM");

    //         let param = CreateIdentityParam {
    //             name: sample_key::NAME.to_string(),
    //             password: sample_key::PASSWORD.to_string(),
    //             password_hint: None,
    //             network: model::NETWORK_MAINNET.to_string(),
    //             seg_wit: None,
    //         };
    //         let ret = call_api("create_identity", param).unwrap();
    //         let create_result: CreateIdentityResult =
    //             CreateIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert!(create_result.ipfs_id.len() > 0);
    //         assert!(create_result.identifier.len() > 0);

    //         let ret_bytes = call_api("get_current_identity", ()).unwrap();
    //         let ret: GetCurrentIdentityResult =
    //             GetCurrentIdentityResult::decode(ret_bytes.as_slice()).unwrap();
    //         assert_eq!(ret.wallets.len(), 1);
    //         let wallet = ret.wallets.get(0).unwrap();
    //         assert_eq!(
    //             wallet.metadata.clone().unwrap().chain_type,
    //             constants::CHAIN_TYPE_ETHEREUM
    //         )
    //     })
    // }

    // #[test]
    // pub fn test_recover_identity_on_testnet() {
    //     run_test(|| {
    //         let param = RecoverIdentityParam {
    //             name: sample_key::NAME.to_string(),
    //             mnemonic: sample_key::MNEMONIC.to_string(),
    //             password: sample_key::PASSWORD.to_string(),
    //             password_hint: Some(sample_key::PASSWORD_HINT.to_string()),
    //             network: model::NETWORK_TESTNET.to_string(),
    //             seg_wit: None,
    //         };
    //         let ret = call_api("recover_identity", param).unwrap();
    //         let recover_result: RecoverIdentityResult =
    //             RecoverIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert_eq!(
    //             recover_result.ipfs_id,
    //             "QmSTTidyfa4np9ak9BZP38atuzkCHy4K59oif23f4dNAGU"
    //         );
    //         assert_eq!(
    //             recover_result.identifier,
    //             "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg"
    //         );

    //         let wallet = recover_result.wallets.get(0).unwrap();
    //         assert_eq!(wallet.chain_type, constants::CHAIN_TYPE_ETHEREUM);
    //         assert_eq!(wallet.address, "6031564e7b2f5cc33737807b2e58daff870b590b");
    //     })
    // }

    // #[test]
    // pub fn test_export_identity() {
    //     run_test(|| {
    //         let param = RecoverIdentityParam {
    //             name: sample_key::NAME.to_string(),
    //             mnemonic: MNEMONIC.to_string(),
    //             password: sample_key::PASSWORD.to_string(),
    //             password_hint: Some(sample_key::PASSWORD_HINT.to_string()),
    //             network: model::NETWORK_TESTNET.to_string(),
    //             seg_wit: None,
    //         };
    //         let ret = call_api("recover_identity", param).unwrap();
    //         let recover_result: RecoverIdentityResult =
    //             RecoverIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert!(recover_result.ipfs_id.len() > 0);
    //         assert!(recover_result.identifier.len() > 0);

    //         let param = ExportIdentityParam {
    //             identifier: recover_result.identifier.to_owned(),
    //             password: sample_key::PASSWORD.to_string(),
    //         };
    //         let ret = call_api("export_identity", param).unwrap();
    //         let export_result: ExportIdentityResult =
    //             ExportIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert_eq!(export_result.mnemonic, MNEMONIC);
    //         assert_eq!(recover_result.identifier, export_result.identifier);
    //     })
    // }

    // #[test]
    // pub fn test_delete_identity() {
    //     run_test(|| {
    //         let param = CreateIdentityParam {
    //             name: sample_key::NAME.to_string(),
    //             password: sample_key::PASSWORD.to_string(),
    //             password_hint: Some(sample_key::PASSWORD_HINT.to_string()),
    //             network: model::NETWORK_TESTNET.to_string(),
    //             seg_wit: None,
    //         };
    //         let ret = call_api("create_identity", param).unwrap();
    //         let create_result: CreateIdentityResult =
    //             CreateIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert!(create_result.ipfs_id.len() > 0);
    //         assert!(create_result.identifier.len() > 0);

    //         let remove_identity_param = RemoveIdentityParam {
    //             identifier: create_result.identifier.to_owned(),
    //             password: sample_key::PASSWORD.to_string(),
    //         };
    //         let ret = call_api("remove_identity", remove_identity_param).unwrap();
    //         let remove_result: RemoveIdentityResult =
    //             RemoveIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert_eq!(remove_result.identifier, create_result.identifier);
    //     })
    // }

    #[test]
    pub fn test_sign_ethereum_legacy_tx() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);

            //legacy transaction
            let eth_tx_input = EthTxInput {
                nonce: "8".to_string(),
                gas_price: "20000000008".to_string(),
                gas_limit: "189000".to_string(),
                to: "0x3535353535353535353535353535353535353535".to_string(),
                value: "512".to_string(),
                data: "".to_string(),
                chain_id: "1".to_string(),
                tx_type: "".to_string(),
                max_fee_per_gas: "".to_string(),
                max_priority_fee_per_gas: "".to_string(),
                access_list: vec![],
            };
            let input_value = encode_message(eth_tx_input).unwrap();
            let param = SignParam {
                id: wallet.id.to_string(),
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
                key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
            };
            let ret = call_api("sign_tx", param).unwrap();
            let output: EthTxOutput = EthTxOutput::decode(ret.as_slice()).unwrap();
            assert_eq!(
                output.tx_hash,
                "0xa0a52398c499ccb09095148188eb027b463de3229f87bfebb8f944606047fd81"
            );
            assert_eq!(output.signature, "f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a06dfc00d1a38acf17137ca1524964ae7e596196703971c6a4d35ada8b09227305a061b8424f251f8724c335fc6df6088db863ee0ea05ebf68ca73a3622aafa19e94");
        })
    }

    #[test]
    pub fn test_sign_ethereum_eip1559_tx() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);

            //eip1559 transaction
            let eth_tx_input = EthTxInput {
                nonce: "8".to_string(),
                gas_price: "".to_string(),
                gas_limit: "4286".to_string(),
                to: "0x3535353535353535353535353535353535353535".to_string(),
                value: "3490361".to_string(),
                data: "0x200184c0486d5f082a27".to_string(),
                chain_id: "1".to_string(),
                tx_type: "02".to_string(),
                max_fee_per_gas: "1076634600920".to_string(),
                max_priority_fee_per_gas: "226".to_string(),
                access_list: vec![],
            };
            let input_value = encode_message(eth_tx_input).unwrap();
            let param = SignParam {
                id: wallet.id.to_string(),
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
                key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
            };
            let ret = call_api("sign_tx", param).unwrap();
            let output: EthTxOutput = EthTxOutput::decode(ret.as_slice()).unwrap();
            assert_eq!(
                output.tx_hash,
                "0x9a427f295369171f686d83a05b92d8849b822f1fa1c9ccb853e81de545f4625b"
            );
            assert_eq!(output.signature, "02f875010881e285faac6c45d88210be943535353535353535353535353535353535353535833542398a200184c0486d5f082a27c001a0602501c9cfedf145810f9b54558de6cf866a89b7a65890ccde19dd6cec1fe32ca02769f3382ee526a372241238922da39f6283a9613215fd98c8ce37a0d03fa3bb");
        })
    }

    #[test]
    pub fn test_sign_ethereum_eip1559_tx2() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let wallet = import_and_derive(derivation);
            //eip1559 transaction
            let mut access_list = vec![];
            access_list.push(AccessList {
                address: "0x019fda53b3198867b8aae65320c9c55d74de1938".to_string(),
                storage_keys: vec![],
            });
            access_list.push(AccessList {
                address: "0x1b976cdbc43cfcbeaad2623c95523981ea1e664a".to_string(),
                storage_keys: vec![
                    "0xd259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2"
                        .to_string(),
                ],
            });
            access_list.push(AccessList {
                address: "0xf1946eba70f89687d67493d8106f56c90ecba943".to_string(),
                storage_keys: vec![
                    "0xb3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9"
                        .to_string(),
                    "0x6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82"
                        .to_string(),
                    "0x0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064"
                        .to_string(),
                ],
            });
            let eth_tx_input = EthTxInput {
                nonce: "8".to_string(),
                gas_price: "".to_string(),
                gas_limit: "4286".to_string(),
                to: "0x3535353535353535353535353535353535353535".to_string(),
                value: "3490361".to_string(),
                data: "0x200184c0486d5f082a27".to_string(),
                chain_id: "1".to_string(),
                tx_type: "02".to_string(),
                max_fee_per_gas: "1076634600920".to_string(),
                max_priority_fee_per_gas: "226".to_string(),
                access_list,
            };
            let input_value = encode_message(eth_tx_input).unwrap();
            let param = SignParam {
                id: wallet.id.to_string(),
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                curve: "SECP256k1".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
                key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
            };
            let ret = call_api("sign_tx", param).unwrap();
            let output: EthTxOutput = EthTxOutput::decode(ret.as_slice()).unwrap();
            assert_eq!(
                output.tx_hash,
                "0x2c20edff7e496c1f8d8370fc3d70f3f02b4c63008bb2586d507ddb88d68cea7d"
            );
            assert_eq!(output.signature, "02f90141010881e285faac6c45d88210be943535353535353535353535353535353535353535833542398a200184c0486d5f082a27f8cbd694019fda53b3198867b8aae65320c9c55d74de1938c0f7941b976cdbc43cfcbeaad2623c95523981ea1e664ae1a0d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2f87a94f1946eba70f89687d67493d8106f56c90ecba943f863a0b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9a06a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82a00c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb206480a0d95cb4d82912b2fed0510dd44cce5c0b177af6e7ed991f1dbe5b8e34303bf84ca04e0896caf07d9644e2728d919a84f7af46cb2421a0ce7bb814cce782d921e672");
        })
    }

    // #[test]
    // pub fn test_eth_ec_sign() {
    //     run_test(|| {
    //         let param = RecoverIdentityParam {
    //             name: sample_key::NAME.to_string(),
    //             mnemonic: MNEMONIC.to_string(),
    //             password: sample_key::PASSWORD.to_string(),
    //             password_hint: Some(sample_key::PASSWORD_HINT.to_string()),
    //             network: model::NETWORK_TESTNET.to_string(),
    //             seg_wit: None,
    //         };
    //         let ret = call_api("recover_identity", param).unwrap();
    //         let recover_result: RecoverIdentityResult =
    //             RecoverIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert!(recover_result.ipfs_id.len() > 0);
    //         assert!(recover_result.identifier.len() > 0);
    //         let eth_message_input = EthMessageInput {
    //             message: "Hello imToken".to_string(),
    //             is_hex: None,
    //         };
    //         let input_value = encode_message(eth_message_input).unwrap();
    //         let param = SignParam {
    //             id: recover_result.wallets.get(0).unwrap().id.clone(),
    //             chain_type: "ETHEREUM".to_string(),
    //             address: recover_result.wallets.get(0).unwrap().address.clone(),
    //             input: Some(::prost_types::Any {
    //                 type_url: "imtoken".to_string(),
    //                 value: input_value,
    //             }),
    //             key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
    //         };
    //         let ret = call_api("eth_ec_sign", param).unwrap();
    //         let output: EthMessageOutput = EthMessageOutput::decode(ret.as_slice()).unwrap();
    //         assert_eq!(output.signature.to_owned(), "0x509afc633572c8f1885ec217cf1a42fb87a2c341217dbfcc21417e2dce357c0b41116412d1dd51af86ed25920ce6b5648d80d77bbbba8c79d68476bdffd773a31b");

    //         let recover_input = EthRecoverAddressInput {
    //             message: "Hello imToken".to_string(),
    //             signature: output.signature.to_owned(),
    //             is_hex: None,
    //         };
    //         let ret = call_api("eth_recover_address", recover_input).unwrap();
    //         let recover_output: EthRecoverAddressOutput =
    //             EthRecoverAddressOutput::decode(ret.as_slice()).unwrap();
    //         assert_eq!(
    //             recover_output.address,
    //             "6031564e7b2f5cc33737807b2e58daff870b590b"
    //         );

    //         let recover_input = EthRecoverAddressInput {
    //             message: hex::encode("Hello imToken".as_bytes()),
    //             signature: output.signature,
    //             is_hex: Some(true),
    //         };
    //         let ret = call_api("eth_recover_address", recover_input).unwrap();
    //         let recover_output: EthRecoverAddressOutput =
    //             EthRecoverAddressOutput::decode(ret.as_slice()).unwrap();
    //         assert_eq!(
    //             recover_output.address,
    //             "6031564e7b2f5cc33737807b2e58daff870b590b"
    //         );
    //     })
    // }

    // #[test]
    // pub fn test_eth_keystore_import() {
    //     run_test(|| {
    //         let param = CreateIdentityParam {
    //             name: sample_key::NAME.to_string(),
    //             password: sample_key::PASSWORD.to_string(),
    //             password_hint: Some(sample_key::PASSWORD_HINT.to_string()),
    //             network: model::NETWORK_TESTNET.to_string(),
    //             seg_wit: None,
    //         };
    //         let ret = call_api("create_identity", param).unwrap();
    //         let create_result: CreateIdentityResult =
    //             CreateIdentityResult::decode(ret.as_slice()).unwrap();
    //         assert!(create_result.ipfs_id.len() > 0);
    //         assert!(create_result.identifier.len() > 0);

    //         // let fixtures = r#"{"address":"6344e16b7733e5211a6b8b5ac1c5628b06d20560",
    //         //     "id":"7abda3f2-fa83-415f-a000-6b8af5b8f05a",
    //         //     "crypto":{
    //         //         "ciphertext":"b28ad9edbeb57f89d32476c2f1415cb328276c573d14a4096faea6588a6931de",
    //         //         "cipherparams":{"iv":"647980eb665ea204e97c5c829f2b4aba"},
    //         //         "kdf":"scrypt",
    //         //         "kdfparams":{"r":8,"p":1,"n":8192,"dklen":32,"salt":"47b199e0082bf2a8fc7ae724f272e7daf2c62a5dc0d01da160d6c6411d2a49ea"},
    //         //         "mac":"a0cf4479d4e46fbc228bc9f7d10786a4501f36dfef591c316d8503f0e450f242",
    //         //         "cipher":"aes-128-ctr"
    //         //     },
    //         //     "version":3}"#.to_string();
    //         let keystore = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"eccde5515c1f9c833ee76ae3c354d1a2"},"ciphertext":"dda14dd1946c89ca85425f588eb32c545061bd022a9e873aa021de64b6f3b2d5","kdf":"pbkdf2","kdfparams":{"c":10240,"dklen":32,"prf":"hmac-sha256","salt":"3d327145c38932079d5400443fd612fe3e685ae13355d2897a78ea58ab8abda8"},"mac":"9e65da279df5d067c6fa9c4e7a689634885142d2106e7ef592cdb973dc1a22e3"},"id":"dea8739a-bd34-401b-9aaf-a92c1a7c381c","version":3,"address":"436ee8da3d1185a55f183d6e2363bad5aad36a13"}"#.to_string();
    //         let param = V3KeystoreImportInput {
    //             keystore,
    //             password: "abcd1234".to_string(),
    //             overwrite: true,
    //             name: "ETH".to_string(),
    //             chain_type: "ETHEREUM".to_string(),
    //             source: "KEYSTORE".to_string(),
    //         };

    //         let ret = call_api("eth_keystore_import", param).unwrap();
    //         let import_result: WalletResult = WalletResult::decode(ret.as_slice()).unwrap();
    //         println!("{}", import_result.id);
    //         // assert_eq!(import_result.id, "7abda3f2-fa83-415f-a000-6b8af5b8f05a");
    //         let param = V3KeystoreExportInput {
    //             password: "abcd1234".to_string(),
    //             id: import_result.id,
    //         };
    //         let ret = call_api("eth_keystore_export", param).unwrap();
    //         let export_result = V3KeystoreExportOutput::decode(ret.as_slice()).unwrap();
    //         println!("{}", export_result.json);
    //     })
    // }

    // #[test]
    // fn test_encrypt_data_to_ipfs() {
    //     todo!()
    // }

    // #[test]
    // fn test_decrypt_data_from_ipfs() {
    //     todo!()
    // }

    // #[test]
    // fn test_sign_authentication_message() {
    //     todo!()
    // }
}
