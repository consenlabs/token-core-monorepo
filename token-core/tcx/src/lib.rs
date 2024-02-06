#![feature(more_qualified_paths)]
#![feature(test)]

use std::ffi::{CStr, CString};

use std::os::raw::c_char;

use anyhow::anyhow;
use handler::{backup, sign_bls_to_execution_change};
use prost::Message;

pub mod api;

use crate::api::{GeneralResult, TcxAction};

pub mod error_handling;
pub mod handler;
pub mod migration;
use anyhow::Error;
use std::result;

use crate::error_handling::{landingpad, LAST_ERROR};
use crate::handler::{
    create_keystore, decrypt_data_from_ipfs, delete_keystore, derive_accounts, derive_sub_accounts,
    encode_message, encrypt_data_to_ipfs, exists_json, exists_mnemonic, exists_private_key,
    export_json, export_mnemonic, export_private_key, get_derived_key, get_extended_public_keys,
    get_public_keys, import_json, import_mnemonic, import_private_key, mnemonic_to_public,
    sign_authentication_message, sign_hashes, sign_message, sign_tx, unlock_then_crash,
    verify_password,
};
use crate::migration::{migrate_keystore, scan_legacy_keystores};

mod filemanager;
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
#[no_mangle]
pub unsafe extern "C" fn free_const_string(s: *const c_char) {
    if s.is_null() {
        return;
    }
    let _ = CStr::from_ptr(s);
}

/// # Safety
///
/// dispatch protobuf rpc call
#[allow(deprecated)]
#[no_mangle]
pub unsafe extern "C" fn call_tcx_api(hex_str: *const c_char) -> *const c_char {
    let hex_c_str = CStr::from_ptr(hex_str);
    let hex_str = hex_c_str.to_str().expect("parse_arguments to_str");

    let data = Vec::from_hex(hex_str).expect("parse_arguments hex decode");
    let action: TcxAction = TcxAction::decode(data.as_slice()).expect("decode tcx api");
    let reply: Result<Vec<u8>> = match action.method.to_lowercase().as_str() {
        "init_token_core_x" => landingpad(|| {
            handler::init_token_core_x(&action.param.unwrap().value).unwrap();
            Ok(vec![])
        }),
        "scan_legacy_keystores" => landingpad(|| {
            let ret = scan_legacy_keystores()?;
            encode_message(ret)
        }),
        "create_keystore" => landingpad(|| create_keystore(&action.param.unwrap().value)),
        "import_mnemonic" => landingpad(|| import_mnemonic(&action.param.unwrap().value)),
        "export_mnemonic" => landingpad(|| export_mnemonic(&action.param.unwrap().value)),
        "derive_accounts" => landingpad(|| derive_accounts(&action.param.unwrap().value)),
        "import_private_key" => landingpad(|| import_private_key(&action.param.unwrap().value)),
        "export_private_key" => landingpad(|| export_private_key(&action.param.unwrap().value)),
        "verify_password" => landingpad(|| verify_password(&action.param.unwrap().value)),
        "delete_keystore" => landingpad(|| delete_keystore(&action.param.unwrap().value)),
        "exists_mnemonic" => landingpad(|| exists_mnemonic(&action.param.unwrap().value)),
        "exists_private_key" => landingpad(|| exists_private_key(&action.param.unwrap().value)),
        "derive_sub_accounts" => landingpad(|| derive_sub_accounts(&action.param.unwrap().value)),
        "sign_tx" => landingpad(|| sign_tx(&action.param.unwrap().value)),
        "sign_msg" => landingpad(|| sign_message(&action.param.unwrap().value)),
        "exists_json" => landingpad(|| exists_json(&action.param.unwrap().value)),
        "import_json" => landingpad(|| import_json(&action.param.unwrap().value)),
        "export_json" => landingpad(|| export_json(&action.param.unwrap().value)),
        "backup" => landingpad(|| backup(&action.param.unwrap().value)),

        // !!! WARNING !!! used for `cache_dk` feature
        "get_derived_key" => landingpad(|| get_derived_key(&action.param.unwrap().value)),
        // !!! WARNING !!! used for test only
        "unlock_then_crash" => landingpad(|| unlock_then_crash(&action.param.unwrap().value)),

        "encrypt_data_to_ipfs" => landingpad(|| encrypt_data_to_ipfs(&action.param.unwrap().value)),
        "decrypt_data_from_ipfs" => {
            landingpad(|| decrypt_data_from_ipfs(&action.param.unwrap().value))
        }
        "sign_authentication_message" => {
            landingpad(|| sign_authentication_message(&action.param.unwrap().value))
        }
        "migrate_keystore" => landingpad(|| migrate_keystore(&action.param.unwrap().value)),

        "get_extended_public_keys" => {
            landingpad(|| get_extended_public_keys(&action.param.unwrap().value))
        }
        "get_public_keys" => landingpad(|| get_public_keys(&action.param.unwrap().value)),
        "sign_hashes" => landingpad(|| sign_hashes(&action.param.unwrap().value)),
        "mnemonic_to_public" => landingpad(|| mnemonic_to_public(&action.param.unwrap().value)),
        "sign_bls_to_execution_change" => {
            landingpad(|| sign_bls_to_execution_change(&action.param.unwrap().value))
        }
        _ => landingpad(|| Err(anyhow!("unsupported_method"))),
    };
    match reply {
        Ok(reply) => {
            let ret_str = reply.to_hex();
            CString::new(ret_str).unwrap().into_raw()
        }
        _ => CString::new("").unwrap().into_raw(),
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
extern crate test;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::derive_accounts_param::Derivation;
    use crate::api::sign_hashes_param::DataToSign;
    use crate::filemanager::KEYSTORE_MAP;
    use api::sign_param::Key;
    use error_handling::Result;
    use serial_test::serial;
    use std::ffi::{CStr, CString};
    use std::fs::remove_file;
    use std::os::raw::c_char;
    use std::panic;
    use std::path::Path;
    use tcx_atom::transaction::{AtomTxInput, AtomTxOutput};
    use tcx_eth2::transaction::{SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult};
    use tcx_keystore::keystore::IdentityNetwork;
    use test::Bencher;

    use crate::api::{
        export_private_key_param, migrate_keystore_param, sign_param, BackupResult,
        CreateKeystoreParam, DecryptDataFromIpfsParam, DecryptDataFromIpfsResult,
        DeriveAccountsParam, DeriveAccountsResult, DeriveSubAccountsParam, DeriveSubAccountsResult,
        DerivedKeyResult, EncryptDataToIpfsParam, EncryptDataToIpfsResult, ExistsJsonParam,
        ExistsKeystoreResult, ExistsMnemonicParam, ExistsPrivateKeyParam, ExportJsonParam,
        ExportJsonResult, ExportMnemonicResult, ExportPrivateKeyParam, ExportPrivateKeyResult,
        GeneralResult, GetExtendedPublicKeysParam, GetExtendedPublicKeysResult, GetPublicKeysParam,
        GetPublicKeysResult, ImportJsonParam, ImportMnemonicParam, ImportPrivateKeyParam,
        ImportPrivateKeyResult, InitTokenCoreXParam, KeystoreResult, MigrateKeystoreParam,
        MigrateKeystoreResult, MnemonicToPublicKeyParam, MnemonicToPublicKeyResult,
        PublicKeyDerivation, SignAuthenticationMessageParam, SignAuthenticationMessageResult,
        SignHashesParam, SignHashesResult, SignParam, WalletKeyParam,
    };
    use crate::handler::import_mnemonic;
    use crate::handler::{encode_message, import_private_key};
    use prost::Message;
    use tcx_constants::{sample_key, CurveType, TEST_PRIVATE_KEY, TEST_WIF};
    use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::Keystore;

    use std::fs;
    use tcx_btc_kin::transaction::BtcKinTxInput;

    use sp_core::ByteArray;
    use sp_runtime::traits::Verify;
    use tcx_btc_kin::Utxo;
    use tcx_ckb::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};

    use tcx_eth::api::{AccessList, EthMessageInput, EthMessageOutput, EthTxInput, EthTxOutput};
    use tcx_filecoin::{SignedMessage, UnsignedMessage};
    use tcx_substrate::{SubstrateKeystore, SubstrateRawTxIn, SubstrateTxOut};
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

        init_token_core_x("/tmp/imtoken");
    }

    fn teardown() {
        fs::remove_dir_all("/tmp/imtoken").expect("remove test directory");
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

    fn import_default_wallet() -> KeystoreResult {
        let param = ImportMnemonicParam {
            mnemonic: TEST_MNEMONIC.to_string(),
            password: TEST_PASSWORD.to_string(),
            network: "TESTNET".to_string(),
            name: "test-wallet".to_string(),
            password_hint: "imtoken".to_string(),
            overwrite: true,
        };
        let ret = import_mnemonic(&encode_message(param).unwrap()).unwrap();
        KeystoreResult::decode(ret.as_slice()).unwrap()
    }

    fn import_default_pk_store() -> ImportPrivateKeyResult {
        let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
            private_key: "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB".to_string(),
            password: TEST_PASSWORD.to_string(),
            name: "import_default_pk_store".to_string(),
            password_hint: "".to_string(),
            network: "".to_string(),
            overwrite: true,
        };

        let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
        ImportPrivateKeyResult::decode(ret.as_slice()).unwrap()
    }

    fn import_filecoin_pk_store() -> KeystoreResult {
        let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
            private_key: "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a"
                .to_string(),
            password: TEST_PASSWORD.to_string(),
            name: "import_filecoin_pk_store".to_string(),
            password_hint: "".to_string(),
            network: "".to_string(),
            overwrite: true,
        };

        let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
        KeystoreResult::decode(ret.as_slice()).unwrap()
    }

    fn import_and_derive(derivation: Derivation) -> (KeystoreResult, DeriveAccountsResult) {
        let wallet = import_default_wallet();

        let param = DeriveAccountsParam {
            id: wallet.id.to_string(),
            key: Some(crate::api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            derivations: vec![derivation],
        };

        let ret = call_api("derive_accounts", param).unwrap();
        let accounts: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

        (wallet, accounts)
    }

    fn import_pk_and_derive(
        derivation: Derivation,
    ) -> (ImportPrivateKeyResult, DeriveAccountsResult) {
        let wallet = import_default_pk_store();

        let param = DeriveAccountsParam {
            id: wallet.id.to_string(),
            key: Some(crate::api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            derivations: vec![derivation],
        };

        let ret = call_api("derive_accounts", param).unwrap();
        let accounts: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

        (wallet, accounts)
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
        let param_hex = param_bytes.to_hex();
        let ret_hex = unsafe { _to_str(call_tcx_api(_to_c_char(&param_hex))) };
        let err = unsafe { _to_str(get_last_err_message()) };
        if !err.is_empty() {
            let err_bytes = Vec::from_hex(err).unwrap();
            let err_ret: GeneralResult = GeneralResult::decode(err_bytes.as_slice()).unwrap();
            Err(anyhow!("{}", err_ret.error))
        } else {
            Ok(Vec::from_hex(ret_hex).unwrap())
        }
    }

    fn init_token_core_x(file_dir: &str) {
        let param = InitTokenCoreXParam {
            file_dir: file_dir.to_string(),
            xpub_common_key: "B888D25EC8C12BD5043777B1AC49F872".to_string(),
            xpub_common_iv: "9C0C30889CBCC5E01AB5B2BB88715799".to_string(),
            is_debug: true,
        };
        let response = call_api("init_token_core_x", param);
        assert!(response.is_ok());
    }

    #[test]
    #[serial]
    #[ignore = "for debug"]
    fn test_call_tcx_api() {
        run_test(|| {
            let bytes = &Vec::<u8>::from_hex_auto("0a0f6465726976655f6163636f756e747312770a176170692e4465726976654163636f756e7473506172616d125c0a2430313831653533662d346566642d343262352d623430302d39333134656239376339373412083132333435363738222a0a08455448455245554d12106d2f3434272f3630272f30272f302f302a01313209736563703235366b31").unwrap();
            let action = TcxAction::decode(bytes.as_slice()).unwrap();
            dbg!(&action);
            let param =
                DeriveAccountsParam::decode(action.param.unwrap().value.as_slice()).unwrap();
            let _wallet = import_default_wallet();
            dbg!(&param);
            // call_tcx_api(bytes.to_hex())
            assert!(true);
        });
    }

    #[test]
    #[serial]
    pub fn test_create_keystore() {
        run_test(|| {
            let param = CreateKeystoreParam {
                password: TEST_PASSWORD.to_string(),
                password_hint: "".to_string(),
                name: "aaa".to_string(),
                network: IdentityNetwork::Mainnet.to_string(),
            };

            let ret = call_api("create_keystore", param).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

            assert_eq!(import_result.name, "aaa");
            assert_eq!(import_result.source, "NEW_MNEMONIC");
            assert!(!import_result.identifier.is_empty());
            assert!(!import_result.ipfs_id.is_empty());
            assert!(!import_result.source_fingerprint.is_empty());

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_import_mnemonic() {
        run_test(|| {
            let import_result: KeystoreResult = import_default_wallet();
            assert_eq!(import_result.source, "MNEMONIC");
            assert_eq!(
                import_result.source_fingerprint,
                "0x1468dba9c246fe22183c056540ab4d8b04553217"
            );
            assert_eq!(
                import_result.identifier,
                "im14x5GXsdME4JsrHYe2wvznqRz4cUhx2pA4HPf"
            );
            assert_eq!(
                import_result.ipfs_id,
                "QmWqwovhrZBMmo32BzY83ZMEBQaP7YRMqXNmMc8mgrpzs6"
            );

            let derivation = Derivation {
                chain_type: "BITCOINCASH".to_string(),
                path: "m/44'/145'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            };
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };

            let ret = call_api("derive_accounts", param).unwrap();
            let result: DeriveAccountsResult =
                DeriveAccountsResult::decode(ret.as_slice()).unwrap();
            let account = result.accounts.first().unwrap();
            assert_eq!(account.chain_type, "BITCOINCASH");
            assert_eq!(
                account.address,
                "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r"
            );
            assert_eq!(
                account.extended_public_key,
                "xpub6Bmkv3mmRZZWoFSBdj9vDMqR2PCPSP6DEj8u3bBuv44g3Ncnro6cPVqZAw6wTEcxHQuodkuJG4EmAinqrrRXGsN3HHnRRMtAvzfYTiBATV1"
            );
            assert_eq!(
                account.encrypted_extended_public_key,
                "wAKUeR6fOGFL+vi50V+MdVSH58gLy8Jx7zSxywz0tN++l2E0UNG7zv+R1FVgnrqU6d0wl699Q/I7O618UxS7gnpFxkGuK0sID4fi7pGf9aivFxuKy/7AJJ6kOmXH1Rz6FCS6b8W7NKlzgbcZpJmDsQ=="
            );

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_import_mnemonic_invalid_params() {
        run_test(|| {
            let invalid_mnemonics = vec![
                "inject kidney empty canal shadow pact comfort wife crush horse",
                "inject kidney empty canal shadow pact comfort wife crush horse wife wife",
                "inject kidney empty canal shadow pact comfort wife crush horse hello",
            ];
            for mn in invalid_mnemonics {
                let param = ImportMnemonicParam {
                    mnemonic: mn.to_string(),
                    password: TEST_PASSWORD.to_string(),
                    network: "TESTNET".to_string(),
                    name: "test-wallet".to_string(),
                    password_hint: "imtoken".to_string(),
                    overwrite: true,
                };

                let ret = call_api("import_mnemonic", param);
                assert!(ret.is_err());
            }
        })
    }

    #[test]
    #[serial]
    pub fn test_import_mnemonic_ltc() {
        run_test(|| {
            let import_result: KeystoreResult = import_default_wallet();

            let derivation = Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/44'/1'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };

            let ret = call_api("derive_accounts", param).unwrap();
            let result: DeriveAccountsResult =
                DeriveAccountsResult::decode(ret.as_slice()).unwrap();
            assert_eq!(result.accounts.first().unwrap().chain_type, "LITECOIN");
            assert_eq!(
                result.accounts.first().unwrap().address,
                "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN"
            );

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_export_mnemonic() {
        run_test(|| {
            let wallet = import_default_wallet();

            let param = WalletKeyParam {
                id: wallet.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let ret = call_api("export_mnemonic", param).unwrap();
            let result: ExportMnemonicResult =
                ExportMnemonicResult::decode(ret.as_slice()).unwrap();

            assert_eq!(result.mnemonic, TEST_MNEMONIC);

            let wallet = import_default_pk_store();

            let param = WalletKeyParam {
                id: wallet.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
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
    #[serial]
    pub fn test_derive_accounts() {
        run_test(|| {
            let param = ImportMnemonicParam {
                mnemonic: OTHER_MNEMONIC.to_string(),
                password: TEST_PASSWORD.to_string(),
                network: "TESTNET".to_string(),
                name: "test-wallet".to_string(),
                password_hint: "imtoken".to_string(),
                overwrite: true,
            };
            let ret = call_api("import_mnemonic", param).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

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
                    chain_type: "KUSAMA".to_string(),
                    path: "//kusama//imToken/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "POLKADOT".to_string(),
                    path: "//polkadot//imToken/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
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
                    chain_type: "FILECOIN".to_string(),
                    path: "m/12381/461/0/0".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "bls12-381".to_string(),
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
                    chain_type: "BITCOIN".to_string(),
                    path: "m/84'/0'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "VERSION_0".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "m/86'/0'/0'/0/0".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "VERSION_1".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "TEZOS".to_string(),
                    path: "m/44'/1729'/0'/0'".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "ed25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];

            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
            let derived_accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(17, derived_accounts.accounts.len());
            assert_eq!(
                "LQ3JqCohgLQ3x1CJXYERnJTy1ySaqr1E32",
                derived_accounts.accounts[0].address
            );
            assert_eq!("/EhDRyPFcj1UGx8i+WiJSIeBSyaN0pX7Oq3wXqwO5M9T1aRhfLpsNPGAPLf07K+p+B0OdQW1ogVbDQCWkIwVXZLPY+njp9LjXaICiWGEeidR1TwBZSwOMRKE68wJWH/7puxYfY/Rq1+d2GFv6NxSCw==", derived_accounts.accounts[0].encrypted_extended_public_key);
            assert_eq!("xpub6BwqzNhMbFpgegP8WGBzFmm7aUsrDQtuuRdT3J3nDhDGnbPCER8qGghKJUCJNhjn2wyZVwAC6mwLNPu9xQpeQenqnzzVj2X7tnDLAM58fRn", derived_accounts.accounts[0].extended_public_key);

            assert_eq!(
                "MQUu6P7wsLQZfVZMuFWB7UXiheuVTM7RYF",
                derived_accounts.accounts[1].address
            );
            //            assert_eq!("5wlT8R+syH37UjMSJXOW3v96ORRykslaBOX7wa+aEt4jbshR9ljP5u+DDskzV5hAKuSBuIPftafEA/k4YQ4Zh2mByl0EE/5jdZI/ZbE0a2zsIiU9BIGuhzA/f+vvQuDJqOHofDd8z0qDesuqxLKv4A==", derived_accounts.accounts[1].encrypted_extended_public_key);
            assert_eq!("A5LUzJcPB4r54wqr8EjFh9fe0L87spIN9KJKtzHV6QJXBH6GEAiYT57uftpJITx613HdIXXzi8VJ30TmG8erBF30oD1DnbDmGmDo4sdRTdQSsp9NuprhZ3Y3PR9+xzdc2tKDblRL5dLZswaPxCOQcw==", derived_accounts.accounts[1].encrypted_extended_public_key);

            assert_eq!(
                "mvdDMnRsqjqzvCyYyRXpvscmnU1FxodhkE",
                derived_accounts.accounts[2].address
            );
            assert_eq!("eZIL4e0a8qw18Pve92iLfehteHDA+kqjwv91aKE+2hNN3arkq20yY2Mx6q4WAowFv0QRfIi6QlrhafJKUpjiC469NNZagCSHLaECYliEwmwTgC97zXmVJDB6MJi79y+mznf8G7Few8+u6UfiXELN5g==", derived_accounts.accounts[2].encrypted_extended_public_key);

            assert_eq!(
                "TLZnqkrSNLUWNrZMug8u9b6pJ3XcTGbzDV",
                derived_accounts.accounts[3].address
            );
            assert_eq!("Sla41n5BdHqc1QmqA9DXjWNx13Fpq18u19jCaMbYbxClsPr7cr/gzXsbE+08wfNLuGgtVVY4/prpnv3/pdJ8KA/I/iOKvelKxuJgN9n2O5Q54CmObc0qJVZxcAQM0PbrKE9YJyGDkJNMLM+OmjEwjg==", derived_accounts.accounts[3].encrypted_extended_public_key);

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
            assert_eq!(
                "t3qnoxt4gpoyahbgmh2n2cvpeqoqa7jowlyxyuo3jgedp4gdyauhvcydd6var2d3i6yyrdhpqsixqxozp7b64a",
                derived_accounts.accounts[8].address
            );
            assert_eq!(
                "cosmos1m566v5rcklnac8vc0dftfu4lnvznhlu7d3f404",
                derived_accounts.accounts[9].address
            );

            assert_eq!("", derived_accounts.accounts[10].address);
            assert_eq!(
                "EOS7Nf9TU1vZaQQgZA3cELTHJf1nnDJ6xVvqHvVzbHehsgcjrzNkq",
                derived_accounts.accounts[10].public_key
            );
            assert_eq!(
                "0x37c6713aa848bCdeE372A620eEbCdcCBA55c695F",
                derived_accounts.accounts[11].address
            );
            assert_eq!(
                "1PHNSh4M6uLqJfiDWZRj4w2F2LXSaygVtE",
                derived_accounts.accounts[12].address
            );
            assert_eq!(
                "3CwQ11hx8yT6eGXqQJBFCRxZ8eCnLd9wZj",
                derived_accounts.accounts[13].address
            );
            assert_eq!(
                "bc1qk5ctv049qsavhh6ykygnm43mjuk5v26jd34qgq",
                derived_accounts.accounts[14].address
            );
            assert_eq!(
                "bc1phazpdjkaruvcqhaakmk56tvmqcd4kx5svvrjdrck5m7g3q2uadpszxypw0",
                derived_accounts.accounts[15].address
            );

            assert_eq!(
                "tz1YhnU6rUigVp6Jei1VJQHofGSbzGKphVmG",
                derived_accounts.accounts[16].address
            );

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_hd_store_derive_invalid_param() {
        run_test(|| {
            let import_result: KeystoreResult = import_default_wallet();

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
                let param = DeriveAccountsParam {
                    id: import_result.id.to_string(),
                    key: Some(crate::api::derive_accounts_param::Key::Password(
                        TEST_PASSWORD.to_owned(),
                    )),
                    derivations: vec![derivation],
                };
                let ret = call_api("derive_accounts", param);
                assert!(ret.is_err());
            }

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_import_private_key() {
        run_test(|| {
            let import_result = import_default_pk_store();
            assert_eq!(
                import_result.identifier,
                "im14x5UPbCXmU2HMQ8jfeKcCDrQYhDppRYaa5C6"
            );
            assert_eq!(
                import_result.ipfs_id,
                "QmczBPUeohPPaE8UnPiESyynPwffBqrn4RqrU6nPJw95VT"
            );
            assert_eq!(
                import_result.source_fingerprint,
                "0xe6cfaab9a59ba187f0a45db0b169c21bb48f09b3"
            );
            assert_eq!(import_result.source, "WIF");

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
                    chain_type: "ETHEREUM".to_string(),
                    path: "m/44'/60'/0'/0/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "COSMOS".to_string(),
                    path: "pk_not_need_path".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "EOS".to_string(),
                    path: "pk_not_need_path".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "pk_not_need_path".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "pk_not_need_path".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "pk_not_need_path".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "P2WPKH".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "pk_not_need_path".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "VERSION_0".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "pk_not_need_path".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "VERSION_1".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
            let derived_accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(13, derived_accounts.accounts.len());
            assert_eq!(
                "LgGNTHMkgETS7oQcoekvACJQcH355xECog",
                derived_accounts.accounts[0].address
            );
            assert_eq!("", derived_accounts.accounts[0].extended_public_key);

            assert_eq!(
                "MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW",
                derived_accounts.accounts[1].address
            );
            assert_eq!("", derived_accounts.accounts[1].extended_public_key);

            assert_eq!(
                "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6",
                derived_accounts.accounts[2].address
            );
            assert_eq!("", derived_accounts.accounts[2].extended_public_key);

            assert_eq!(
                "TXo4VDm8Qc5YBSjPhu8pMaxzTApSvLshWG",
                derived_accounts.accounts[3].address
            );
            assert_eq!("", derived_accounts.accounts[3].extended_public_key);

            assert_eq!(
                "ckt1qyqpavderq5jjxh6qhxeks4t706kglffkyassx7h5z",
                derived_accounts.accounts[4].address
            );

            assert_eq!(
                "0xef678007D18427E6022059Dbc264f27507CD1ffC",
                derived_accounts.accounts[5].address
            );

            assert_eq!(
                "cosmos1um864wd9nwsc0u9ytkctz6wzrw6g7zdnapqz35",
                derived_accounts.accounts[6].address
            );

            assert_eq!(
                "EOS5Vubes67f2xXCRDJXx5WJRsMBuf4gTfzukbqLnyjZQCyoPjPZu",
                derived_accounts.accounts[7].public_key
            );

            assert_eq!(
                "1N3RC53vbaDNrziTdWmctBEeQ4fo4quNpq",
                derived_accounts.accounts[8].address
            );

            assert_eq!(
                "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6",
                derived_accounts.accounts[9].address
            );

            assert_eq!(
                "3Js9bGaZSQCNLudeGRHL4NExVinc25RbuG",
                derived_accounts.accounts[10].address
            );

            assert_eq!(
                "bc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdntm7f4e",
                derived_accounts.accounts[11].address
            );

            assert_eq!(
                "bc1pqpae4d6594jj3yueluku5tlu7r6nqwm24xc8thk5g396s9e5anvq6x4n33",
                derived_accounts.accounts[12].address
            );

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
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
            let derived_accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(
                "LgGNTHMkgETS7oQcoekvACJQcH355xECog",
                derived_accounts.accounts[0].address
            );
            assert_eq!("", derived_accounts.accounts[0].extended_public_key);

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_tezos_import_private_key_export() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: "edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_tezos_import_private_key_export".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };

            let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

            let derivations = vec![Derivation {
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
            let derived_accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(
                "tz1QSHaKpTFhgHLbqinyYRjxD5sLcbfbzhxy",
                derived_accounts.accounts[0].address
            );

            let param: ExistsPrivateKeyParam = ExistsPrivateKeyParam {
                private_key: "edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH"
                    .to_string(),
            };

            let ret_bytes = call_api("exists_private_key", param).unwrap();
            let result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, import_result.id);

            let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_string(),
                )),
                chain_type: "TEZOS".to_string(),
                network: "MAINNET".to_string(),
                curve: "ed25519".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
            };
            let ret_bytes = call_api("export_private_key", param).unwrap();
            let export_result: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH",
                export_result.private_key
            );

            let param: GetPublicKeysParam = GetPublicKeysParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::get_public_keys_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![PublicKeyDerivation {
                    chain_type: "TEZOS".to_string(),
                    path: "".to_string(),
                    curve: CurveType::ED25519.as_str().to_string(),
                }],
            };
            let ret_bytes = call_api("get_public_keys", param).unwrap();
            let public_key_result: GetPublicKeysResult =
                GetPublicKeysResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "edpkvQtuhdZQmjdjVfaY9Kf4hHfrRJYugaJErkCGvV3ER1S7XWsrrj",
                public_key_result.public_keys[0]
            );
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_tezos_hd_private_key_import_export() {
        run_test(|| {
            let import_result = import_default_pk_store();

            let derivations = vec![Derivation {
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
            let derived_accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(
                "tz1RTCY2tQdBCWYacqmV18UYy5YMBdCgcpL1",
                derived_accounts.accounts[0].address
            );

            let export_param = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "TEZOS".to_string(),
                network: "".to_string(),
                curve: "secp256k1".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
            };
            let export_pk_bytes = call_api("export_private_key", export_param).unwrap();
            let export_pk: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(export_pk_bytes.as_slice()).unwrap();
            assert_eq!(
                export_pk.private_key,
                "edskRyQy6W7Vs3eDVZtqu3bsAEVPuFCWbsPKXpFn5uDmkbwDfyBA6Qx8tuD516GCCf92W57LeMgU6kdgefRGpE6H3w9VZYRxAG"
            );
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_filecoin_private_key_secp256k1_import() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f354a6754767776725a774c5061513758326d4b4c6a386e4478634e685a6b537667315564434a317866593d227d"
                    .to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_filecoin_import_private_key".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };

            let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

            let derivations = vec![Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
            let derived_accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();

            assert_eq!(1, derived_accounts.accounts.len());

            assert_eq!(
                "t1zerdvi3fx2lrcslsqdewpadzzm2hefpn6ixew3i",
                derived_accounts.accounts[0].address
            );

            let export_param = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "FILECOIN".to_string(),
                network: "".to_string(),
                curve: "secp256k1".to_string(),
                path: "".to_string(),
            };

            let export_pk_bytes = call_api("export_private_key", export_param).unwrap();
            let export_pk: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(export_pk_bytes.as_slice()).unwrap();
            assert_eq!(
                export_pk.private_key,
                "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f354a6754767776725a774c5061513758326d4b4c6a386e4478634e685a6b537667315564434a317866593d227d"
            );

            remove_created_wallet(&import_result.id);
        });
    }

    #[test]
    #[serial]
    pub fn test_filecoin_private_key_bls_import() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: "7b2254797065223a22626c73222c22507269766174654b6579223a2269376b4f2b7a78633651532b7637597967636d555968374d55595352657336616e6967694c684b463830383d227d"
                    .to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_filecoin_import_private_key".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };

            let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

            let derivations = vec![Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "bls12-381".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
            let derived_accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(1, derived_accounts.accounts.len());

            assert_eq!(
                "t3qdyntx5snnwgmjkp2ztd6tf6hhcmurxfj53zylrqyympwvzvbznx6vnvdqloate5eviphnzrkupno4wheesa",
                derived_accounts.accounts[0].address
            );

            let export_param = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "FILECOIN".to_string(),
                network: "".to_string(),
                curve: "bls12-381".to_string(),
                path: "".to_string(),
            };

            let export_pk_bytes = call_api("export_private_key", export_param).unwrap();
            let export_pk: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(export_pk_bytes.as_slice()).unwrap();
            assert_eq!(
                export_pk.private_key,
                "7b2254797065223a22626c73222c22507269766174654b6579223a2269376b4f2b7a78633651532b7637597967636d555968374d55595352657336616e6967694c684b463830383d227d"
            );

            remove_created_wallet(&import_result.id);
        });
    }

    #[test]
    #[serial]
    pub fn test_fil_bls_tezos_reimport() {
        run_test(|| {
            let hd_import_result = import_default_wallet();
            let test_case = vec![
                (
                    "TEZOS".to_string(),
                    "m/44'/1729'/0'/0'".to_string(),
                    "ed25519".to_string(),
                ),
                (
                    "FILECOIN".to_string(),
                    "m/2334/461/0/0".to_string(),
                    "bls12-381".to_string(),
                ),
            ];

            for case in test_case.iter() {
                let derivations = vec![Derivation {
                    chain_type: case.0.to_string(),
                    path: case.1.to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: case.2.to_string(),
                    bech32_prefix: "".to_string(),
                }];
                let param = DeriveAccountsParam {
                    id: hd_import_result.id.to_string(),
                    key: Some(crate::api::derive_accounts_param::Key::Password(
                        TEST_PASSWORD.to_owned(),
                    )),
                    derivations,
                };
                let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
                let derived_accounts: DeriveAccountsResult =
                    DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();

                let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                    id: hd_import_result.id.to_string(),
                    key: Some(export_private_key_param::Key::Password(
                        TEST_PASSWORD.to_string(),
                    )),
                    chain_type: case.0.to_string(),
                    network: "MAINNET".to_string(),
                    curve: case.2.to_string(),
                    path: case.1.to_string(),
                };
                let ret_bytes = call_api("export_private_key", param).unwrap();
                let export_result: ExportPrivateKeyResult =
                    ExportPrivateKeyResult::decode(ret_bytes.as_slice()).unwrap();

                let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                    private_key: export_result.private_key.to_string(),
                    password: TEST_PASSWORD.to_string(),
                    name: "reimport".to_string(),
                    password_hint: "".to_string(),
                    network: "".to_string(),
                    overwrite: true,
                };

                let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
                let pk_import_result: KeystoreResult =
                    KeystoreResult::decode(ret.as_slice()).unwrap();

                let derivations = vec![Derivation {
                    chain_type: case.0.to_string(),
                    path: case.1.to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: case.2.to_string(),
                    bech32_prefix: "".to_string(),
                }];
                let param = DeriveAccountsParam {
                    id: pk_import_result.id.to_string(),
                    key: Some(crate::api::derive_accounts_param::Key::Password(
                        TEST_PASSWORD.to_owned(),
                    )),
                    derivations,
                };
                let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
                let pk_derived_accounts: DeriveAccountsResult =
                    DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
                assert_eq!(
                    derived_accounts.accounts.first().unwrap().address,
                    pk_derived_accounts.accounts.first().unwrap().address
                );
            }
        });
    }

    #[test]
    #[serial]
    pub fn test_import_sr25519_private_key() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: "0x416c696365202020202020202020202020202020202020202020202020202020d172a74cda4c865912c32ba0a80a57ae69abae410e5ccb59dee84e2f4432db4f"
                    .to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_64bytes_import_private_key".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };

            let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
            let import_result: ImportPrivateKeyResult =
                ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();
            assert_eq!(
                "im14x5JEvG1gEwF9ukFv5EsVyQ47V3BegEA3hVa",
                import_result.identifier
            );

            let derivations = vec![Derivation {
                chain_type: "POLKADOT".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                bech32_prefix: "".to_string(),
            }];
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
            let derived_accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
            assert_eq!(1, derived_accounts.accounts.len());

            assert_eq!(
                "133smEABgtt8FRkZGrZfAzCV522bxo2y5FwVoTcSaY8z1nEq",
                derived_accounts.accounts[0].address
            );

            let export_param = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "POLKADOT".to_string(),
                network: "".to_string(),
                curve: "sr25519".to_string(),
                path: "".to_string(),
            };

            let export_pk_bytes = call_api("export_private_key", export_param).unwrap();
            let export_pk: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(export_pk_bytes.as_slice()).unwrap();
            assert_eq!(
                export_pk.private_key,
                "0x406c696365202020202020202020202020202020202020202020202020202020d172a74cda4c865912c32ba0a80a57ae69abae410e5ccb59dee84e2f4432db4f"
            );

            let export_param = ExportJsonParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "POLKADOT".to_string(),
                path: "".to_string(),
            };

            let export_pk_bytes = call_api("export_json", export_param).unwrap();
            let export_pk: ExportJsonResult =
                ExportJsonResult::decode(export_pk_bytes.as_slice()).unwrap();
            assert!(export_pk
                .json
                .contains("133smEABgtt8FRkZGrZfAzCV522bxo2y5FwVoTcSaY8z1nEq"));
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_private_key_store_export() {
        run_test(|| {
            let import_result = import_default_pk_store();
            let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "BITCOINCASH".to_string(),
                network: "MAINNET".to_string(),
                curve: "secp256k1".to_string(),
                path: "m/44'/0'/0'/0/0".to_string(),
            };
            let ret_bytes = call_api("export_private_key", param).unwrap();
            let export_result: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB",
                export_result.private_key
            );

            let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "BITCOINCASH".to_string(),
                network: "TESTNET".to_string(),
                curve: "secp256k1".to_string(),
                path: "m/44'/0'/0'/0/0".to_string(),
            };
            let ret_bytes = call_api("export_private_key", param).unwrap();
            let export_result: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "cT4fTJyLd5RmSZFHnkGmVCzXDKuJLbyTt7cy77ghTTCagzNdPH1j",
                export_result.private_key
            );

            let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "TRON".to_string(),
                network: "".to_string(),
                curve: "secp256k1".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
            };
            let ret_bytes = call_api("export_private_key", param).unwrap();
            let export_result: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "0xa392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
                export_result.private_key
            );
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
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
                    chain_type: "ETHEREUM".to_string(),
                    path: "".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "FILECOIN".to_string(),
                    path: "".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "NONE".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "P2WPKH".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "VERSION_0".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "BITCOIN".to_string(),
                    path: "".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "VERSION_1".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "EOS".to_string(),
                    path: "".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "secp256k1".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];
            let pks = vec![
                "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB",
                "cT4fTJyLd5RmSZFHnkGmVCzXDKuJLbyTt7cy77ghTTCagzNdPH1j",
                "0xa392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
                "0xa392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
                "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f354a6754767776725a774c5061513758326d4b4c6a386e4478634e685a6b537667315564434a317866593d227d",
                "cT4fTJyLd5RmSZFHnkGmVCzXDKuJLbyTt7cy77ghTTCagzNdPH1j",
                "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB",
                "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB",
                "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB",
                "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB",
                "5K4KoY2vWgb6jAh7D5rzM93NRwjo9RDQkHsdvrSeNbnfqpgVJKh",
            ];

            for idx in 0..pks.len() {
                let (import_result, acc_rsp) = import_pk_and_derive(derivations[idx].clone());
                let acc = acc_rsp.accounts.first().unwrap().clone();
                let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                    id: import_result.id.to_string(),
                    key: Some(crate::api::export_private_key_param::Key::Password(
                        TEST_PASSWORD.to_owned(),
                    )),
                    chain_type: acc.chain_type.to_string(),
                    network: derivations[idx].network.to_string(),
                    curve: "secp256k1".to_string(),
                    path: "".to_string(),
                };
                let ret_bytes = call_api("export_private_key", param).unwrap();
                let export_result: ExportPrivateKeyResult =
                    ExportPrivateKeyResult::decode(ret_bytes.as_slice()).unwrap();

                // test export as mainnet
                assert_eq!(pks[idx], export_result.private_key);
                remove_created_wallet(&import_result.id);
            }
        })
    }

    #[test]
    #[serial]
    pub fn test_export_private_key_from_hd_store() {
        run_test(|| {
            let pks = vec![
                "L39VXyorp19JfsEJfbD7Tfr4pBEX93RJuVXW7E13C51ZYAhUWbYa",
                "KyLGdagds7tY1vupT5Kf8C1Cc5wkzzWRK51e4vsh1svCSvYk4Abo",
                "cN4b1V3cicEexrYXiEhaWEdURyhZiVX6PzAZNFSzZaWfSNZG2cJX",
                "0xb2a3f2ad9ea57b03aae9584a50b36e8b8f9ddfdc1b5c2ca26f90a041fb28f260",
                "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a222f5059574777574e577a58614d5675437a613958502b314b4a695a4474696f4c76777863754268783041553d227d",
                "7b2254797065223a22626c73222c22507269766174654b6579223a226e763064516a49635965556341682f6a792b6d7a77656a306c4a75495447504238433938766576713046513d227d",
                "0xcce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2",
                "cSLf8bi4X2EBNBDagaKuzkLB7jonh1Rqp6is2Md6wDdXMekFqFzN",
                "KxBhnk7DGkXY7Fsw4MaRGXtHrmeqpxxc6u1Rr9aGjNQhH514gkU4",
                "KzDsQasE4c45YHDiuidSiiss85Srs913BQeWcTthv4Y6bvBSio9w",
                "KxVvPYS7mmZpmVTpakwWhqgZsutEa2qVqTxoQ5DfcGPNV1h84jxe",
                "L1FaeGmj8cAFY2d6fnux6LtzD9yKyqGRF3FTmxTdu4Z4ACVzJotJ",
                "5KAigHMamRhN7uwHFnk3yz7vUTyQT1nmXoAA899XpZKJpkqsPFp",
                "T4oDFhweKSqfPjiebJb6hoCLJKNFsWTYHfodfGyuoGy5yHoete7k",
                "edskS3E5CLrkwHRYAbDvw5xC913C9GGseMcyNGeGbeaD57Yvvi2jqizpAAZyzUtRK626UvkKYdJwCYE9oKMcqFCtJeBpDYcrVH"
            ];
            let export_info = vec![
                ("m/44'/145'/0'/0/0", "BITCOINCASH", "MAINNET", "secp256k1"),
                ("m/44'/145'/0'/0/1", "BITCOINCASH", "MAINNET", "secp256k1"),
                ("m/44'/1'/0'/0/1", "BITCOINCASH", "TESTNET", "secp256k1"),
                ("m/44'/195'/0'/0/0", "TRON", "", "secp256k1"),
                ("m/44'/461'/0'/0/0", "FILECOIN", "MAINNET", "secp256k1"),
                ("m/2334/461/0/0", "FILECOIN", "MAINNET", "bls12-381"),
                ("m/44'/60'/0'/0/0", "ETHEREUM", "", "secp256k1"),
                ("m/44'/1'/0'/0/0", "BITCOIN", "TESTNET", "secp256k1"),
                ("m/44'/0'/0'/0/0", "BITCOIN", "MAINNET", "secp256k1"),
                ("m/49'/0'/0'/0/0", "BITCOIN", "MAINNET", "secp256k1"),
                ("m/84'/0'/0'/0/0", "BITCOIN", "MAINNET", "secp256k1"),
                ("m/86'/0'/0'/0/0", "BITCOIN", "MAINNET", "secp256k1"),
                ("m/44'/194'/0'/0/0", "EOS", "", "secp256k1"),
                ("m/44'/2'/0'/0/0", "LITECOIN", "MAINNET", "secp256k1"),
                ("m/44'/1729'/0'/0'", "TEZOS", "", "ed25519"),
            ];

            let import_result = import_default_wallet();
            for idx in 0..export_info.len() {
                let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                    id: import_result.id.to_string(),
                    key: Some(crate::api::export_private_key_param::Key::Password(
                        TEST_PASSWORD.to_owned(),
                    )),
                    chain_type: export_info[idx].1.to_string(),
                    network: export_info[idx].2.to_string(),
                    curve: export_info[idx].3.to_string(),
                    path: export_info[idx].0.to_string(),
                };
                let ret_bytes = call_api("export_private_key", param).unwrap();
                let export_result: ExportPrivateKeyResult =
                    ExportPrivateKeyResult::decode(ret_bytes.as_slice()).unwrap();

                assert_eq!(pks[idx], export_result.private_key);
            }

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_chain_cannot_export_private_key() {
        run_test(|| {
            let derivations = vec![Derivation {
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            }];

            let export_info = vec![
                ("m/44'/118'/0'/0/0", "COSMOS", "secp256k1"),
                ("m/44'/434'/0'/0/0", "KUSAMA", "sr25519"),
                ("m/44'/354'/0'/0/0", "POLKADOT", "sr25519"),
            ];

            let import_result = import_default_wallet();
            for idx in 0..derivations.len() {
                let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                    id: import_result.id.to_string(),
                    key: Some(crate::api::export_private_key_param::Key::Password(
                        TEST_PASSWORD.to_owned(),
                    )),
                    chain_type: export_info[idx].1.to_string(),
                    network: "".to_string(),
                    curve: export_info[idx].2.to_string(),
                    path: export_info[idx].1.to_string(),
                };
                let ret = call_api("export_private_key", param);

                assert!(ret.is_err());
            }
        })
    }

    #[test]
    #[serial]
    pub fn test_import_to_pk_which_from_hd() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: "L39VXyorp19JfsEJfbD7Tfr4pBEX93RJuVXW7E13C51ZYAhUWbYa".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_import_to_pk_which_from_hd".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };

            let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
            let wallet: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

            let derivation = Derivation {
                chain_type: "BITCOINCASH".to_string(),
                path: "".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let derive_param = DeriveAccountsParam {
                id: wallet.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };
            let ret_bytes = derive_accounts(&encode_message(derive_param).unwrap()).unwrap();
            let ret: DeriveAccountsResult =
                DeriveAccountsResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r",
                ret.accounts.first().unwrap().address
            );
            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_verify_password() {
        run_test(|| {
            let wallet_id = vec![
                import_default_pk_store().id.to_string(),
                import_default_wallet().id.to_string(),
            ];
            for id in wallet_id {
                let param: WalletKeyParam = WalletKeyParam {
                    id: id.to_string(),
                    key: Some(api::wallet_key_param::Key::Password(
                        TEST_PASSWORD.to_owned(),
                    )),
                };

                let ret_bytes = call_api("verify_password", param).unwrap();
                let result: GeneralResult = GeneralResult::decode(ret_bytes.as_slice()).unwrap();
                assert!(result.is_success);

                let param: WalletKeyParam = WalletKeyParam {
                    id: id.to_string(),
                    key: Some(api::wallet_key_param::Key::Password(
                        "WRONG PASSWORD".to_string(),
                    )),
                };

                let ret = call_api("verify_password", param);
                assert!(ret.is_err());
                assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");
            }
        })
    }

    #[test]
    #[serial]
    pub fn test_delete_keystore_by_password() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: "5JZc7wGRUr4J1RHDcM9ySWKLfQ2xjRUEo612qC4RLJ3G7jzJ4qx".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_delete_keystore".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };

            let ret_bytes = import_private_key(&encode_message(param).unwrap()).unwrap();
            let import_result: KeystoreResult =
                KeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            let param: WalletKeyParam = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    "WRONG PASSWORD".to_string(),
                )),
            };

            let ret = call_api("delete_keystore", param);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

            let param: WalletKeyParam = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };

            let ret_bytes = call_api("delete_keystore", param).unwrap();
            let ret: GeneralResult = GeneralResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(ret.is_success);

            let param: ExistsPrivateKeyParam = ExistsPrivateKeyParam {
                private_key: "5JZc7wGRUr4J1RHDcM9ySWKLfQ2xjRUEo612qC4RLJ3G7jzJ4qx".to_string(),
            };

            let ret_bytes = call_api("exists_private_key", param).unwrap();
            let ret: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();

            assert_eq!(false, ret.is_exists);
        })
    }

    #[test]
    #[serial]
    pub fn test_delete_keystore_by_derived_key() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: "5JZc7wGRUr4J1RHDcM9ySWKLfQ2xjRUEo612qC4RLJ3G7jzJ4qx".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test_delete_keystore".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };

            let ret_bytes = import_private_key(&encode_message(param).unwrap()).unwrap();
            let import_result: KeystoreResult =
                KeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let ret_bytes = get_derived_key(&encode_message(param).unwrap()).unwrap();
            let derived_key_result: DerivedKeyResult =
                DerivedKeyResult::decode(ret_bytes.as_slice()).unwrap();

            let param: WalletKeyParam = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::DerivedKey(
                    "2de5cb10b712be587f31e428e22984bd9ee420d198ddd742f70d746fff27d19904629dd64246a0ce2dbb1484c193d51bb2fd47d5611def5b4db4531d7abed824".to_string(),
                )),
            };

            let ret = call_api("delete_keystore", param);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

            let param: WalletKeyParam = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::DerivedKey(
                    derived_key_result.derived_key.to_owned(),
                )),
            };

            let ret_bytes = call_api("delete_keystore", param).unwrap();
            let ret: GeneralResult = GeneralResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(ret.is_success);

            let param: ExistsPrivateKeyParam = ExistsPrivateKeyParam {
                private_key: "5JZc7wGRUr4J1RHDcM9ySWKLfQ2xjRUEo612qC4RLJ3G7jzJ4qx".to_string(),
            };

            let ret_bytes = call_api("exists_private_key", param).unwrap();
            let ret: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();

            assert_eq!(false, ret.is_exists);
        })
    }

    #[test]
    #[serial]
    pub fn test_keystore_exists() {
        run_test(|| {
            let wallet = import_default_wallet();
            let param: ExistsMnemonicParam = ExistsMnemonicParam {
                mnemonic: TEST_MNEMONIC.to_string(),
            };

            let ret_bytes = call_api("exists_mnemonic", param).unwrap();
            let result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, wallet.id);

            let wallet = import_default_pk_store();
            let param: ExistsPrivateKeyParam = ExistsPrivateKeyParam {
                private_key: "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB".to_string(),
            };

            let ret_bytes = call_api("exists_private_key", param).unwrap();
            let result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, wallet.id);

            let param: ExistsPrivateKeyParam = ExistsPrivateKeyParam {
                private_key: "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6"
                    .to_string(),
            };

            let ret_bytes = call_api("exists_private_key", param).unwrap();
            let result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, wallet.id);

            let wallet = import_default_wallet();
            let param: ExistsMnemonicParam = ExistsMnemonicParam {
                mnemonic: format!("{}", " inject  kidney  empty canal shadow  pact comfort  wife crush horse wife sketch  ").to_string(),//Badly formatted mnemonic
            };

            let ret_bytes = call_api("exists_mnemonic", param).unwrap();
            let result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(result.is_exists);
            assert_eq!(result.id, wallet.id);

            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_sign_ckb_tx() {
        run_test(|| {
            let wallet: KeystoreResult = import_default_wallet();
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
                        derived_path: "m/44'/309'/0'/0/1".to_string(),
                    },
                    CachedCell {
                        capacity: 0,
                        lock: Some(Script {
                            hash_type: "type".to_string(),
                            code_hash: code_hash.clone(),
                            args: "0x2d79d9ed37184c1136bcfbe229947a137f80dec0".to_owned(),
                        }),
                        out_point: Some(out_points[1].clone()),
                        derived_path: "m/44'/309'/0'/1/0".to_string(),
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
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    pub fn test_sign_tron_tx() {
        run_test(|| {
            let wallet = import_default_wallet();

            let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
            let input = TronTxInput { raw_data };
            let input_value = encode_message(input).unwrap();
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password("WRONG PASSWORD".to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                curve: "secp256k1".to_string(),
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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    pub fn test_sign_cosmos_tx() {
        run_test(|| {
            let wallet = import_default_wallet();

            let raw_data = "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201".to_string();
            let input = AtomTxInput { raw_data };
            let input_value = encode_message(input).unwrap();
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password("WRONG PASSWORD".to_string())),
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    pub fn test_get_public_keys() {
        run_test(|| {
            let wallet = import_default_wallet();

            let param: GetPublicKeysParam = GetPublicKeysParam {
                id: wallet.id.to_string(),
                key: Some(crate::api::get_public_keys_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![PublicKeyDerivation {
                    chain_type: "EOS".to_string(),
                    path: "m/44'/194'/0'/0/0".to_string(),
                    curve: "secp256k1".to_string(),
                }],
            };
            let ret_bytes = call_api("get_public_keys", param).unwrap();
            let public_key_result: GetPublicKeysResult =
                GetPublicKeysResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
                public_key_result.public_keys[0]
            );
        })
    }

    #[test]
    #[serial]
    pub fn test_get_public_keys_ethereum2() {
        run_test(|| {
            let wallet = import_default_wallet();

            let param: GetPublicKeysParam = GetPublicKeysParam {
                id: wallet.id.to_string(),
                key: Some(crate::api::get_public_keys_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![PublicKeyDerivation {
                    chain_type: "ETEHREUM2".to_string(),
                    path: "m/12381/3600/0/0".to_string(),
                    curve: "bls12-381".to_string(),
                }],
            };
            let ret_bytes = call_api("get_public_keys", param).unwrap();
            let public_key_result: GetPublicKeysResult =
                GetPublicKeysResult::decode(ret_bytes.as_slice()).unwrap();
            assert_eq!(
                "0x99833eeee8cfad1bb7a82a5ceecca02590eeb342ad491c64c270fdb9bd739c398b7f8ca8608bfada25ba4efb5d8e5653",
                public_key_result.public_keys[0]
            );
        })
    }

    #[test]
    #[serial]
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

            let param = ImportJsonParam {
                json: wrong_keystore_str.to_string(),
                password: TEST_PASSWORD.to_string(),
                overwrite: true,
            };

            let ret = call_api("exists_json", param.clone());

            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "decrypt_json_error");

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

            let param = ExistsJsonParam {
                json: keystore_str.to_string(),
                password: TEST_PASSWORD.to_string(),
            };
            // let param_bytes = encode_message(param).unwrap();

            let ret_bytes = call_api("exists_json", param.clone()).unwrap();

            let exists_result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(!exists_result.is_exists);

            let ret_bytes = call_api("import_json", param.clone()).unwrap();
            let wallet_ret: KeystoreResult = KeystoreResult::decode(ret_bytes.as_slice()).unwrap();

            let ret_bytes = call_api("exists_json", param.clone()).unwrap();
            let exists_result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
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

            let param = DeriveAccountsParam {
                id: wallet_ret.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };

            let ret = call_api("derive_accounts", param).unwrap();
            let accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(ret.as_slice()).unwrap();

            assert_eq!(
                accounts.accounts[0].address,
                "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS"
            );

            let export_param = ExportPrivateKeyParam {
                id: wallet_ret.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "KUSAMA".to_string(),
                network: "".to_string(),
                curve: "sr25519".to_string(),
                path: "".to_string(),
            };
            let ret = call_api("export_json", export_param).unwrap();
            let keystore_ret: ExportJsonResult = ExportJsonResult::decode(ret.as_slice()).unwrap();

            let keystore: SubstrateKeystore = serde_json::from_str(&keystore_ret.json).unwrap();
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
    #[serial]
    pub fn test_import_substrate_keystore_v3() {
        run_test(|| {
            let keystore_str: &str = r#"{
                "encoded": "nvrLmNETK/X6M5mylXX1g1++zpnULbYM8Da2NxI7Xe4AgAAAAQAAAAgAAAATe9CosvVLlmy71DcyeOI8BCRhPDmDGbFJJixjDOp6i6nTmkD1PvOVuSWmVQGeTMLl/nZfkmOiSrRc/u9UTBL4uJVuKxupBbsKdWmRx7ftm2E77SG9VtOrJDdpmcmID8Elk9ZtDGudz+5Chehffhx2UYZPVdxFRDDnIH9fTUJT3+DYVx/2X2dlcyRwU4O2iWLcI4ud9Hh271D9YGkh",
                "encoding": {
                  "content": ["pkcs8", "sr25519"],
                  "type": ["scrypt", "xsalsa20-poly1305"],
                  "version": "3"
                },
                "address": "5EhpTExwgK3VMfoawHrpLejmjuoUx7vNb6kF8SpHPzNnNBs3",
                "meta": {
                  "genesisHash": "",
                  "name": "test account",
                  "whenCreated": 1702811906958
                }
              }"#;

            let param = ExistsJsonParam {
                json: keystore_str.to_string(),
                password: TEST_PASSWORD.to_string(),
            };
            // let param_bytes = encode_message(param).unwrap();

            let ret_bytes = call_api("exists_json", param.clone()).unwrap();

            let exists_result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(!exists_result.is_exists);

            let ret_bytes = call_api("import_json", param.clone()).unwrap();
            let wallet_ret: KeystoreResult = KeystoreResult::decode(ret_bytes.as_slice()).unwrap();

            let ret_bytes = call_api("exists_json", param.clone()).unwrap();
            let exists_result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            assert!(exists_result.is_exists);

            let derivation = Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                bech32_prefix: "".to_string(),
            };

            let param = DeriveAccountsParam {
                id: wallet_ret.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };

            let ret = call_api("derive_accounts", param).unwrap();
            let accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(ret.as_slice()).unwrap();

            assert_eq!(
                accounts.accounts[0].address,
                "FDS7ZJpJg4R7Kd2hzfsEc6mtW5iknjZ3UazX76EsnbH74v8"
            );

            let export_param = ExportPrivateKeyParam {
                id: wallet_ret.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "KUSAMA".to_string(),
                network: "".to_string(),
                curve: "sr25519".to_string(),
                path: "".to_string(),
            };
            let ret = call_api("export_json", export_param).unwrap();
            let keystore_ret: ExportJsonResult = ExportJsonResult::decode(ret.as_slice()).unwrap();

            let keystore: SubstrateKeystore = serde_json::from_str(&keystore_ret.json).unwrap();
            assert!(keystore.validate().is_ok());
            assert_eq!(
                keystore.address,
                "FDS7ZJpJg4R7Kd2hzfsEc6mtW5iknjZ3UazX76EsnbH74v8"
            );
            assert_eq!(keystore.meta.name, "test account");
            assert!(keystore.meta.when_created > 1594102917);

            // assert_eq!(keystore_ret.fixtures, "");
            remove_created_wallet(&wallet_ret.id);
        })
    }

    #[test]
    #[serial]
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

            let param = ImportJsonParam {
                json: keystore_str.to_string(),
                password: TEST_PASSWORD.to_string(),
                overwrite: true,
            };

            let ret_bytes = call_api("import_json", param).unwrap();
            let wallet_ret: KeystoreResult = KeystoreResult::decode(ret_bytes.as_slice()).unwrap();
            let derivation = Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                bech32_prefix: "".to_string(),
            };

            let param = DeriveAccountsParam {
                id: wallet_ret.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };

            let ret = call_api("derive_accounts", param).unwrap();
            let accounts: DeriveAccountsResult =
                DeriveAccountsResult::decode(ret.as_slice()).unwrap();

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

            let param = DeriveAccountsParam {
                id: wallet_ret.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };

            let ret = call_api("derive_accounts", param);
            assert!(ret.is_err());
            // assert_eq!(
            //     format!("{}", ret.err().unwrap()),
            //     "pkstore_can_not_add_other_curve_account"
            // );
            assert_eq!(format!("{}", ret.err().unwrap()), "invalid_private_key");

            remove_created_wallet(&wallet_ret.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_sign_substrate_raw_tx() {
        run_test(|| {
            let wallet = import_default_wallet();

            let unsigned_msg = "0x0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7";
            let input = SubstrateRawTxIn {
                raw_data: unsigned_msg.to_string(),
            };

            let input_value = encode_message(input).unwrap();
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "KUSAMA".to_string(),
                path: "//kusama//imToken/0".to_string(),
                curve: "sr25519".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx).unwrap();
            let output: SubstrateTxOut = SubstrateTxOut::decode(ret.as_slice()).unwrap();

            assert_eq!(output.signature[0..4].to_string(), "0x01",);

            let sig_bytes = Vec::from_hex(output.signature[4..].to_string()).unwrap();
            let signature = sp_core::sr25519::Signature::from_slice(&sig_bytes).unwrap();

            let pub_key =
                Vec::from_hex("90742a577c8515391a46b7881c98c80ec92fe04255bb5b5fec862c7d633ada21")
                    .unwrap();
            let singer = sp_core::sr25519::Public::from_slice(&pub_key).unwrap();
            let msg = Vec::from_hex("0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7").unwrap();

            assert!(
                sp_core::sr25519::Signature::verify(&signature, msg.as_slice(), &singer),
                "assert sig"
            );

            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    #[serial]
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
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };

            let ret = call_api("derive_accounts", param).unwrap();
            let _rsp: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

            let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
            let input = TronTxInput { raw_data };
            let tx = SignParam {
                id: import_result.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    pub fn test_sign_filecoin_bls() {
        run_test(|| {
            let import_result = import_filecoin_pk_store();

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
                curve: "bls12-381".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    pub fn test_sign_filecoin_secp256k1() {
        run_test(|| {
            let import_result = import_default_pk_store();

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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    pub fn test_sign_by_dk_in_pk_store() {
        run_test(|| {
            let import_result = import_default_pk_store();

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input.clone()).unwrap(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!("password_incorrect", format!("{}", ret.err().unwrap()));

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    fn test_tron_sign_message() {
        run_test(|| {
            let wallet = import_default_wallet();

            let input_expects = vec![
                (TronMessageInput {
                    value: "0x645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                        .to_string(),
                    is_tron_header: true,
                }, "0x16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b"),
                (TronMessageInput {
                    value: "645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                        .to_string(),
                    is_tron_header: true,
                }, "0x16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b"),
                (TronMessageInput {
                    value: "abcdef"
                        .to_string(),
                    is_tron_header: true,
                }, "0x13e407627e584c821ba527d23d64163d458447dfea1c3bfc92be660aa8d093ee5cfa3881870c4c51f157828eb9d4f7fad8112761f3b51cf76c7a4a3f241033d51b"),
            ];
            for (input, expected) in input_expects {
                let tx = SignParam {
                    id: wallet.id.to_string(),
                    key: Some(Key::Password(TEST_PASSWORD.to_string())),
                    chain_type: "TRON".to_string(),
                    path: "m/44'/195'/0'/0/0".to_string(),
                    curve: "secp256k1".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    input: Some(::prost_types::Any {
                        type_url: "imtoken".to_string(),
                        value: encode_message(input).unwrap(),
                    }),
                };

                let sign_result = call_api("sign_msg", tx).unwrap();
                let ret: TronMessageOutput =
                    TronMessageOutput::decode(sign_result.as_slice()).unwrap();
                assert_eq!(expected, ret.signature);
            }
        });
    }

    #[test]
    #[serial]
    fn test_sign_by_dk_hd_store() {
        run_test(|| {
            let wallet = import_default_wallet();
            let input = TronMessageInput {
                value: "0x645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                    .to_string(),
                is_tron_header: true,
            };

            let dk_param = WalletKeyParam {
                id: wallet.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };

            let ret_bytes = get_derived_key(&encode_message(dk_param).unwrap()).unwrap();
            let ret: DerivedKeyResult = DerivedKeyResult::decode(ret_bytes.as_slice()).unwrap();

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::DerivedKey(ret.derived_key)),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input.clone()).unwrap(),
                }),
            };

            let sign_result = call_api("sign_msg", tx).unwrap();
            let ret: TronMessageOutput = TronMessageOutput::decode(sign_result.as_slice()).unwrap();
            assert_eq!("0x16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b", ret.signature);

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::DerivedKey("7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001".to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input).unwrap(),
                }),
            };

            let ret = call_api("sign_msg", tx);
            assert!(ret.is_err());
            assert_eq!("password_incorrect", format!("{}", ret.err().unwrap()));

            remove_created_wallet(&wallet.id);
        });
    }

    #[test]
    #[serial]
    pub fn test_sign_btc_fork_invalid_address() {
        run_test(|| {
            let chain_types = vec!["BITCOIN", "LITECOIN", "BITCOINCASH"];

            let import_result: KeystoreResult = import_default_wallet();

            for chain_type in chain_types {
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
                    curve: "secp256k1".to_string(),
                    network: "MAINNET".to_string(),
                    seg_wit: "".to_string(),
                    input: Some(::prost_types::Any {
                        type_url: "imtoken".to_string(),
                        value: input_value.clone(),
                    }),
                };

                let ret = call_api("sign_tx", tx);
                assert!(ret.is_err());
                assert_eq!(format!("{}", ret.err().unwrap()), "invalid_address");
            }

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
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

            let (wallet, _acc_rsp) = import_and_derive(derivation);

            let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
            let input = TronTxInput { raw_data };
            let input_value = encode_message(input).unwrap();

            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    #[ignore = "this case is test panic"]
    fn test_panic_keystore_locked() {
        run_test(|| {
            let wallet = import_default_wallet();
            let param = WalletKeyParam {
                id: wallet.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let _ret = call_api("unlock_then_crash", param);
            let err = unsafe { _to_str(get_last_err_message()) };
            let err_bytes = Vec::from_hex(err).unwrap();
            let rsp: GeneralResult = GeneralResult::decode(err_bytes.as_slice()).unwrap();
            assert!(!rsp.is_success);
            assert_eq!(rsp.error, "test_unlock_then_crash");
            let map = KEYSTORE_MAP.read();
            let keystore: &Keystore = map.get(&wallet.id).unwrap();
            assert!(keystore.is_locked())
        });
    }

    fn remove_created_wallet(wid: &str) {
        let full_file_path = format!("{}/{}.json", "/tmp/imtoken/walletsv2", wid);
        let p = Path::new(&full_file_path);
        remove_file(p).expect("should remove file");
    }

    #[test]
    #[serial]
    pub fn test_sign_tezos_tx() {
        run_test(|| {
            let wallet = import_default_wallet();

            let raw_data = "d3bdafa2e36f872e24f1ccd68dbdca4356b193823d0a6a54886d7641e532a2a26c00dedf1a2f428e5e85edf105cb3600949f3d0e8837c70cacb4e803e8528102c0843d0000dcdcf88d0cfb769e33b1888d6bdc351ee3277ea700".to_string();
            let input = TezosRawTxIn { raw_data };
            let input_value = encode_message(input).unwrap();
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password("WRONG PASSWORD".to_string())),
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
                curve: "ed25519".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
                path: "m/44'/1729'/0'/0'".to_string(),
                curve: "ed25519".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_chain");

            let mut tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
                curve: "ed25519".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
            };

            let ret = call_api("sign_tx", tx.clone()).unwrap();

            let output: TezosTxOut = TezosTxOut::decode(ret.as_slice()).unwrap();
            let expected_sign = "0df020458bdcfe24546488dd81e1bd7e2cb05379dc7c72ad626646ae22df5d3a652fdc4ffd2383dd5823a98fe158780928da07a3f0a234e23b759ce7b3a39a0c";
            assert_eq!(expected_sign, output.signature.as_str());

            let raw_data = "0xd3bdafa2e36f872e24f1ccd68dbdca4356b193823d0a6a54886d7641e532a2a26c00dedf1a2f428e5e85edf105cb3600949f3d0e8837c70cacb4e803e8528102c0843d0000dcdcf88d0cfb769e33b1888d6bdc351ee3277ea700".to_string();
            let input = TezosRawTxIn { raw_data };
            let input_value = encode_message(input).unwrap();
            tx.input = Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            });
            let ret = call_api("sign_tx", tx).unwrap();
            let output: TezosTxOut = TezosTxOut::decode(ret.as_slice()).unwrap();
            let expected_sign = "0df020458bdcfe24546488dd81e1bd7e2cb05379dc7c72ad626646ae22df5d3a652fdc4ffd2383dd5823a98fe158780928da07a3f0a234e23b759ce7b3a39a0c";
            assert_eq!(expected_sign, output.signature.as_str());
            remove_created_wallet(&wallet.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_get_pubkey_keys() {
        run_test(|| {
            let param = ImportMnemonicParam {
                mnemonic: OTHER_MNEMONIC.to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test-wallet".to_string(),
                password_hint: "imtoken".to_string(),
                overwrite: true,
                network: "TESTNET".to_string(),
            };
            let ret = call_api("import_mnemonic", param).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();
            let derivations = vec![PublicKeyDerivation {
                chain_type: "ETHEREUM2".to_string(),
                path: "m/12381/3600/0/0/0".to_string(),
                curve: "bls12-381".to_string(),
            }];
            let param = GetPublicKeysParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::get_public_keys_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let result_bytes = call_api("get_public_keys", param).unwrap();
            let result = GetPublicKeysResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(result.public_keys.get(0).unwrap(), "0x941c2ab3d28b0fe37fde727e3178738a475696aed7335c7f4c2d91d06a1540acadb8042f119fb5f8029e7765de21fac2");

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_sign_hashes() {
        run_test(|| {
            let param = ImportMnemonicParam {
                mnemonic: OTHER_MNEMONIC.to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test-wallet".to_string(),
                password_hint: "imtoken".to_string(),
                overwrite: true,
                network: "MAINNET".to_string(),
            };
            let ret = call_api("import_mnemonic", param).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();
            let data_to_sign = vec![DataToSign {
                hash: "3e0658d8284d8f50c0aa8fa6cdbd1bde0eb370d4b3489a26c83763671ace8b1c"
                    .to_string(),
                path: "m/12381/3600/0/0".to_string(),
                curve: "bls12-381".to_string(),
                sig_alg: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".to_string(),
            }];
            let param = SignHashesParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::sign_hashes_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                data_to_sign,
            };
            let result_bytes = call_api("sign_hashes", param).unwrap();
            let result = SignHashesResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(result.signatures.get(0).unwrap(), "0x8fa5d4dfe4766de7896f0e32c5bee9baae47aaa843cf5f1a2587dd9aaedf8a8c4400cb31bdcb1e90ddfe6d309e57841204dbf53704e4c4da3a9d25e9b4a09dac31a3221a7aac76f58ca21854173303cf58f039770a9e2307966e89faf0e5e79e");

            let data_to_sign = vec![DataToSign {
                hash: "3e0658d8284d8f50c0aa8fa6cdbd1bde0eb370d4b3489a26c83763671ace8b1c"
                    .to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                sig_alg: "ECDSA".to_string(),
            }];
            let param = SignHashesParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::sign_hashes_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                data_to_sign,
            };
            let result_bytes = call_api("sign_hashes", param).unwrap();
            let result = SignHashesResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(result.signatures.get(0).unwrap(), "0x80c4f5c9299d21dc62a91e6bd1868cda545e31cadbf0eff35f802a4509cecea2618e5b352843ac4f487d2b43ebd55cdf7ad0b78ca81a96504744cd4209ce343d00");

            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_sign_ethereum_legacy_tx() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "1".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            };

            let (wallet, acc_rsp) = import_and_derive(derivation);

            let acc = acc_rsp.accounts.first().unwrap();
            assert_eq!("tpubDCvte6zYB6DKMaEy4fwyoXpuExA4ery3Hu6dVSBZeY9Rg57VKFLwNPMfywWtqRFM1Df5gQJTu42RaaNCgVEyngdVfnYRh9Kb1UCoEYojURc", acc.extended_public_key);
            assert_eq!("w6s0ZvUoPPSiEi1xDMKy5X9+qwhcX4u3e3LOBosJaOSro2ny9jppDxcczZfrhe29n9H3UkmgNoecq/85xfXkGDtH8PMR9iclK5WrcUtkgjXsBcrR6JF0j58i4W9x3y539vXOsLMifCmUr2RcqknDgw==", acc.encrypted_extended_public_key);

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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    pub fn test_sign_ethereum_eip1559_tx() {
        run_test(|| {
            let wallet = import_default_wallet();

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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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
    #[serial]
    pub fn test_sign_ethereum_eip1559_tx2() {
        run_test(|| {
            let wallet = import_default_wallet();
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
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
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

    #[test]
    #[serial]
    pub fn test_sign_ethereum_sign_message() {
        run_test(|| {
            let wallet = import_default_wallet();

            let eth_tx_input = EthMessageInput {
                message: "0x4578616d706c652060706572736f6e616c5f7369676e60206d657373616765"
                    .to_string(),
                signature_type: 0i32,
            };
            let input_value = encode_message(eth_tx_input).unwrap();
            let param = SignParam {
                id: wallet.id.to_string(),
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value,
                }),
                key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
            };
            let ret = call_api("sign_msg", param).unwrap();
            let output: EthMessageOutput = EthMessageOutput::decode(ret.as_slice()).unwrap();

            assert_eq!(output.signature, "0x5d595524847790aade63630ba4320854e0ae474b50d4c83eadfea9179185b2d67479cdfa9f59ec8f62575a7c09d4a5c9683aaf9cdb198ee51bdbe1bbf6eed1e91b");
        })
    }

    #[test]
    #[serial]
    pub fn test_derive_btc_legacy_sub_accounts() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/44'/0'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            };

            let (_wallet, accounts) = import_and_derive(derivation);
            let params = DeriveSubAccountsParam {
                chain_type: "BITCOIN".to_string(),
                curve: "secp256k1".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                relative_paths: vec!["0/0".to_string(), "0/1".to_string(), "1/0".to_string()],
                extended_public_key: accounts.accounts[0].extended_public_key.to_string(),
            };

            let result_bytes = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
            let result = DeriveSubAccountsResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(
                "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
                result.accounts[0].address
            );
            assert_eq!(
                "1962gsZ8PoPUYHneFakkCTrukdFMVQ4i4T",
                result.accounts[1].address
            );
            assert_eq!(
                "19vddWhyq637bqDfuKadsoy5mTNRgfb3hr",
                result.accounts[2].address
            );
        })
    }

    #[test]
    #[serial]
    pub fn test_derive_btc_p2wpkh_sub_accounts() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/49'/0'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            };

            let (_wallet, accounts) = import_and_derive(derivation);
            let params = DeriveSubAccountsParam {
                chain_type: "BITCOIN".to_string(),
                curve: "secp256k1".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                relative_paths: vec!["0/0".to_string(), "0/1".to_string(), "1/0".to_string()],
                extended_public_key: accounts.accounts[0].extended_public_key.to_string(),
            };

            let result_bytes = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
            let result = DeriveSubAccountsResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(
                "3JmreiUEKn8P3SyLYmZ7C1YCd4r2nFy3Dp",
                result.accounts[0].address
            );
            assert_eq!(
                "33xJxujVGf4qBmPTnGW9P8wrKCmT7Nwt3t",
                result.accounts[1].address
            );
            assert_eq!(
                "33K4nJ6HuM4fuJct11xPPHH65dnGrN5Ggt",
                result.accounts[2].address
            );
        })
    }

    #[test]
    #[serial]
    pub fn test_derive_eth_sub_accounts() {
        run_test(|| {
            let derivation = Derivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                bech32_prefix: "".to_string(),
            };

            let (_, accounts) = import_and_derive(derivation);
            let params = DeriveSubAccountsParam {
                chain_type: "ETHEREUM".to_string(),
                curve: "secp256k1".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
                extended_public_key: accounts.accounts[0].extended_public_key.to_string(),
            };

            let result_bytes = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
            let result = DeriveSubAccountsResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(
                "0x6031564e7b2F5cc33737807b2E58DaFF870B590b",
                result.accounts[0].address
            );
            assert_eq!(
                "0x80427Ae1f55bCf60ee4CD2db7549b8BC69a74303",
                result.accounts[1].address
            );
        })
    }

    #[test]
    #[serial]
    pub fn test_mnemonic_to_public() {
        run_test(|| {
            let params = MnemonicToPublicKeyParam {
                mnemonic: TEST_MNEMONIC.to_string(),
                path: "m/44'/194'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                encoding: "EOS".to_string(),
            };

            let result_bytes = mnemonic_to_public(&encode_message(params).unwrap()).unwrap();
            let result = MnemonicToPublicKeyResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(
                "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
                result.public_key
            );

            let params = MnemonicToPublicKeyParam {
                mnemonic: TEST_MNEMONIC.to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                encoding: "HEX".to_string(),
            };

            let result_bytes = mnemonic_to_public(&encode_message(params).unwrap()).unwrap();
            let result = MnemonicToPublicKeyResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(
                "0x0280c98b8ea7cab630defb0c09a4295c2193cdee016c1d5b9b0cb18572b9c370fe",
                result.public_key
            );
        })
    }

    #[test]
    #[serial]
    pub fn test_import_hex_private_key() {
        run_test(|| {
            let param: ExistsPrivateKeyParam = ExistsPrivateKeyParam {
                private_key: TEST_PRIVATE_KEY.to_string(),
            };
            let ret = call_api("exists_private_key", param).unwrap();
            let exists_private_key_result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret.as_slice()).unwrap();
            assert!(!exists_private_key_result.is_exists);

            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: TEST_PRIVATE_KEY.to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "import_private_key_wallet".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };
            let ret = call_api("import_private_key", param).unwrap();
            let import_result: ImportPrivateKeyResult =
                ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();
            assert_eq!(Vec::<String>::new(), import_result.identified_chain_types);
            assert_eq!("secp256k1", import_result.identified_curve);
            assert_eq!("", import_result.identified_network);
            assert_eq!("PRIVATE", import_result.source);

            let param: ExistsPrivateKeyParam = ExistsPrivateKeyParam {
                private_key: TEST_PRIVATE_KEY.to_string(),
            };
            let ret = call_api("exists_private_key", param).unwrap();
            let exists_private_key_result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret.as_slice()).unwrap();
            assert!(exists_private_key_result.is_exists);
            assert_eq!(exists_private_key_result.id, import_result.id);

            let param: ExportPrivateKeyParam = ExportPrivateKeyParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::export_private_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                chain_type: "ETHEREUM".to_string(),
                network: "".to_string(),
                curve: CurveType::SECP256k1.as_str().to_string(),
                path: "".to_string(),
            };
            let ret = call_api("export_private_key", param).unwrap();
            let export_result: ExportPrivateKeyResult =
                ExportPrivateKeyResult::decode(ret.as_slice()).unwrap();
            assert_eq!(export_result.id, import_result.id);
            assert_eq!(export_result.private_key, TEST_PRIVATE_KEY);

            let param: ExportJsonParam = ExportJsonParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "ETHEREUM".to_string(),
                path: "".to_string(),
            };
            let ret = call_api("export_json", param).unwrap();
            let export_result: ExportJsonResult = ExportJsonResult::decode(ret.as_slice()).unwrap();
            assert_eq!(export_result.id, import_result.id);
            assert!(export_result
                .json
                .contains("0x6031564e7b2F5cc33737807b2E58DaFF870B590b"));
        })
    }

    #[test]
    #[serial]
    pub fn test_import_wif_network_mismatch() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: TEST_WIF.to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "import_private_key_wallet".to_string(),
                password_hint: "".to_string(),
                network: "".to_string(),
                overwrite: true,
            };
            let ret = call_api("import_private_key", param);
            assert_eq!(
                format!("{}", ret.unwrap_err()),
                "private_key_network_mismatch"
            );

            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: TEST_WIF.to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "import_private_key_wallet".to_string(),
                password_hint: "".to_string(),
                network: "MAINNET".to_string(),
                overwrite: true,
            };
            let ret = call_api("import_private_key", param);
            // let import_result: ImportPrivateKeyResult =
            //     ImportPrivateKeyResult::decode(ret.as_slice());
            assert_eq!(
                format!("{}", ret.unwrap_err()),
                "private_key_network_mismatch"
            );

            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                private_key: TEST_WIF.to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "import_private_key_wallet".to_string(),
                password_hint: "".to_string(),
                network: "TESTNET".to_string(),
                overwrite: true,
            };
            let ret = call_api("import_private_key", param).unwrap();
            let import_result: ImportPrivateKeyResult =
                ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();
            assert_eq!(import_result.identified_network, "TESTNET");
        })
    }

    #[test]
    #[serial]
    pub fn test_import_v3_keystore_json() {
        run_test(|| {
            let json = r#"{
                "version": 3,
                "id": "5c24e96a-8fd8-4872-9702-3fd2fc9166cd",
                "crypto": {
                  "cipher": "aes-128-ctr",
                  "cipherparams": { "iv": "56ed1daad9226d7edd75e8ab34e32309" },
                  "ciphertext": "95cae71ef4d76c3def64bf77d267608a823fc65cda6254ea24d1cbbe09de6b6b",
                  "kdf": "pbkdf2",
                  "kdfparams": {
                    "c": 262144,
                    "prf": "hmac-sha256",
                    "dklen": 32,
                    "salt": "63c89a7275a65bd659a937fe374c668e5aa3b05a9b0ef3ec9178aa9182f42666"
                  },
                  "mac": "2adc6da2f5f183e528a063b36ebeddaf0d3a90269ef797b99dc143d58ba3bb58"
                },
                "address": "0x6031564e7b2F5cc33737807b2E58DaFF870B590b"
              }
              "#;
            let param: ExistsJsonParam = ExistsJsonParam {
                json: json.to_string(),
                password: TEST_PASSWORD.to_string(),
            };
            let ret = call_api("exists_json", param).unwrap();
            let exists_private_key_result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret.as_slice()).unwrap();
            assert!(!exists_private_key_result.is_exists);

            let param: ImportJsonParam = ImportJsonParam {
                password: TEST_PASSWORD.to_string(),
                json: json.to_string(),
                overwrite: true,
            };
            let ret = call_api("import_json", param).unwrap();
            let import_result: ImportPrivateKeyResult =
                ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();
            assert_eq!(
                vec!["ETHEREUM".to_string()],
                import_result.identified_chain_types
            );
            assert_eq!("secp256k1", import_result.identified_curve);
            assert_eq!("", import_result.identified_network);
            assert_eq!("KEYSTORE_V3", import_result.source);

            let param: ExistsJsonParam = ExistsJsonParam {
                password: TEST_PASSWORD.to_string(),
                json: json.to_string(),
            };
            let ret = call_api("exists_json", param).unwrap();
            let exists_private_key_result: ExistsKeystoreResult =
                ExistsKeystoreResult::decode(ret.as_slice()).unwrap();
            assert!(exists_private_key_result.is_exists);
            assert_eq!(exists_private_key_result.id, import_result.id);

            let param: ExportJsonParam = ExportJsonParam {
                id: import_result.id.to_string(),
                password: TEST_PASSWORD.to_string(),
                chain_type: "ETHEREUM".to_string(),
                path: "".to_string(),
            };
            let ret = call_api("export_json", param).unwrap();
            let export_result: ExportJsonResult = ExportJsonResult::decode(ret.as_slice()).unwrap();
            assert_eq!(export_result.id, import_result.id);
            assert!(export_result
                .json
                .to_string()
                .contains("0x6031564e7b2F5cc33737807b2E58DaFF870B590b"));
        })
    }

    #[test]
    #[serial]
    pub fn test_sign_bls_to_execution_change() {
        run_test(|| {
            let param = ImportMnemonicParam {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test-wallet".to_string(),
                password_hint: "imtoken".to_string(),
                overwrite: true,
                network: "MAINNET".to_string(),
            };
            let ret = call_api("import_mnemonic", param).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

            let derivations = vec![PublicKeyDerivation {
                path: "m/12381/3600/0/0".to_string(),
                curve: "bls12-381".to_string(),
                chain_type: "ETHEREUM2".to_string(),
            }];
            let param = GetPublicKeysParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::get_public_keys_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let result_bytes = call_api("get_public_keys", param).unwrap();
            let result = GetPublicKeysResult::decode(result_bytes.as_slice()).unwrap();
            assert_eq!(result.public_keys.clone().get(0).unwrap(), "0x99b1f1d84d76185466d86c34bde1101316afddae76217aa86cd066979b19858c2c9d9e56eebc1e067ac54277a61790db");

            let mut param = SignBlsToExecutionChangeParam {
                id: import_result.id.to_string(),
                key: Some(
                    tcx_eth2::transaction::sign_bls_to_execution_change_param::Key::Password(
                        TEST_PASSWORD.to_owned(),
                    ),
                ),
                genesis_fork_version: "0x03000000".to_string(),
                genesis_validators_root:
                    "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_string(),
                validator_index: vec![0],
                from_bls_pub_key: result.public_keys.get(0).unwrap().to_owned(),
                eth1_withdrawal_address: "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15".to_string(),
            };
            let ret_bytes = call_api("sign_bls_to_execution_change", param.clone()).unwrap();
            let result: SignBlsToExecutionChangeResult =
                SignBlsToExecutionChangeResult::decode(ret_bytes.as_slice()).unwrap();

            assert_eq!(result.signeds.get(0).unwrap().signature, "8c8ce9f8aedf380e47548501d348afa28fbfc282f50edf33555a3ed72eb24d710bc527b5108022cffb764b953941ec4014c44106d2708387d26cc84cbc5c546a1e6e56fdc194cf2649719e6ac149596d80c86bf6844b36bd47038ee96dd3962f");
            param.eth1_withdrawal_address =
                "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15XX".to_string();
            let result = call_api("sign_bls_to_execution_change", param.clone());
            assert_eq!(
                result.err().unwrap().to_string(),
                "invalid_eth_address".to_string()
            );
            remove_created_wallet(&import_result.id);
        })
    }

    #[test]
    #[serial]
    pub fn test_migrate_keystores_existed() {
        let _ = fs::remove_dir_all("../test-data/walletsV2");
        init_token_core_x("../test-data");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "0a2756cd-ff70-437b-9bdb-ad46b8bb0819".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let ret = call_api("migrate_keystore", param).unwrap();
        let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        let keystore = result.keystore.unwrap();
        assert_eq!(keystore.id, "0a2756cd-ff70-437b-9bdb-ad46b8bb0819");
        assert_eq!(
            keystore.identifier,
            "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg"
        );
        assert_eq!(
            keystore.ipfs_id,
            "QmSTTidyfa4np9ak9BZP38atuzkCHy4K59oif23f4dNAGU"
        );
        assert_eq!(keystore.created_at, 1703213098);
        assert_eq!(keystore.source, "MNEMONIC");
        assert_eq!(keystore.name, "tcx-wallet");
        assert_eq!(
            keystore.source_fingerprint,
            "0x1468dba9c246fe22183c056540ab4d8b04553217"
        );

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "00fc0804-7cea-46d8-9e95-ed1efac65358".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "2d7380db28736ae5b0693340a5731e137759d32bbcc1f7988574bc5a1ffd97f3411b4edc14ea648fa17d511129e81a84d2b8a00d45bc37f4784e49b641d5c3be".to_string(),
            )),
        };
        let ret = call_api("migrate_keystore", param).unwrap();
        let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        assert!(result.is_existed);
        assert_eq!(result.existed_id, "0a2756cd-ff70-437b-9bdb-ad46b8bb0819");

        fs::remove_dir_all("../test-data/walletsV2").unwrap();
    }

    #[test]
    #[serial]
    pub fn test_migrate_keystores_source() {
        let _ = fs::remove_dir_all("../test-data/walletsV2");
        init_token_core_x("../test-data");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "1a60471067b6c6a3202e0014de2ce9b2d45fd73e2289b3cc3d8e5b58fe99ff242fd61e9fe63e75abbdc0ed87a50756cc10c57daf1d6297b99ec9a3b174eee017".to_string(),
            )),
        };
        let ret = call_api("migrate_keystore", param).unwrap();
        let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        assert_eq!(result.keystore.unwrap().source, "PRIVATE");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "6c3eae60-ad03-48db-a5e5-61a6f72aef8d".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "9f65c31b4a61c430cd6c976e7f1b1b912bb09b46ec718447bbb5dccc353b19becb6b386405b3fcc7d43bd8e617764c3407d45824e52984d0074ac3f75c68bd92".to_string()
            )),
        };
        let ret = call_api("migrate_keystore", param).unwrap();
        let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        assert_eq!(result.keystore.unwrap().source, "MNEMONIC");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "9f4acb4a-7431-4c7d-bd25-a19656a86ea0".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "a5b0cb9cb0536d6ec6ab21da77415bd59aff62c44c1da40d377c4faf2a44608693a72efb4079f57a5dca710ecff75dc5b54beb4ad6d9f9d47b63583810b50c61".to_string(),
            )),
        };
        let ret = call_api("migrate_keystore", param).unwrap();
        let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        assert_eq!(result.keystore.unwrap().source, "WIF");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "949bada8-776c-4554-ad0c-001e3726a0f8".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let ret = call_api("migrate_keystore", param).unwrap();
        let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        assert_eq!(result.keystore.unwrap().source, "SUBSTRATE_KEYSTORE");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "60573d8d-8e83-45c3-85a5-34fbb2aad5e1".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let ret = call_api("migrate_keystore", param).unwrap();
        let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        assert_eq!(result.keystore.unwrap().source, "KEYSTORE_V3");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let ret = call_api("migrate_keystore", param).unwrap();
        let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        assert_eq!(result.keystore.unwrap().source, "PRIVATE");

        // fs::remove_dir_all("../test-data/walletsV2").unwrap();
    }

    #[test]
    #[serial]
    pub fn test_migrate_keystores_curve() {
        let _ = fs::remove_dir_all("../test-data/walletsV2");
        init_token_core_x("../test-data");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "1a60471067b6c6a3202e0014de2ce9b2d45fd73e2289b3cc3d8e5b58fe99ff242fd61e9fe63e75abbdc0ed87a50756cc10c57daf1d6297b99ec9a3b174eee017".to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        // let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        {
            let map = KEYSTORE_MAP.read();
            assert_eq!(
                map.get("4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca")
                    .unwrap()
                    .get_curve()
                    .unwrap(),
                CurveType::SECP256k1
            );
        }

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "9f4acb4a-7431-4c7d-bd25-a19656a86ea0".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "a5b0cb9cb0536d6ec6ab21da77415bd59aff62c44c1da40d377c4faf2a44608693a72efb4079f57a5dca710ecff75dc5b54beb4ad6d9f9d47b63583810b50c61".to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        {
            let map = KEYSTORE_MAP.read();
            assert_eq!(
                map.get("9f4acb4a-7431-4c7d-bd25-a19656a86ea0")
                    .unwrap()
                    .get_curve()
                    .unwrap(),
                CurveType::SECP256k1
            );
        }
        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "949bada8-776c-4554-ad0c-001e3726a0f8".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        {
            let map = KEYSTORE_MAP.read();
            assert_eq!(
                map.get("949bada8-776c-4554-ad0c-001e3726a0f8")
                    .unwrap()
                    .get_curve()
                    .unwrap(),
                CurveType::SR25519
            );
        }
        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "60573d8d-8e83-45c3-85a5-34fbb2aad5e1".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        {
            let map = KEYSTORE_MAP.read();
            assert_eq!(
                map.get("60573d8d-8e83-45c3-85a5-34fbb2aad5e1")
                    .unwrap()
                    .get_curve()
                    .unwrap(),
                CurveType::SECP256k1
            );
        }

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        {
            let map = KEYSTORE_MAP.read();
            assert_eq!(
                map.get("fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb")
                    .unwrap()
                    .get_curve()
                    .unwrap(),
                CurveType::BLS
            );
        }

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        {
            let map = KEYSTORE_MAP.read();
            assert_eq!(
                map.get("fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb")
                    .unwrap()
                    .get_curve()
                    .unwrap(),
                CurveType::BLS
            );
        }

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "4d5cbfcf-aee1-4908-9991-9d060eb68a0e".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        {
            let map = KEYSTORE_MAP.read();
            assert_eq!(
                map.get("4d5cbfcf-aee1-4908-9991-9d060eb68a0e")
                    .unwrap()
                    .get_curve()
                    .unwrap(),
                CurveType::ED25519
            );
        }

        fs::remove_dir_all("../test-data/walletsV2").unwrap();
    }

    #[test]
    #[serial]
    pub fn test_migrate_keystores_flush() {
        let _ = fs::remove_dir_all("../test-data/walletsV2");
        init_token_core_x("../test-data");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "1a60471067b6c6a3202e0014de2ce9b2d45fd73e2289b3cc3d8e5b58fe99ff242fd61e9fe63e75abbdc0ed87a50756cc10c57daf1d6297b99ec9a3b174eee017".to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        // let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        let json = fs::read_to_string(format!(
            "../test-data/walletsV2/4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca.json"
        ))
        .unwrap();
        let mut keystore = Keystore::from_json(&json).unwrap();
        assert_eq!(
            keystore.fingerprint(),
            "0x8b650646c72d8ec3f2a6da9f76dfe624a862c578"
        );

        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        assert_eq!(
            keystore.export().unwrap(),
            "685634d212eabe016a1cb09d9f1ea1ea757ebe590b9a097d7b1c9379ad280171"
        );

        assert_eq!(keystore.get_curve().unwrap(), CurveType::SECP256k1);
        assert_eq!(keystore.id(), "4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca");
        fs::remove_dir_all("../test-data/walletsV2").unwrap();
    }

    #[test]
    #[serial]
    pub fn test_identified_network_flush() {
        let _ = fs::remove_dir_all("../test-data/walletsV2");
        init_token_core_x("../test-data");

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "1a60471067b6c6a3202e0014de2ce9b2d45fd73e2289b3cc3d8e5b58fe99ff242fd61e9fe63e75abbdc0ed87a50756cc10c57daf1d6297b99ec9a3b174eee017".to_string(),
            )),
        };
        let _ = call_api("migrate_keystore", param).unwrap();
        // let result: MigrateKeystoreResult = MigrateKeystoreResult::decode(ret.as_slice()).unwrap();
        let json = fs::read_to_string(format!(
            "../test-data/walletsV2/4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca.json"
        ))
        .unwrap();
        let mut keystore = Keystore::from_json(&json).unwrap();
        assert_eq!(
            keystore.fingerprint(),
            "0x8b650646c72d8ec3f2a6da9f76dfe624a862c578"
        );

        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        assert_eq!(
            keystore.export().unwrap(),
            "685634d212eabe016a1cb09d9f1ea1ea757ebe590b9a097d7b1c9379ad280171"
        );

        assert_eq!(keystore.get_curve().unwrap(), CurveType::SECP256k1);
        assert_eq!(keystore.id(), "4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca");
        fs::remove_dir_all("../test-data/walletsV2").unwrap();
    }

    #[test]
    #[serial]
    pub fn test_migrate_keystores_identified_chain_types() {
        let _ = fs::remove_dir_all("../test-data/walletsV2");
        init_token_core_x("../test-data");

        // original = wif, identified_chain_types = BITCOIN
        {
            let param: MigrateKeystoreParam = MigrateKeystoreParam {
                id: "d9e3bb9c-87fd-4836-b146-10a3e249eb75".to_string(),
                key: Some(migrate_keystore_param::Key::DerivedKey(
                    "01073f22079380d2180300c518f6b510d4761fd83ce738271460c9e745b9055dabb28f93ff3a8fd54e0c71c005b5e799f8d52bcce1a81e08b5f15f9604531574".to_string(),
                )),
            };
            call_api("migrate_keystore", param).unwrap();
            let json = fs::read_to_string(format!(
                "../test-data/walletsV2/d9e3bb9c-87fd-4836-b146-10a3e249eb75.json"
            ))
            .unwrap();
            let keystore = Keystore::from_json(&json).unwrap();
            assert_eq!(
                keystore.meta().identified_chain_types,
                Some(vec!["BITCOIN".to_string()])
            );
            let unlocker = keystore
                .store()
                .crypto
                .use_key(&tcx_crypto::Key::DerivedKey("01073f22079380d2180300c518f6b510d4761fd83ce738271460c9e745b9055dabb28f93ff3a8fd54e0c71c005b5e799f8d52bcce1a81e08b5f15f9604531574".to_string()))
                .unwrap();
            let wif_bytes = unlocker
                .decrypt_enc_pair(&keystore.store().enc_original)
                .unwrap();
            let wif = String::from_utf8_lossy(&wif_bytes);
            assert_eq!("L1xDTJYPqhofU8DQCiwjStEBr1X6dhiNfweUhxhoRSgYyMJPcZ6B", wif);
        }

        // original = hex, identified_chain_types = ETEHREUM
        {
            let param: MigrateKeystoreParam = MigrateKeystoreParam {
                id: "60573d8d-8e83-45c3-85a5-34fbb2aad5e1".to_string(),
                key: Some(migrate_keystore_param::Key::DerivedKey(
                    "8f2316895af6d58b5b75d424977cdaeae2a619c6b941ca5f77dcfed592cd3b23b698040caf397df6153db6f2d5b2815bf8f8cd32f99998ca46534242df82d1ca".to_string(),
                )),
            };
            call_api("migrate_keystore", param).unwrap();
            let json = fs::read_to_string(format!(
                "../test-data/walletsV2/60573d8d-8e83-45c3-85a5-34fbb2aad5e1.json"
            ))
            .unwrap();
            let keystore = Keystore::from_json(&json).unwrap();
            assert_eq!(
                keystore.meta().identified_chain_types,
                Some(vec!["ETHEREUM".to_string()])
            );

            let unlocker = keystore
                .store()
                .crypto
                .use_key(&tcx_crypto::Key::DerivedKey("8f2316895af6d58b5b75d424977cdaeae2a619c6b941ca5f77dcfed592cd3b23b698040caf397df6153db6f2d5b2815bf8f8cd32f99998ca46534242df82d1ca".to_string()))
                .unwrap();
            let decrypted = unlocker
                .decrypt_enc_pair(&keystore.store().enc_original)
                .unwrap();
            let json = String::from_utf8_lossy(&decrypted);
            assert!(
                json.contains("9b62a4c07c96ca9b0b82b5b5eae4e7c9b2b7db531a6d2991198eb6809a8c35ac")
            );
        }

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "792a0051-16d7-44a7-921a-9b4a0c893b8f".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "0xebe2739dd04525823b967b914a74a5dedd0086622d0da3449c1354199518673dd33fca8f6bd64870d6e6dc28b0f6e9de169243679b1668750f23cfe9523c03b3".to_string(),
            )),
        };
        call_api("migrate_keystore", param).unwrap();
        let json = fs::read_to_string(format!(
            "../test-data/walletsV2/792a0051-16d7-44a7-921a-9b4a0c893b8f.json"
        ))
        .unwrap();
        let keystore = Keystore::from_json(&json).unwrap();
        assert!(keystore.meta().identified_chain_types.is_none());

        // assert!(keystore.store().enc_original.is_none());

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "f3615a56-cb03-4aa4-a893-89944e49920d".to_string(),
            key: Some(migrate_keystore_param::Key::DerivedKey(
                "0x79c74b67fc73a255bc66afc1e7c25867a19e6d2afa5b8e3107a472de13201f1924fed05e811e7f5a4c3e72a8a6e047a80393c215412bde239ec7ded520896630".to_string(),
            )),
        };
        call_api("migrate_keystore", param).unwrap();
        let json = fs::read_to_string(format!(
            "../test-data/walletsV2/f3615a56-cb03-4aa4-a893-89944e49920d.json"
        ))
        .unwrap();
        let keystore = Keystore::from_json(&json).unwrap();
        assert_eq!(
            keystore.meta().identified_chain_types,
            Some(vec!["ETHEREUM".to_string()])
        );

        let unlocker = keystore
            .store()
            .crypto
            .use_key(&tcx_crypto::Key::DerivedKey("0x79c74b67fc73a255bc66afc1e7c25867a19e6d2afa5b8e3107a472de13201f1924fed05e811e7f5a4c3e72a8a6e047a80393c215412bde239ec7ded520896630".to_string()))
            .unwrap();
        let decrypted = unlocker
            .decrypt_enc_pair(&keystore.store().enc_original)
            .unwrap();
        let hex = String::from_utf8_lossy(&decrypted);
        assert_eq!(
            "4b8e7a47497d810cd11f209b8ce9d3b0eec34e85dc8bad5d12cb602425dd3d6b",
            hex
        );

        let param: MigrateKeystoreParam = MigrateKeystoreParam {
            id: "fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb".to_string(),
            key: Some(migrate_keystore_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        call_api("migrate_keystore", param).unwrap();
        let json = fs::read_to_string(format!(
            "../test-data/walletsV2/fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb.json"
        ))
        .unwrap();
        let keystore = Keystore::from_json(&json).unwrap();
        assert_eq!(
            keystore.meta().identified_chain_types,
            Some(vec!["FILECOIN".to_string()])
        );
        // assert!(keystore.store().enc_original.is_none());

        // fs::remove_dir_all("../test-data/walletsV2").unwrap();
    }

    #[test]
    #[serial]
    pub fn test_backup_v3_keystore() {
        run_test(|| {
            let json = r#"{
                "version": 3,
                "id": "5c24e96a-8fd8-4872-9702-3fd2fc9166cd",
                "crypto": {
                  "cipher": "aes-128-ctr",
                  "cipherparams": { "iv": "56ed1daad9226d7edd75e8ab34e32309" },
                  "ciphertext": "95cae71ef4d76c3def64bf77d267608a823fc65cda6254ea24d1cbbe09de6b6b",
                  "kdf": "pbkdf2",
                  "kdfparams": {
                    "c": 262144,
                    "prf": "hmac-sha256",
                    "dklen": 32,
                    "salt": "63c89a7275a65bd659a937fe374c668e5aa3b05a9b0ef3ec9178aa9182f42666"
                  },
                  "mac": "2adc6da2f5f183e528a063b36ebeddaf0d3a90269ef797b99dc143d58ba3bb58"
                },
                "address": "0x6031564e7b2F5cc33737807b2E58DaFF870B590b"
              }
              "#;

            let param: ImportJsonParam = ImportJsonParam {
                password: TEST_PASSWORD.to_string(),
                json: json.to_string(),
                overwrite: true,
            };
            let ret = call_api("import_json", param).unwrap();
            let import_result: ImportPrivateKeyResult =
                ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();
            assert_eq!(
                vec!["ETHEREUM".to_string()],
                import_result.identified_chain_types
            );

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let ret = call_api("backup", param).unwrap();
            let export_result: BackupResult = BackupResult::decode(ret.as_slice()).unwrap();
            assert!(export_result
                .original
                .contains("0x6031564e7b2F5cc33737807b2E58DaFF870B590b"));

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };

            let ret = call_api("get_derived_key", param).unwrap();
            let derived_key_result: DerivedKeyResult =
                DerivedKeyResult::decode(ret.as_slice()).unwrap();
            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::DerivedKey(
                    derived_key_result.derived_key,
                )),
            };
            let ret = call_api("backup", param);
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "backup_keystore_need_password"
            );
        })
    }

    #[test]
    #[serial]
    pub fn test_backup_pjs_kystore() {
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
                    "name": "i_can_save_name",
                    "tags": [],
                    "whenCreated": 1593591324334
                }
                }"#;
            let param: ImportJsonParam = ImportJsonParam {
                password: TEST_PASSWORD.to_string(),
                json: keystore_str.to_string(),
                overwrite: true,
            };
            let ret = call_api("import_json", param).unwrap();
            let import_result: ImportPrivateKeyResult =
                ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();
            assert_eq!(
                vec!["KUSAMA".to_string(), "POLKADOT".to_string(),],
                import_result.identified_chain_types
            );

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let ret = call_api("backup", param).unwrap();
            let export_result: BackupResult = BackupResult::decode(ret.as_slice()).unwrap();
            assert!(export_result
                .original
                .contains("JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS"));

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };

            let ret = call_api("get_derived_key", param).unwrap();
            let derived_key_result: DerivedKeyResult =
                DerivedKeyResult::decode(ret.as_slice()).unwrap();
            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::DerivedKey(
                    derived_key_result.derived_key,
                )),
            };
            let ret = call_api("backup", param);
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "backup_keystore_need_password"
            );
        })
    }

    #[test]
    #[serial]
    pub fn test_backup_private_key() {
        run_test(|| {
            let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
                password: TEST_PASSWORD.to_string(),
                private_key: TEST_WIF.to_string(),
                name: "".to_string(),
                password_hint: "".to_string(),
                network: "TESTNET".to_string(),
                overwrite: true,
            };
            let ret = call_api("import_private_key", param).unwrap();
            let import_result: ImportPrivateKeyResult =
                ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();
            assert_eq!(
                vec![
                    "BITCOIN".to_string(),
                    "BITCOINCASH".to_string(),
                    "LITECOIN".to_string()
                ],
                import_result.identified_chain_types
            );

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let ret = call_api("backup", param).unwrap();
            let export_result: BackupResult = BackupResult::decode(ret.as_slice()).unwrap();
            assert_eq!(export_result.original, TEST_WIF);

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };

            let ret = call_api("get_derived_key", param).unwrap();
            let derived_key_result: DerivedKeyResult =
                DerivedKeyResult::decode(ret.as_slice()).unwrap();
            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::DerivedKey(
                    derived_key_result.derived_key,
                )),
            };
            let ret = call_api("backup", param).unwrap();
            let backup_result = BackupResult::decode(ret.as_slice()).unwrap();
            assert_eq!(backup_result.original, TEST_WIF);
        })
    }

    #[test]
    #[serial]
    pub fn test_backup_mnemonic() {
        run_test(|| {
            let param: ImportMnemonicParam = ImportMnemonicParam {
                password: TEST_PASSWORD.to_string(),
                mnemonic: TEST_MNEMONIC.to_string(),
                password_hint: "".to_string(),
                name: "".to_string(),
                network: "MAINNET".to_string(),
                overwrite: true,
            };
            let ret = call_api("import_mnemonic", param).unwrap();
            let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let ret = call_api("backup", param).unwrap();
            let export_result: BackupResult = BackupResult::decode(ret.as_slice()).unwrap();
            assert_eq!(export_result.original, TEST_MNEMONIC.to_string());

            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };

            let ret = call_api("get_derived_key", param).unwrap();
            let derived_key_result: DerivedKeyResult =
                DerivedKeyResult::decode(ret.as_slice()).unwrap();
            let param = WalletKeyParam {
                id: import_result.id.to_string(),
                key: Some(api::wallet_key_param::Key::DerivedKey(
                    derived_key_result.derived_key,
                )),
            };
            let ret = call_api("backup", param).unwrap();
            let export_result: BackupResult = BackupResult::decode(ret.as_slice()).unwrap();
            assert_eq!(export_result.original, TEST_MNEMONIC.to_string());
        })
    }

    #[bench]
    fn bench_import_mnemonic(b: &mut Bencher) {
        b.iter(|| {
            test_import_mnemonic();
        });
    }

    #[test]
    #[serial]
    pub fn test_ipfs_encrypt_and_decrypt() {
        run_test(|| {
            let wallet = import_default_wallet();

            let content = "imToken".to_string();
            let param = EncryptDataToIpfsParam {
                identifier: wallet.identifier.clone(),
                content: content.clone(),
            };
            let ret = call_api("encrypt_data_to_ipfs", param).unwrap();
            let resp: EncryptDataToIpfsResult =
                EncryptDataToIpfsResult::decode(ret.as_slice()).unwrap();
            assert!(!resp.encrypted.is_empty());
            let param = DecryptDataFromIpfsParam {
                identifier: wallet.identifier,
                encrypted: resp.encrypted,
            };
            let ret = call_api("decrypt_data_from_ipfs", param).unwrap();
            let resp: DecryptDataFromIpfsResult =
                DecryptDataFromIpfsResult::decode(ret.as_slice()).unwrap();
            assert_eq!(content, resp.content);
        })
    }

    #[test]
    #[serial]
    pub fn test_sign_authentication_message() {
        run_test(|| {
            let wallet = import_default_wallet();

            let param = SignAuthenticationMessageParam {
                access_time: 1514736000,
                identifier: wallet.identifier,
                device_token: "12345ABCDE".to_string(),
                key: Some(api::sign_authentication_message_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let ret = call_api("sign_authentication_message", param).unwrap();
            let resp: SignAuthenticationMessageResult =
                SignAuthenticationMessageResult::decode(ret.as_slice()).unwrap();
            assert_eq!(resp.signature, "0x120cc977f9023c90635144bd0f4c8b85ff8aa23c003edcced9449f0465d05e954bccf9c114484e472c1837b0394f1933ad78ec8050673099e8bf5e9329737fe01c".to_string());
        })
    }

    #[test]
    #[serial]
    pub fn test_get_extended_public_keys() {
        run_test(|| {
            let wallet = import_default_wallet();
            let derivations = vec![PublicKeyDerivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/44'/145'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
            }];
            let param = GetExtendedPublicKeysParam {
                id: wallet.id,
                derivations,
                key: Some(api::get_extended_public_keys_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            };
            let ret = call_api("get_extended_public_keys", param).unwrap();
            let resp: GetExtendedPublicKeysResult =
                GetExtendedPublicKeysResult::decode(ret.as_slice()).unwrap();
            assert_eq!(resp.extended_public_keys.get(0).unwrap(), "xpub6GZjFnyumLtEwC4KQkigvc3vXJdZvy71QxHTsFQQv1YtEUWNEwynKWsK2LBFZNLWdTk3w1Y9cRv4NN7V2pnDBoWgH3PkVE9r9Q2kSQL2zkH");
        })
    }

    #[test]
    #[serial]
    fn polkadotjs_cross_test() {
        run_test(|| {
            let param = ImportMnemonicParam {
                mnemonic: TEST_MNEMONIC.to_string(),
                password: TEST_PASSWORD.to_string(),
                network: "TESTNET".to_string(),
                name: "test-wallet".to_string(),
                password_hint: "imtoken".to_string(),
                overwrite: true,
            };
            let ret = import_mnemonic(&encode_message(param).unwrap()).unwrap();
            let wallet = KeystoreResult::decode(ret.as_slice()).unwrap();

            let derivations = vec![
                Derivation {
                    chain_type: "POLKADOT".to_string(),
                    path: "//imToken//polakdot/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "POLKADOT".to_string(),
                    path: "//imToken//polakdot/0/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "POLKADOT".to_string(),
                    path: "".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "KUSAMA".to_string(),
                    path: "//imToken//polakdot/0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "KUSAMA".to_string(),
                    path: "//imToken//polakdot/0//1".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "KUSAMA".to_string(),
                    path: "".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "KUSAMA".to_string(),
                    path: "//0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
                Derivation {
                    chain_type: "POLKADOT".to_string(),
                    path: "//0".to_string(),
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                    chain_id: "".to_string(),
                    curve: "sr25519".to_string(),
                    bech32_prefix: "".to_string(),
                },
            ];
            let param = DeriveAccountsParam {
                id: wallet.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations,
            };
            let expected = vec![
                "148fArFqHEtURxdvYAtLkSUkuHxqzPGsaC7Ro1zaUWFJ5dNF",
                "15YFBQp1kUWEXm22QXySuWyVZckk7QCZiuBfENLAfmbevstt",
                "16hsF1UW1kob7vUR7tymVNCmp1eo18uhhtc4szetH4xbYpbd",
                "FhygqLe3pdvk5SrMEePWF1cCGFS6kXux5Dh2PHBQDSGeJSW",
                "EkkpqYe4XGLst9o8NhvFRhMwto7MNxrsW9vboMzffdwUW3F",
                "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS",
                "JKZKcChQMRYd4zFdeSL5DX3EPNMtaLqAddnycJ4gEL2kJTK",
                "16kEod7tdmg6JxBKpagHKQzBwR5mnD5nnkXXkF1TkX94BooY",
            ];

            let ret = call_api("derive_accounts", param).unwrap();
            let result: DeriveAccountsResult =
                DeriveAccountsResult::decode(ret.as_slice()).unwrap();
            assert_eq!(result.accounts.len(), 8);
            for (index, account) in result.accounts.iter().enumerate() {
                assert_eq!(account.address, expected[index]);
            }
        })
    }
}
