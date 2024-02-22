use common::run_test;
use serial_test::serial;
use tcx::api::TcxAction;

mod common;
use api::sign_param::Key;
use error_handling::Result;
use std::ffi::{CStr, CString};
use std::fs::remove_file;
use std::os::raw::c_char;
use std::panic;
use std::path::Path;
use tcx::api::derive_accounts_param::Derivation;
use tcx::api::sign_hashes_param::DataToSign;
use tcx::filemanager::KEYSTORE_MAP;
use tcx::handler::scan_keystores;
use tcx::*;
use tcx_atom::transaction::{AtomTxInput, AtomTxOutput};
use tcx_common::ToHex;
use tcx_eth2::transaction::{SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult};
use tcx_keystore::keystore::IdentityNetwork;

use prost::Message;
use tcx::api::{
    export_mnemonic_param, export_private_key_param, migrate_keystore_param, sign_param,
    BackupResult, CreateKeystoreParam, DecryptDataFromIpfsParam, DecryptDataFromIpfsResult,
    DeriveAccountsParam, DeriveAccountsResult, DeriveSubAccountsParam, DeriveSubAccountsResult,
    DerivedKeyResult, EncryptDataToIpfsParam, EncryptDataToIpfsResult, ExistsJsonParam,
    ExistsKeystoreResult, ExistsMnemonicParam, ExistsPrivateKeyParam, ExportJsonParam,
    ExportJsonResult, ExportMnemonicParam, ExportMnemonicResult, ExportPrivateKeyParam,
    ExportPrivateKeyResult, GeneralResult, GetExtendedPublicKeysParam, GetExtendedPublicKeysResult,
    GetPublicKeysParam, GetPublicKeysResult, ImportJsonParam, ImportMnemonicParam,
    ImportPrivateKeyParam, ImportPrivateKeyResult, InitTokenCoreXParam, KeystoreResult,
    MigrateKeystoreParam, MigrateKeystoreResult, MnemonicToPublicKeyParam,
    MnemonicToPublicKeyResult, PublicKeyDerivation, SignAuthenticationMessageParam,
    SignAuthenticationMessageResult, SignHashesParam, SignHashesResult, SignParam, WalletKeyParam,
};
use tcx::handler::import_mnemonic;
use tcx::handler::{encode_message, get_derived_key, import_private_key};
use tcx_constants::{sample_key, CurveType, TEST_PRIVATE_KEY, TEST_WIF};
use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};
use tcx_keystore::Keystore;

use std::fs;
use tcx_btc_kin::transaction::BtcKinTxInput;

use sp_core::ByteArray;
use sp_runtime::traits::Verify;
use tcx_btc_kin::{OmniTxInput, Utxo};
use tcx_ckb::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};

use anyhow::anyhow;
use tcx_common::hex::FromHex;
use tcx_eth::transaction::{
    AccessList, EthMessageInput, EthMessageOutput, EthTxInput, EthTxOutput,
};
use tcx_filecoin::{SignedMessage, UnsignedMessage};
use tcx_substrate::{SubstrateKeystore, SubstrateRawTxIn, SubstrateTxOut};
use tcx_tezos::transaction::{TezosRawTxIn, TezosTxOut};
use tcx_tron::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};

use crate::common::*;

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
        let import_result: KeystoreResult = KeystoreResult::decode(ret_bytes.as_slice()).unwrap();
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
        let ret: ExistsKeystoreResult = ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();

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
        let import_result: KeystoreResult = KeystoreResult::decode(ret_bytes.as_slice()).unwrap();
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
        let ret: ExistsKeystoreResult = ExistsKeystoreResult::decode(ret_bytes.as_slice()).unwrap();

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
            mnemonic: format!(
                "{}",
                " inject  kidney  empty canal shadow  pact comfort  wife crush horse wife sketch  "
            )
            .to_string(), //Badly formatted mnemonic
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
