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
use tcx::handler::{encode_message, import_private_key};
use tcx_constants::{sample_key, CurveType, TEST_PRIVATE_KEY, TEST_WIF};
use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};
use tcx_keystore::Keystore;

use std::fs;
use tcx_btc_kin::transaction::BtcKinTxInput;

use sp_core::ByteArray;
use sp_runtime::traits::Verify;
use tcx_btc_kin::{OmniTxInput, Utxo};
use tcx_ckb::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};

use crate::common::*;
use anyhow::anyhow;
use tcx::handler::get_derived_key;
use tcx_common::hex::FromHex;
use tcx_eth::transaction::{
    AccessList, EthMessageInput, EthMessageOutput, EthTxInput, EthTxOutput,
};
use tcx_filecoin::{SignedMessage, UnsignedMessage};
use tcx_substrate::{SubstrateKeystore, SubstrateRawTxIn, SubstrateTxOut};
use tcx_tezos::transaction::{TezosRawTxIn, TezosTxOut};
use tcx_tron::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};

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
        let result: ExportMnemonicResult = ExportMnemonicResult::decode(ret.as_slice()).unwrap();

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
pub fn test_tezos_hd_private_key_export() {
    run_test(|| {
        let import_result = import_default_wallet();

        let derivations = vec![Derivation {
            chain_type: "TEZOS".to_string(),
            path: "m/44'/1729'/0'/0'".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "ed25519".to_string(),
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
            "tz1d2TfcvWBwtPqo7f21DVv7HSSCoNAVp8gz",
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
                "edskRjTYrWf4xZje3NbZ7WCYXwY4DqL4WwyYbbnv8opNa1tNHo9AcLaB6sV42uqeTohjzu5ohTTn9vQg5EJ4cDcTZTtrDi4Fxn"
            );
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
            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
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
                "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
                "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
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
                "b2a3f2ad9ea57b03aae9584a50b36e8b8f9ddfdc1b5c2ca26f90a041fb28f260",
                "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a222f5059574777574e577a58614d5675437a613958502b314b4a695a4474696f4c76777863754268783041553d227d",
                "7b2254797065223a22626c73222c22507269766174654b6579223a226e763064516a49635965556341682f6a792b6d7a77656a306c4a75495447504238433938766576713046513d227d",
                "cce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2",
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
        let ret = call_api("backup", param).unwrap();
        let export_result: BackupResult = BackupResult::decode(ret.as_slice()).unwrap();
        assert!(export_result
            .original
            .contains("0x6031564e7b2F5cc33737807b2E58DaFF870B590b"));
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
        let ret = call_api("backup", param).unwrap();
        let export_result: BackupResult = BackupResult::decode(ret.as_slice()).unwrap();
        assert!(export_result
            .original
            .contains("JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS"));
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
        let ret = call_api("backup", param.clone()).unwrap();
        let backup_result = BackupResult::decode(ret.as_slice()).unwrap();
        assert_eq!(backup_result.original, TEST_WIF);

        change_fingerprint_in_keystore(&import_result.id, &import_result.source_fingerprint);
        scan_keystores().unwrap();

        let ret = call_api("backup", param);
        assert_eq!(format!("{}", ret.err().unwrap()), "fingerprint_not_match");
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
        let ret = call_api("backup", param.clone()).unwrap();
        let export_result: BackupResult = BackupResult::decode(ret.as_slice()).unwrap();
        assert_eq!(export_result.original, TEST_MNEMONIC.to_string());

        change_fingerprint_in_keystore(&import_result.id, &import_result.source_fingerprint);
        scan_keystores().unwrap();

        let ret = call_api("backup", param);
        assert_eq!(format!("{}", ret.err().unwrap()), "fingerprint_not_match");
    })
}

fn change_fingerprint_in_keystore(id: &str, fingerprint: &str) {
    let file_path = format!("/tmp/imtoken/walletsV2/{}.json", id);
    let contents = fs::read_to_string(&file_path).unwrap();
    let new_contents = contents.replace(fingerprint, "0x00000000000000000000");
    fs::write(file_path, new_contents).expect("change fingerprint");
}
