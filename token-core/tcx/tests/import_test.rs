use common::run_test;
use serial_test::serial;

mod common;

use tcx::api::derive_accounts_param::Derivation;

use tcx::*;

use tcx_keystore::keystore::IdentityNetwork;

use prost::Message;
use tcx::api::{
    export_private_key_param, CreateKeystoreParam, DeriveAccountsParam, DeriveAccountsResult,
    ExistsJsonParam, ExistsKeystoreResult, ExistsPrivateKeyParam, ExportJsonParam,
    ExportJsonResult, ExportPrivateKeyParam, ExportPrivateKeyResult, ImportJsonParam,
    ImportMnemonicParam, ImportPrivateKeyParam, ImportPrivateKeyResult, KeystoreResult,
};

use tcx::handler::{encode_message, import_private_key};
use tcx_constants::TEST_PASSWORD;
use tcx_constants::{CurveType, TEST_PRIVATE_KEY, TEST_WIF};

use sp_core::ByteArray;

use tcx_substrate::SubstrateKeystore;

use crate::common::*;
use tcx::handler::derive_accounts;

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
        let result: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();
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
        let result: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();
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
            let pk_import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

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
        let ret: DeriveAccountsResult = DeriveAccountsResult::decode(ret_bytes.as_slice()).unwrap();
        assert_eq!(
            "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r",
            ret.accounts.first().unwrap().address
        );
        remove_created_wallet(&wallet.id);
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
        let accounts: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

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
        let accounts: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

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
        let accounts: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

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
            curve: "secp256k1".to_string(),
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
        assert_eq!(
            format!("{}", ret.err().unwrap()),
            "private_key_curve_not_match"
        );

        remove_created_wallet(&wallet_ret.id);
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
