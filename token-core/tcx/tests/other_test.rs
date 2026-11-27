use std::fs;

use common::run_test;
use serial_test::serial;

mod common;

use tcx::*;

use prost::Message;
use tcx::api::{
    DecryptDataFromIpfsParam, DecryptDataFromIpfsResult, DerivedKeyResult, EncryptDataToIpfsParam,
    EncryptDataToIpfsResult, ExistsKeystoreResult, ExistsMnemonicParam, ExistsPrivateKeyParam,
    GeneralResult, ImportPrivateKeyParam, KeystoreResult, SignAuthenticationMessageParam,
    SignAuthenticationMessageResult, WalletKeyParam,
};

use tcx::handler::{encode_message, get_derived_key, import_private_key};

use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};

use sp_core::ByteArray;

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
            overwrite_id: "".to_string(),
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
            overwrite_id: "".to_string(),
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

        let delete_param = WalletKeyParam {
            id: wallet.id.to_string(),
            key: Some(api::wallet_key_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        call_api("delete_keystore", delete_param).unwrap();
        // remove_created_wallet(&wallet.id);
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
            key: Some(api::encrypt_data_to_ipfs_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret = call_api("encrypt_data_to_ipfs", param).unwrap();
        let resp: EncryptDataToIpfsResult =
            EncryptDataToIpfsResult::decode(ret.as_slice()).unwrap();
        assert!(!resp.encrypted.is_empty());
        let param = DecryptDataFromIpfsParam {
            identifier: wallet.identifier,
            encrypted: resp.encrypted,
            key: Some(api::decrypt_data_from_ipfs_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret = call_api("decrypt_data_from_ipfs", param).unwrap();
        let resp: DecryptDataFromIpfsResult =
            DecryptDataFromIpfsResult::decode(ret.as_slice()).unwrap();
        assert_eq!(content, resp.content);
    })
}

#[test]
#[serial]
pub fn test_ipfs_encrypt_and_decrypt_before_migrate() {
    run_test(|| {
        fs::copy(
            "../test-data/wallets/identity.json",
            "/tmp/imtoken/wallets/identity.json",
        )
        .unwrap();
        let content = "imToken".to_string();
        let param = EncryptDataToIpfsParam {
            identifier: "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg".to_string(),
            content: content.clone(),
            key: Some(api::encrypt_data_to_ipfs_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let err = call_api("encrypt_data_to_ipfs", param).unwrap_err();
        assert_eq!(err.to_string(), "backup_security_migration_required");
        // identity.json alone also contains the encrypted mnemonic: the existing
        // migration API accepts its file stem and needs no other legacy wallet.
        let migrated = call_api(
            "migrate_keystore",
            api::MigrateKeystoreParam {
                id: "identity".into(),
                network: "TESTNET".into(),
                key: Some(api::migrate_keystore_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            },
        )
        .unwrap();
        let migrated = api::MigrateKeystoreResult::decode(migrated.as_slice())
            .unwrap()
            .keystore
            .unwrap();
        assert_eq!(
            migrated.identifier,
            "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg"
        );
        assert_eq!(
            migrated.ipfs_id,
            "QmSTTidyfa4np9ak9BZP38atuzkCHy4K59oif23f4dNAGU"
        );
        let decoded = call_api("decrypt_data_from_ipfs", DecryptDataFromIpfsParam {
            identifier: migrated.identifier,
            encrypted: "0340b2495a1111111111111111111111111111111110b6602c68084bdd08dae796657aa6854ad13312fedc88f5b6f16c56b3e755dde125a1c4775db536ac0442ac942f9634c777f3ae5ca39f6abcae4bd6c87e54ab29ae0062b04d917b32e8d7c88eeb6261301b".into(),
            key: Some(api::decrypt_data_from_ipfs_param::Key::Password(TEST_PASSWORD.to_owned())),
        }).unwrap();
        assert_eq!(
            DecryptDataFromIpfsResult::decode(decoded.as_slice())
                .unwrap()
                .content,
            "imToken"
        );
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
fn test_security_backup_credentials_and_legacy_migration() {
    run_test(|| {
        let id = "0a2756cd-ff70-437b-9bdb-ad46b8bb0819";
        fs::copy(
            format!("../test-data/wallets/{id}.json"),
            format!("/tmp/imtoken/wallets/{id}.json"),
        )
        .unwrap();
        let migrated = call_api(
            "migrate_keystore",
            api::MigrateKeystoreParam {
                id: id.to_owned(),
                network: "TESTNET".to_owned(),
                key: Some(api::migrate_keystore_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            },
        )
        .unwrap();
        let migrated = api::MigrateKeystoreResult::decode(migrated.as_slice())
            .unwrap()
            .keystore
            .unwrap();
        assert_eq!(
            migrated.identifier,
            "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg"
        );
        assert_eq!(
            migrated.ipfs_id,
            "QmSTTidyfa4np9ak9BZP38atuzkCHy4K59oif23f4dNAGU"
        );
        // Historical v3 vector encrypted before this migration.
        let legacy = "0340b2495a1111111111111111111111111111111110b6602c68084bdd08dae796657aa6854ad13312fedc88f5b6f16c56b3e755dde125a1c4775db536ac0442ac942f9634c777f3ae5ca39f6abcae4bd6c87e54ab29ae0062b04d917b32e8d7c88eeb6261301b";
        let request = |key| DecryptDataFromIpfsParam {
            identifier: migrated.identifier.clone(),
            encrypted: legacy.to_owned(),
            key,
        };
        assert_eq!(
            call_api("decrypt_data_from_ipfs", request(None))
                .unwrap_err()
                .to_string(),
            "missing_key"
        );
        assert_eq!(
            call_api(
                "decrypt_data_from_ipfs",
                request(Some(api::decrypt_data_from_ipfs_param::Key::Password(
                    "wrong".to_owned()
                )))
            )
            .unwrap_err()
            .to_string(),
            "password_incorrect"
        );
        let decoded = call_api(
            "decrypt_data_from_ipfs",
            request(Some(api::decrypt_data_from_ipfs_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            ))),
        )
        .unwrap();
        assert_eq!(
            DecryptDataFromIpfsResult::decode(decoded.as_slice())
                .unwrap()
                .content,
            "imToken"
        );
        let path = format!("/tmp/imtoken/walletsV2/{}.json", migrated.id);
        let saved = fs::read_to_string(path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(value["crypto"]["kdf"], "argon2id");
        assert!(value["identity"].get("encKey").is_none());
        let restored = tcx_keystore::Keystore::from_json(&saved).unwrap();
        let key = tcx_crypto::Key::Password(TEST_PASSWORD.to_owned());
        let unlocker = restored.store().crypto.use_key(&key).unwrap();
        assert_eq!(
            restored.identity().decrypt_ipfs(legacy, &unlocker).unwrap(),
            "imToken"
        );
        assert_eq!(restored.backup(&key).unwrap(), TEST_MNEMONIC);
        let encrypted = call_api(
            "encrypt_data_to_ipfs",
            EncryptDataToIpfsParam {
                identifier: migrated.identifier.clone(),
                content: "modern backup".into(),
                key: Some(api::encrypt_data_to_ipfs_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            },
        )
        .unwrap();
        let encrypted = EncryptDataToIpfsResult::decode(encrypted.as_slice()).unwrap();
        assert!(encrypted.encrypted.starts_with("04tcx-aead-v1:"));
        let upgraded = call_api(
            "upgrade_keystore_security",
            WalletKeyParam {
                id: migrated.id,
                key: Some(api::wallet_key_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
            },
        )
        .unwrap();
        assert!(
            GeneralResult::decode(upgraded.as_slice())
                .unwrap()
                .is_success
        );
    });
}
