use std::fs;

use common::run_test;
use serial_test::serial;

mod common;

use tcx::*;

use prost::Message;
#[cfg(feature = "cache_dk")]
use tcx::api::DerivedKeyResult;
use tcx::api::{
    DecryptDataFromIpfsParam, DecryptDataFromIpfsResult, EncryptDataToIpfsParam,
    EncryptDataToIpfsResult, ExistsKeystoreResult, ExistsMnemonicParam, ExistsPrivateKeyParam,
    GeneralResult, ImportPrivateKeyParam, KeystoreResult, SignAuthenticationMessageParam,
    SignAuthenticationMessageResult, WalletKeyParam,
};

#[cfg(feature = "cache_dk")]
use tcx::handler::get_derived_key;
use tcx::handler::{encode_message, import_private_key};

use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};

use crate::common::*;

#[test]
#[serial]
pub fn test_kdf_api_formats_and_feature_gates() {
    run_test(|| {
        let hd_id = import_default_wallet().id;
        let pk_id = import_default_pk_store().id;
        for id in [hd_id, pk_id.clone()] {
            let map = tcx::filemanager::KEYSTORE_MAP.read();
            let crypto = &map.get(&id).unwrap().store().crypto;
            let json = serde_json::to_value(crypto).unwrap();
            assert_eq!(json["kdf"], "argon2id");
            assert_eq!(json["kdfparams"]["dklen"], 64);
            drop(map);

            let param = WalletKeyParam {
                id,
                key: Some(api::wallet_key_param::Key::Password(TEST_PASSWORD.into())),
            };
            let result = call_api("verify_password", param.clone()).unwrap();
            assert!(GeneralResult::decode(result.as_slice()).unwrap().is_success);
            let result = call_api("get_derived_key", param.clone());
            #[cfg(feature = "cache_dk")]
            {
                let result = DerivedKeyResult::decode(result.unwrap().as_slice()).unwrap();
                assert_eq!(result.derived_key.len(), 128);
                let mut cached = param.clone();
                cached.key = Some(api::wallet_key_param::Key::DerivedKey(result.derived_key));
                let result = call_api("verify_password", cached).unwrap();
                assert!(GeneralResult::decode(result.as_slice()).unwrap().is_success);
            }
            #[cfg(not(feature = "cache_dk"))]
            assert_eq!(result.unwrap_err().to_string(), "unsupported_method");

            let mut wrong = param;
            wrong.key = Some(api::wallet_key_param::Key::Password("wrong".into()));
            assert_eq!(
                call_api("verify_password", wrong).unwrap_err().to_string(),
                "password_incorrect"
            );
        }

        // Check the test-only route without reaching its deliberate panic.
        let result = call_api(
            "unlock_then_crash",
            WalletKeyParam {
                id: "missing-kdf-test-wallet".into(),
                key: Some(api::wallet_key_param::Key::Password(TEST_PASSWORD.into())),
            },
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            if cfg!(feature = "test_api") {
                "wallet_not_found"
            } else {
                "unsupported_method"
            }
        );

        let result = call_api(
            "export_json",
            api::ExportJsonParam {
                id: pk_id.clone(),
                password: TEST_PASSWORD.into(),
                chain_type: "ETHEREUM".into(),
                path: "".into(),
            },
        )
        .unwrap();
        let result = api::ExportJsonResult::decode(result.as_slice()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        assert_eq!(json["version"], 3);
        assert_eq!(json["crypto"]["kdf"], "pbkdf2");
        assert_eq!(json["crypto"]["kdfparams"]["dklen"], 32);
        assert_eq!(json["crypto"]["kdfparams"]["prf"], "hmac-sha256");
        let legacy = tcx_migration::migration::LegacyKeystore::from_json_str(&result.json).unwrap();
        legacy.validate_v3(TEST_PASSWORD).unwrap();

        // Preserve the public Rust constructor signature across crate boundaries.
        let constructor: fn(&str, &[u8], tcx_crypto::crypto::KdfType) -> tcx_crypto::Crypto =
            tcx_crypto::Crypto::new_with_kdf;
        let kdf = serde_json::from_value(serde_json::json!({
            "kdf": "argon2id", "kdfparams": {
                "memoryCost": 32, "timeCost": 2, "parallelism": 1, "dklen": 32,
                "salt": "01020304010203040102030401020304",
            },
        }))
        .unwrap();
        let crypto = constructor(TEST_PASSWORD, b"TokenCoreX", kdf);
        let expected_dk = "d956f86a8815a4ee7eacd92712ed85b204d935c81a216bdd9a88863522045f88";
        assert_eq!(
            crypto
                .use_key(&tcx_crypto::Key::DerivedKey(expected_dk.into()))
                .unwrap()
                .plaintext()
                .unwrap(),
            b"TokenCoreX"
        );

        // Only the crypto body is relevant to password/cache API contracts.
        tcx::filemanager::KEYSTORE_MAP
            .write()
            .get_mut(&pk_id)
            .unwrap()
            .store_mut()
            .crypto = crypto;
        let param = WalletKeyParam {
            id: pk_id,
            key: Some(api::wallet_key_param::Key::Password(TEST_PASSWORD.into())),
        };
        let result = call_api("verify_password", param.clone()).unwrap();
        assert!(GeneralResult::decode(result.as_slice()).unwrap().is_success);
        let result = call_api("get_derived_key", param.clone());
        #[cfg(feature = "cache_dk")]
        {
            let result = DerivedKeyResult::decode(result.unwrap().as_slice()).unwrap();
            assert_eq!(result.derived_key, expected_dk); // 32 bytes, never padded to 64
        }
        #[cfg(not(feature = "cache_dk"))]
        assert_eq!(result.unwrap_err().to_string(), "unsupported_method");
        let mut cached = param;
        cached.key = Some(api::wallet_key_param::Key::DerivedKey(expected_dk.into()));
        let result = call_api("verify_password", cached).unwrap();
        assert!(GeneralResult::decode(result.as_slice()).unwrap().is_success);
    });
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
#[cfg(not(feature = "cache_dk"))]
pub fn test_get_derived_key_is_not_in_default_api_table() {
    run_test(|| {
        let wallet = import_default_wallet();
        let param = WalletKeyParam {
            id: wallet.id,
            key: Some(api::wallet_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };

        let ret = call_api("get_derived_key", param);
        assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_method");
    })
}

#[test]
#[serial]
#[cfg(not(feature = "test_api"))]
pub fn test_unlock_then_crash_is_not_in_default_api_table() {
    run_test(|| {
        let wallet = import_default_wallet();
        let param = WalletKeyParam {
            id: wallet.id,
            key: Some(api::wallet_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };

        let ret = call_api("unlock_then_crash", param);
        assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_method");
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
#[cfg(feature = "cache_dk")]
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
        };
        let ret = call_api("encrypt_data_to_ipfs", param).unwrap();
        let resp: EncryptDataToIpfsResult =
            EncryptDataToIpfsResult::decode(ret.as_slice()).unwrap();
        assert!(!resp.encrypted.is_empty());
        let param = DecryptDataFromIpfsParam {
            identifier: "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg".to_string(),
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
