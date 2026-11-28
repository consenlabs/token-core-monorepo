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
    SignAuthenticationMessageResult, SignTypedDataWithAuthKeyParam, SignTypedDataWithAuthKeyResult,
    WalletKeyParam,
};

use tcx::handler::{encode_message, get_derived_key, import_private_key};

use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};

use sp_core::ByteArray;

use crate::common::*;

fn stake_typed_data(identifier: &str) -> String {
    format!(
        r#"{{
          "types": {{
            "EIP712Domain": [
              {{ "name": "name", "type": "string" }},
              {{ "name": "version", "type": "string" }},
              {{ "name": "chainId", "type": "uint256" }},
              {{ "name": "verifyingContract", "type": "address" }}
            ],
            "BindStakeXpub": [
              {{ "name": "identifier", "type": "string" }},
              {{ "name": "xpub", "type": "string" }},
              {{ "name": "purpose", "type": "string" }},
              {{ "name": "nonce", "type": "string" }},
              {{ "name": "expiration", "type": "uint256" }},
              {{ "name": "network", "type": "string" }}
            ]
          }},
          "primaryType": "BindStakeXpub",
          "domain": {{
            "name": "imToken Stake",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0x0000000000000000000000000000000000000000"
          }},
          "message": {{
            "identifier": "{}",
            "xpub": "xpub-test-value",
            "purpose": "bind_stake_xpub",
            "nonce": "nonce-1",
            "expiration": 1893456000,
            "network": "ethereum-mainnet"
          }}
        }}"#,
        identifier
    )
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

#[test]
#[serial]
pub fn test_sign_typed_data_with_auth_key_by_password() {
    run_test(|| {
        let wallet = import_default_wallet();

        let param = SignTypedDataWithAuthKeyParam {
            identifier: wallet.identifier.clone(),
            typed_data: stake_typed_data(&wallet.identifier),
            key: Some(api::sign_typed_data_with_auth_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret = call_api("sign_typed_data_with_auth_key", param).unwrap();
        let resp: SignTypedDataWithAuthKeyResult =
            SignTypedDataWithAuthKeyResult::decode(ret.as_slice()).unwrap();

        assert_eq!(resp.identifier, wallet.identifier);
        assert_eq!(
            resp.signature,
            "0x53ef27314951ae39fcb43b4970241cad83f43c9a4f1350597d63c4fe4dca3d6a2c835831a0dcc167c0b9d6ee30f48593868c06397b3cf4e644bccc90307e7fcc1b"
        );
    })
}

#[test]
#[serial]
pub fn test_sign_typed_data_with_auth_key_by_derived_key() {
    run_test(|| {
        let wallet = import_default_wallet();
        let typed_data = stake_typed_data(&wallet.identifier);

        let dk_param = WalletKeyParam {
            id: wallet.id.to_string(),
            key: Some(api::wallet_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret_bytes = get_derived_key(&encode_message(dk_param).unwrap()).unwrap();
        let derived_key_result: DerivedKeyResult =
            DerivedKeyResult::decode(ret_bytes.as_slice()).unwrap();

        let password_param = SignTypedDataWithAuthKeyParam {
            identifier: wallet.identifier.clone(),
            typed_data: typed_data.clone(),
            key: Some(api::sign_typed_data_with_auth_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let password_ret = call_api("sign_typed_data_with_auth_key", password_param).unwrap();
        let password_resp: SignTypedDataWithAuthKeyResult =
            SignTypedDataWithAuthKeyResult::decode(password_ret.as_slice()).unwrap();

        let derived_key_param = SignTypedDataWithAuthKeyParam {
            identifier: wallet.identifier,
            typed_data,
            key: Some(api::sign_typed_data_with_auth_key_param::Key::DerivedKey(
                derived_key_result.derived_key,
            )),
        };
        let derived_key_ret = call_api("sign_typed_data_with_auth_key", derived_key_param).unwrap();
        let derived_key_resp: SignTypedDataWithAuthKeyResult =
            SignTypedDataWithAuthKeyResult::decode(derived_key_ret.as_slice()).unwrap();

        assert_eq!(password_resp.signature, derived_key_resp.signature);
    })
}

#[test]
#[serial]
pub fn test_sign_typed_data_with_auth_key_identity_not_found() {
    run_test(|| {
        let param = SignTypedDataWithAuthKeyParam {
            identifier: "im-not-found".to_string(),
            typed_data: stake_typed_data("im-not-found"),
            key: Some(api::sign_typed_data_with_auth_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret = call_api("sign_typed_data_with_auth_key", param);
        assert_eq!(ret.unwrap_err().to_string(), "identity_not_found");
    })
}

#[test]
#[serial]
pub fn test_sign_typed_data_with_auth_key_malformed_typed_data() {
    run_test(|| {
        let wallet = import_default_wallet();

        let param = SignTypedDataWithAuthKeyParam {
            identifier: wallet.identifier,
            typed_data: "{".to_string(),
            key: Some(api::sign_typed_data_with_auth_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret = call_api("sign_typed_data_with_auth_key", param);
        assert!(ret
            .unwrap_err()
            .to_string()
            .starts_with("invalid_typed_data_json:"));
    })
}

#[test]
#[serial]
pub fn test_sign_typed_data_with_auth_key_invalid_typed_data() {
    run_test(|| {
        let wallet = import_default_wallet();

        let param = SignTypedDataWithAuthKeyParam {
            identifier: wallet.identifier,
            typed_data: r#"{
              "types": { "EIP712Domain": [] },
              "primaryType": "MissingType",
              "domain": {},
              "message": {}
            }"#
            .to_string(),
            key: Some(api::sign_typed_data_with_auth_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret = call_api("sign_typed_data_with_auth_key", param);
        assert!(ret
            .unwrap_err()
            .to_string()
            .starts_with("invalid_typed_data:"));
    })
}

#[test]
#[serial]
pub fn test_sign_typed_data_with_auth_key_missing_key() {
    run_test(|| {
        let wallet = import_default_wallet();

        let param = SignTypedDataWithAuthKeyParam {
            identifier: wallet.identifier.clone(),
            typed_data: stake_typed_data(&wallet.identifier),
            key: None,
        };
        let ret = call_api("sign_typed_data_with_auth_key", param);
        assert_eq!(ret.unwrap_err().to_string(), "need_password_or_derived_key");
    })
}
