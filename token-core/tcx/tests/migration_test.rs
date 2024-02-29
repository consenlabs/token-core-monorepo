use serial_test::serial;

mod common;
use api::sign_param::Key;

use tcx::filemanager::{KEYSTORE_MAP, LEGACY_WALLET_FILE_DIR};

use tcx::*;
use tcx_atom::transaction::{AtomTxInput, AtomTxOutput};

use prost::Message;
use tcx::api::{
    export_mnemonic_param, migrate_keystore_param, wallet_key_param, ExportMnemonicParam,
    ExportMnemonicResult, MigrateKeystoreParam, MigrateKeystoreResult, SignParam, WalletKeyParam,
};

use tcx::handler::encode_message;
use tcx_constants::CurveType;
use tcx_constants::{OTHER_MNEMONIC, TEST_PASSWORD};
use tcx_keystore::Keystore;

use anyhow::{anyhow, format_err};
use std::fs;
use std::path::Path;

use sp_core::ByteArray;

use crate::common::*;

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
        assert!(json.contains("9b62a4c07c96ca9b0b82b5b5eae4e7c9b2b7db531a6d2991198eb6809a8c35ac"));
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

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    if src.is_dir() {
        fs::create_dir_all(dst)?; // Create destination directory if it doesn't exist
        for entry in src.read_dir()? {
            let entry = entry?;
            let path = entry.path();
            let new_dest = dst.join(path.strip_prefix(src)?);
            if path.is_dir() {
                copy_dir(&path, &new_dest)?; // Recursively copy subdirectories
            } else {
                fs::copy(&path, &new_dest)?; // Copy files
            }
        }
    } else {
        return Err(anyhow!("source is not a directory"));
    }
    Ok(())
}

fn setup_test(old_wallet_dir: &str) {
    let _ = fs::remove_dir_all("/tmp/token-core-x");
    copy_dir(&Path::new(old_wallet_dir), &Path::new("/tmp/token-core-x")).unwrap();

    init_token_core_x("/tmp/token-core-x");
}

#[test]
#[serial]
fn test_migrate_duplicate_then_delete_keystore() {
    setup_test("../test-data/migrate-duplication-fixtures");
    let param = MigrateKeystoreParam {
        id: "300b42bc-0948-4734-82cb-4293dfeeefd2".to_string(),
        key: Some(migrate_keystore_param::Key::Password(
            TEST_PASSWORD.to_string(),
        )),
    };
    call_api("migrate_keystore", param).unwrap();
    let param = ExportMnemonicParam {
        id: "300b42bc-0948-4734-82cb-4293dfeeefd2".to_string(),
        key: Some(export_mnemonic_param::Key::Password(
            TEST_PASSWORD.to_string(),
        )),
    };
    let ret = call_api("export_mnemonic", param).unwrap();
    let exported = ExportMnemonicResult::decode(ret.as_slice())
        .unwrap()
        .mnemonic;
    assert_eq!(OTHER_MNEMONIC, exported);
    // CKB imported 300b42bc-0948-4734-82cb-4293dfeeefd2
    // 9b696367-69c1-4cfe-8325-e5530399fc3f
    let param = MigrateKeystoreParam {
        id: "9b696367-69c1-4cfe-8325-e5530399fc3f".to_string(),
        key: Some(migrate_keystore_param::Key::Password(
            TEST_PASSWORD.to_string(),
        )),
    };
    call_api("migrate_keystore", param).unwrap();
    let param = ExportMnemonicParam {
        id: "9b696367-69c1-4cfe-8325-e5530399fc3f".to_string(),
        key: Some(export_mnemonic_param::Key::Password(
            TEST_PASSWORD.to_string(),
        )),
    };
    let ret = call_api("export_mnemonic", param).unwrap();
    let exported = ExportMnemonicResult::decode(ret.as_slice())
        .unwrap()
        .mnemonic;
    assert_eq!(OTHER_MNEMONIC, exported);

    let raw_data = "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201".to_string();
    let input = AtomTxInput { raw_data };
    let input_value = encode_message(input).unwrap();

    let tx = SignParam {
        id: "9b696367-69c1-4cfe-8325-e5530399fc3f".to_string(),
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
    let expected_sig =
        "3/FXveMRWVXcdJRSaz1hBbEReka2/vXqAoHlj1L1jl9y0worNAjEqo3Y9CWx8ddl9qKwghWBRQ70mJDNsXnoJQ==";
    assert_eq!(expected_sig, output.signature);

    let param = WalletKeyParam {
        id: "300b42bc-0948-4734-82cb-4293dfeeefd2".to_string(),
        key: Some(wallet_key_param::Key::Password(TEST_PASSWORD.to_string())),
    };
    let ret = call_api("delete_keystore", param).unwrap();

    assert_eq!(
        Path::new("/tmp/token-core-x/wallets/300b42bc-0948-4734-82cb-4293dfeeefd2.json").exists(),
        false
    );
    assert_eq!(
        Path::new("/tmp/token-core-x/wallets/9b696367-69c1-4cfe-8325-e5530399fc3f").exists(),
        false
    );
    assert_eq!(
        Path::new("/tmp/token-core-x/wallets/_migrated").exists(),
        false
    );
}
