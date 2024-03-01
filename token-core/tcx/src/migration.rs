use crate::api::{
    migrate_keystore_param, AccountResponse, KeystoreResult, LegacyKeystoreResult,
    MigrateKeystoreParam, MigrateKeystoreResult, ScanLegacyKeystoresResult,
};
use crate::error_handling::Result;
use crate::filemanager::{cache_keystore, KEYSTORE_MAP};
use crate::filemanager::{flush_keystore, LEGACY_WALLET_FILE_DIR};
use crate::handler::{encode_message, encrypt_xpub};
use anyhow::anyhow;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use tcx_common::{FromHex, ToHex};
use tcx_constants::coin_info::get_xpub_prefix;
use tcx_keystore::keystore::IdentityNetwork;
use tcx_keystore::Keystore;
use tcx_keystore::Metadata;
use tcx_migration::keystore_upgrade::{mapping_curve_name, KeystoreUpgrade};
use tcx_migration::migration::{LegacyKeystore, NumberOrNumberStr};
use tcx_primitive::{Bip32DeterministicPublicKey, Ss58Codec};

fn read_migrated_map() -> (String, HashMap<String, Vec<String>>) {
    let legacy_file_dir = {
        let dir = LEGACY_WALLET_FILE_DIR.read();
        dir.to_string()
    };

    let migrated_file = format!("{}/_migrated.json", legacy_file_dir);
    let map = if let Ok(json_str) = fs::read_to_string(&migrated_file) {
        serde_json::from_str::<HashMap<String, Vec<String>>>(&json_str).unwrap_or(HashMap::new())
    } else {
        HashMap::new()
    };

    (migrated_file, map)
}

pub fn remove_old_keystore_by_id(id: &str) {
    let legacy_file_dir = {
        let dir = LEGACY_WALLET_FILE_DIR.read();
        dir.to_string()
    };

    let result = read_migrated_map();

    let migrated_file = result.0;
    let mut map = result.1;

    if let Some(files) = map.get(id) {
        for file_id in files.iter() {
            let mut file_path = format!("{}/{}.json", legacy_file_dir, file_id);
            if !Path::new(&file_path).exists() {
                file_path = format!("{}/{}", legacy_file_dir, file_id);
            }

            if Path::new(&file_path).exists() {
                fs::remove_file(&file_path);
            }
        }
    }

    map.remove(id);

    if !map.is_empty() {
        let json_str = serde_json::to_string(&map).unwrap();
        fs::write(&migrated_file, json_str);
    } else {
        fs::remove_file(&migrated_file);
    }
}

fn mark_keystore_as_migrated(legacy_file_id: &str, migrated_file_id: &str) {
    let result = read_migrated_map();
    let mut map: HashMap<String, Vec<String>> = result.1;
    let migrated_file = result.0;

    let file_ids = map.entry(migrated_file_id.to_string()).or_insert(vec![]);
    if file_ids.contains(&legacy_file_id.to_string()) {
        return;
    }

    file_ids.push(legacy_file_id.to_string());

    let json_str = serde_json::to_string(&map).unwrap();
    fs::write(&migrated_file, json_str).expect("write migrated.json");
}

pub(crate) fn migrate_keystore(data: &[u8]) -> Result<Vec<u8>> {
    let param: MigrateKeystoreParam =
        MigrateKeystoreParam::decode(data).expect("param: MigrateKeystoreParam");
    let legacy_file_dir = {
        let dir = LEGACY_WALLET_FILE_DIR.read();
        dir.to_string()
    };
    let mut file_path = format!("{}/{}.json", legacy_file_dir, param.id);
    let path = Path::new(&file_path);
    if !path.exists() {
        file_path = format!("{}/{}", legacy_file_dir, param.id);
    }
    let json_str = fs::read_to_string(file_path)?;
    let json = serde_json::from_str::<Value>(&json_str)?;

    let key = match param.key.clone().unwrap() {
        migrate_keystore_param::Key::Password(password) => tcx_crypto::Key::Password(password),
        migrate_keystore_param::Key::DerivedKey(derived_key) => {
            tcx_crypto::Key::DerivedKey(derived_key)
        }
    };

    let keystore;

    if let Some(version) = json["version"].as_i64() {
        let network = IdentityNetwork::from_str(&param.network.to_uppercase())?;
        match version {
            11000 | 11001 => {
                let keystore_upgrade = KeystoreUpgrade::new(json);
                keystore = keystore_upgrade.upgrade(&key, &network)?;
            }
            _ => {
                let legacy_keystore = LegacyKeystore::from_json_str(&json_str)?;
                keystore = legacy_keystore.migrate(&key, &network)?;
            }
        }
        let id = param.id.clone();
        let mut is_existed = false;
        let mut existed_id = "".to_string();
        let fingerprint = keystore.fingerprint();
        {
            let mut keystore_map = KEYSTORE_MAP.write();
            let existed_ks: Vec<&Keystore> = keystore_map
                .values()
                .filter(|ks| ks.fingerprint() == fingerprint)
                .collect();
            if existed_ks.len() > 0 {
                is_existed = true;
                existed_id = existed_ks[0].id().to_string();
                // Note: Temporary retention of the old ID,
                // so that users can continue to use the old ID for subsequent operations.
                keystore_map.insert(param.id, keystore.clone());
            }
        }

        if is_existed {
            mark_keystore_as_migrated(&id, &existed_id);

            return encode_message(MigrateKeystoreResult {
                is_existed: true,
                existed_id,
                keystore: None,
            });
        } else {
            mark_keystore_as_migrated(&id, &keystore.id());

            let identity = keystore.identity();

            let keystore_result = KeystoreResult {
                id: keystore.id(),
                name: keystore.meta().name,
                source: keystore.meta().source.to_string(),
                created_at: keystore.meta().timestamp,
                identifier: identity.identifier.to_string(),
                ipfs_id: identity.ipfs_id.to_string(),
                source_fingerprint: keystore.fingerprint().to_string(),
            };

            let ret = encode_message(MigrateKeystoreResult {
                is_existed: false,
                existed_id: "".to_string(),
                keystore: Some(keystore_result),
            });
            flush_keystore(&keystore)?;
            cache_keystore(keystore);
            return ret;
        }
    } else {
        Err(anyhow!("unknown_version_when_upgrade_keystore"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyAccount {
    pub address: String,
    pub derivation_path: String,
    pub curve: String,
    pub coin: String,
    pub network: String,
    pub seg_wit: String,
    pub ext_pub_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

pub(crate) fn scan_legacy_keystores() -> Result<ScanLegacyKeystoresResult> {
    let file_dir = LEGACY_WALLET_FILE_DIR.read();
    let p = Path::new(file_dir.as_str());
    let walk_dir = std::fs::read_dir(p).expect("read dir");

    let mut keystores: Vec<LegacyKeystoreResult> = Vec::new();
    let mut result = ScanLegacyKeystoresResult::default();

    for entry in walk_dir {
        let entry = entry.expect("DirEntry");
        let fp = entry.path();

        let mut f = fs::File::open(fp).expect("open file");

        let mut contents = String::new();
        let read_ret = f.read_to_string(&mut contents);
        if read_ret.is_err() {
            // imkey directory
            continue;
        }

        let v_result = serde_json::from_str::<Value>(&contents);
        let Ok(v) = v_result  else {
            continue;
        };

        let version = v["version"].as_i64().expect("version");

        if version == 11000 || version == 11001 {
            // let keystore = Keystore::from_json(&contents)?;
            let keystore_result = parse_tcx_keystore(&v)?;
            keystores.push(keystore_result);
        } else if version == 44 || version == 3 || version == 10001 {
            let keystore_result = parse_legacy_kesytore(contents)?;
            keystores.push(keystore_result);
        } else if version == 10000 {
            parse_identity_keystore(&mut result, v);
        }
    }
    result.keystores = keystores;
    Ok(result)
}

fn parse_identity_keystore(result: &mut ScanLegacyKeystoresResult, v: Value) {
    result.identifier = v["identifier"].as_str().unwrap_or("").to_string();

    result.ipfs_id = v["ipfsId"].as_str().unwrap_or("").to_string();
    result.network = v["imTokenMeta"]["network"]
        .as_str()
        .expect("identity.json network")
        .to_string();
    result.source = v["imTokenMeta"]["source"]
        .as_str()
        .expect("identity.json source")
        .to_string();
}

fn parse_legacy_kesytore(contents: String) -> Result<LegacyKeystoreResult> {
    let legacy_keystore = LegacyKeystore::from_json_str(&contents)?;
    let meta = legacy_keystore
        .im_token_meta
        .expect("imToken keystore need meta");
    let chain_type = if let Some(chain_type) = meta.chain_type {
        chain_type
    } else {
        meta.chain.unwrap()
    };
    let seg_wit = if let Some(seg_wit) = meta.seg_wit {
        seg_wit
    } else {
        "NONE".to_string()
    };
    let path = if let Some(path) = legacy_keystore.mnemonic_path {
        if !path.is_empty() && chain_type.eq("BITCOIN") {
            format!("{}/0/0", path)
        } else {
            path
        }
    } else {
        "".to_string()
    };
    let (extended_public_key, encrypted_extended_public_key) =
        if let Some(xpub) = legacy_keystore.xpub {
            if let Ok(ext_pub_key) = Bip32DeterministicPublicKey::from_ss58check(&xpub) {
                let ext_pub_key_hex = ext_pub_key.to_hex();
                let enc_ext_pub_key = encrypt_xpub(&ext_pub_key_hex).unwrap_or("".to_string());
                (xpub, enc_ext_pub_key)
            } else {
                ("".to_string(), "".to_string())
            }
        } else {
            ("".to_string(), "".to_string())
        };
    let public_key = if let Some(key_paths) = legacy_keystore.key_path_privates {
        key_paths
            .iter()
            .find(|x| x.derived_mode == "PATH_DIRECTLY")
            .map(|x| x.public_key.clone())
            .unwrap_or_default()
    } else {
        "".to_string()
    };
    let account = AccountResponse {
        chain_type,
        address: legacy_keystore.address.expect("legacy address"),
        path,
        curve: "secp256k1".to_string(),
        public_key,
        extended_public_key,
        encrypted_extended_public_key,
        seg_wit,
    };
    let created_at = match meta.timestamp.clone() {
        NumberOrNumberStr::Number(t) => t,
        NumberOrNumberStr::NumberStr(t) => f64::from_str(&t).expect("f64 from timestamp") as i64,
    };
    let keystore_result = LegacyKeystoreResult {
        id: legacy_keystore.id.to_string(),
        name: meta.name.to_string(),
        source: meta.source.as_ref().unwrap_or(&"".to_string()).to_string(),
        created_at,
        accounts: vec![account],
    };
    Ok(keystore_result)
}

fn parse_tcx_keystore(v: &Value) -> Result<LegacyKeystoreResult> {
    let legacy_accounts: Vec<LegacyAccount> = serde_json::from_value(v["activeAccounts"].clone())
        .ok()
        .unwrap_or(vec![]);
    let mut account_responses: Vec<AccountResponse> = vec![];
    for legacy_account in legacy_accounts.iter() {
        let public_key = if let Some(public_key) = &legacy_account.public_key {
            public_key.to_string()
        } else {
            "".to_string()
        };

        let (extended_public_key, encrypted_extended_public_key) = if !legacy_account
            .ext_pub_key
            .is_empty()
        {
            let Ok(hd_key) = Bip32DeterministicPublicKey::from_hex_auto(&legacy_account.ext_pub_key) else {
                    continue;
                };
            let xpub_prefix = get_xpub_prefix(&legacy_account.network);
            let extended_public_key = hd_key.to_ss58check_with_version(&xpub_prefix);

            (
                extended_public_key,
                encrypt_xpub(&legacy_account.ext_pub_key).unwrap_or("".to_string()),
            )
        } else {
            ("".to_string(), "".to_string())
        };

        account_responses.push(AccountResponse {
            chain_type: legacy_account.coin.to_string(),
            address: legacy_account.address.to_string(),
            path: legacy_account.derivation_path.to_string(),
            curve: mapping_curve_name(legacy_account.curve.as_str()).to_string(),
            public_key,
            extended_public_key,
            encrypted_extended_public_key,
            seg_wit: legacy_account.seg_wit.to_string(),
        })
    }
    let id = v["id"].as_str().expect("keystore id").to_string();
    let meta: Metadata = serde_json::from_value(v["imTokenMeta"].clone())?;
    let keystore_result = LegacyKeystoreResult {
        id,
        name: meta.name.to_string(),
        source: meta.source.to_string(),
        created_at: meta.timestamp,
        accounts: account_responses,
    };
    Ok(keystore_result)
}

fn read_identity_network() -> Result<IdentityNetwork> {
    let dir = LEGACY_WALLET_FILE_DIR.read();
    let identify_path = format!("{}/identity.json", dir);
    let mut identify_file = fs::File::open(&identify_path)?;

    let mut json_str = String::new();
    identify_file.read_to_string(&mut json_str)?;
    let json: Value = serde_json::from_str(&json_str)?;
    let network = json["imTokenMeta"]["network"]
        .as_str()
        .expect("network")
        .to_string();
    IdentityNetwork::from_str(&network)
}

#[cfg(test)]
mod tests {
    use crate::{filemanager::LEGACY_WALLET_FILE_DIR, migration::scan_legacy_keystores};
    use serial_test::serial;
    use tcx_keystore::keystore::IdentityNetwork;

    use super::read_identity_network;

    #[test]
    #[serial]

    fn test_scan_tcx_legacy_keystores() {
        *LEGACY_WALLET_FILE_DIR.write() = "../test-data/wallets-ios-2_14_1/".to_string();
        let result = scan_legacy_keystores().unwrap();

        assert_eq!(result.identifier, "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg");

        assert_eq!(
            result.ipfs_id,
            "QmSTTidyfa4np9ak9BZP38atuzkCHy4K59oif23f4dNAGU"
        );

        let keystore = result
            .keystores
            .iter()
            .find(|x| x.id.eq("0a2756cd-ff70-437b-9bdb-ad46b8bb0819"))
            .clone()
            .unwrap();
        assert_eq!(keystore.id, "0a2756cd-ff70-437b-9bdb-ad46b8bb0819");
        let account = keystore.accounts.first().unwrap();
        assert_eq!(account.address, "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2");
        assert_eq!(account.chain_type, "TRON");
        assert_eq!(account.path, "m/44'/195'/0'/0/0");
        assert_eq!(account.curve, "secp256k1");
        assert_eq!(
            account.public_key,
            "037b5253c24ce2a293566f9e066051366cda5073e4a43b25f07c990d7c9ac0aab5"
        );
        assert_eq!(account.extended_public_key, "tpubDCxD6k9PreNhSacpfSZ3iErESZnncY1n7qU7e3stZXLPh84xVVt5ERMAqKeefUU8jswx2GpCkQpeYow4xH3PGx2iim6ftPa32GNvTKAtknz");
        assert_eq!(account.encrypted_extended_public_key, "b78BOM632Fph4a2xIzWH7Y2fUbHbkYVr2OgJ4WuNxubppAue5npoXgG1kjB7ATxYxpjxYqu/0TgRM1Dz8QO3cT1GPVASzzt4U+f2qeiQcUSj3pnYneGRDcTnY9JsXZmshVbmX7s1He9a0j8x7UeUCS61JM3S9nATdx6YVU/+ViD2tDdRHk6v8IwGnh1uoKb2a/CCsYQbPs5taZoLfwS3BA==");

        let account = keystore
            .accounts
            .iter()
            .find(|x| x.chain_type.eq("FILECOIN"))
            .unwrap();
        assert_eq!(account.address, "t12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey");
        assert_eq!(account.chain_type, "FILECOIN");
        assert_eq!(account.path, "m/44'/461'/0'/0/0");
        assert_eq!(account.curve, "secp256k1");
        assert_eq!(
            account.public_key,
            "03bd460186d29fd9ac68ee88b110c3acc4a4443648a1ec7607af9ce306ad76f785"
        );
        assert_eq!(account.extended_public_key, "tpubDDaEZaaDDmwnZTP6u7m3yTKFgnbSx2uTaxp1hKM5oiVZo6iBB46rWnWpdkpbPxtfdYiyLbyhqgbXRXYff3LfW4rCpYyfpb5pC67CPZdKkZB");
        assert_eq!(account.encrypted_extended_public_key, "PyK/ofjxHbRbZlOE7N4Au7LZIzM5DoV6SgHbfrQvaOsWv5ZwXL2s3nQk6eCj1SIRL6A3s9STpPz7Y3KdggApnOgUpIw7v6ZB3kTKbH4Y8RPH8e1Nlkg2J1CDaf5US1nBmWCxKD4gDh9GEI8H41/MaRWIBnyyw+vwCf5hvVpSvpL9b/sUe8boZmw/VfNpbF5MkGMtFyaZnxd80qFqxgc8fA==");

        let keystore = result
            .keystores
            .iter()
            .find(|x| x.id.eq("4d5cbfcf-aee1-4908-9991-9d060eb68a0e"))
            .clone()
            .unwrap();
        assert_eq!(keystore.id, "4d5cbfcf-aee1-4908-9991-9d060eb68a0e");
        let account = keystore.accounts.first().unwrap();
        assert_eq!(account.address, "tz1d2TfcvWBwtPqo7f21DVv7HSSCoNAVp8gz");
        assert_eq!(account.chain_type, "TEZOS");
        assert_eq!(account.curve, "ed25519");
        assert_eq!(
            account.public_key,
            "bdb7b056d28a8610de329fb4c367886256cc15a5e438a42fff485cd4fc73e574"
        );
        assert_eq!(account.path, "");
        assert_eq!(account.extended_public_key, "");
        assert_eq!(account.encrypted_extended_public_key, "");

        let keystore = result
            .keystores
            .iter()
            .find(|x| x.id.eq("fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb"))
            .clone()
            .unwrap();
        assert_eq!(keystore.id, "fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb");
        let account = keystore.accounts.first().unwrap();
        assert_eq!(account.address, "t3qdyntx5snnwgmjkp2ztd6tf6hhcmurxfj53zylrqyympwvzvbznx6vnvdqloate5eviphnzrkupno4wheesa");
        assert_eq!(account.chain_type, "FILECOIN");
        assert_eq!(account.curve, "bls12-381");
        assert_eq!(
            account.public_key,
            "80f0d9dfb26b6c66254fd6663f4cbe39c4ca46e54f779c2e30c618fb57350e5b7f55b51c16e04c9d2550f3b731551ed7"
        );
        assert_eq!(account.path, "");
        assert_eq!(account.extended_public_key, "");
        assert_eq!(account.encrypted_extended_public_key, "");
    }

    #[test]
    #[serial]
    fn test_scan_legacy_keystores() {
        *LEGACY_WALLET_FILE_DIR.write() = "../test-data/wallets-ios-2_14_1/".to_string();
        let result = scan_legacy_keystores().unwrap();

        let keystore = result
            .keystores
            .iter()
            .find(|x| x.id.eq("00fc0804-7cea-46d8-9e95-ed1efac65358"))
            .clone()
            .unwrap();
        assert_eq!(keystore.id, "00fc0804-7cea-46d8-9e95-ed1efac65358");
        let account = keystore.accounts.first().unwrap();
        assert_eq!(account.address, "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB");
        assert_eq!(account.chain_type, "BITCOIN");
        assert_eq!(account.curve, "secp256k1");
        assert_eq!(account.public_key, "");
        assert_eq!(account.path, "m/49'/1'/0'/0/0");
        assert_eq!(account.extended_public_key, "tpubDCwNET9ErXmBracx3ZBfi6rXQZRjYkpitFe23FAW9M3RcCw4aveNC4SAV5yYrFDjtP3b46eFfv4VtiYP3EXoTZsbnJia2yNznExS8EEcACv");
        assert_eq!(account.encrypted_extended_public_key, "re1xUqBS63Dybo7YZi60QdPm9MC7VdCoHABo7T1qf+btzCUROCND0HxmrShSZEy08QzLoiXxvZBO20/wS7OGjNXmI9wH2i7554S1ol5kwTKoid3Qhk12U6s1zHKCuInAdcNW+/jh4ttp6cO3hosjQGJRCQu8Ts43/TFsN+I0A/8DtyJlSbg1YYz5Xn9R83IRc4R8EvdHj0M2Mrfnae4T0g==");
        assert_eq!(keystore.source, "RECOVERED_IDENTITY");

        let keystore = result
            .keystores
            .iter()
            .find(|x| x.id.eq("6c3eae60-ad03-48db-a5e5-61a6f72aef8d"))
            .clone()
            .unwrap();
        assert_eq!(keystore.id, "6c3eae60-ad03-48db-a5e5-61a6f72aef8d");
        let account = keystore.accounts.first().unwrap();
        assert_eq!(account.address, "");
        assert_eq!(account.chain_type, "EOS");
        assert_eq!(account.curve, "secp256k1");
        assert_eq!(account.path, "m/44'/194'/0'/0/0");
        assert_eq!(
            account.public_key,
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF"
        );
        assert_eq!(account.extended_public_key, "");
        assert_eq!(account.encrypted_extended_public_key, "");
        assert_eq!(keystore.source, "RECOVERED_IDENTITY");

        let keystore = result
            .keystores
            .iter()
            .find(|x| x.id.eq("9b696367-69c1-4cfe-8325-e5530399fc3f"))
            .clone()
            .unwrap();
        assert_eq!(keystore.id, "9b696367-69c1-4cfe-8325-e5530399fc3f");
        let account = keystore.accounts.first().unwrap();
        assert_eq!(
            account.address,
            "cosmos1m566v5rcklnac8vc0dftfu4lnvznhlu7d3f404"
        );
        assert_eq!(account.chain_type, "COSMOS");
        assert_eq!(account.curve, "secp256k1");
        assert_eq!(account.path, "m/44'/118'/0'/0/0");

        let keystore = result
            .keystores
            .iter()
            .find(|x| x.id.eq("60573d8d-8e83-45c3-85a5-34fbb2aad5e1"))
            .clone()
            .unwrap();
        assert_eq!(keystore.id, "60573d8d-8e83-45c3-85a5-34fbb2aad5e1");
        let account = keystore.accounts.first().unwrap();
        assert_eq!(account.address, "02c98f4ed8c8aab1aaba46539e45070a02e416c0");
        assert_eq!(account.chain_type, "ETHEREUM");
        assert_eq!(account.curve, "secp256k1");
        assert_eq!(account.path, "");
        assert_eq!(keystore.source, "KEYSTORE");

        let keystore = result
            .keystores
            .iter()
            .find(|x| x.id.eq("792a0051-16d7-44a7-921a-9b4a0c893b8f"))
            .clone()
            .unwrap();
        assert_eq!(keystore.id, "792a0051-16d7-44a7-921a-9b4a0c893b8f");
        let account = keystore.accounts.first().unwrap();
        assert_eq!(account.address, "7152bcad819b084d57179e293d2765ffa0109e04");
        assert_eq!(account.chain_type, "ETHEREUM");
        assert_eq!(account.curve, "secp256k1");
        assert_eq!(account.path, "m/44'/60'/0'/0/1");
        assert_eq!(keystore.source, "MNEMONIC");
    }

    #[test]
    #[serial]
    fn test_read_mainnet_identity() {
        *LEGACY_WALLET_FILE_DIR.write() = "../test-data/mainnet-identity/".to_string();
        assert_eq!(read_identity_network().unwrap(), IdentityNetwork::Mainnet);
    }

    #[test]
    #[serial]
    fn test_read_testnet_identity() {
        *LEGACY_WALLET_FILE_DIR.write() = "../test-data/testnet-identity/".to_string();
        assert_eq!(read_identity_network().unwrap(), IdentityNetwork::Testnet);
    }
}
