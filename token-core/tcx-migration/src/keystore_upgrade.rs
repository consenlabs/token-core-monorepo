use anyhow::anyhow;
use serde_json::{json, Value};
use tcx_btc_kin::WIFDisplay;
use tcx_common::ToHex;
use tcx_constants::{coin_info_from_param, CurveType};
use tcx_crypto::{Crypto, Key};
use tcx_filecoin::KeyInfo;
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::IdentityNetwork;
use tcx_keystore::{
    fingerprint_from_mnemonic, fingerprint_from_private_key, fingerprint_from_seed,
    mnemonic_to_seed, HdKeystore, Keystore, PrivateKeystore, Result, Source,
};
use tcx_primitive::TypedPrivateKey;
use tcx_substrate::encode_substrate_keystore;
use tcx_tezos::encode_tezos_private_key;

pub fn mapping_curve_name(old_curve_name: &str) -> String {
    let new_curve_name = match old_curve_name {
        "ED25519" => CurveType::ED25519,
        "SECP256k1" => CurveType::SECP256k1,
        "ED25519Blake2bNano" => CurveType::ED25519Blake2bNano,
        "SubSr25519" => CurveType::SR25519,
        "BLS" => CurveType::BLS,
        _ => panic!("unsupported_curve_name"),
    };
    new_curve_name.as_str().to_string()
}

pub struct KeystoreUpgrade {
    json: Value,
}

impl KeystoreUpgrade {
    pub fn new(json: Value) -> Self {
        KeystoreUpgrade { json }
    }

    pub fn need_upgrade(&self) -> bool {
        let version = self.json["version"].as_i64().unwrap_or(0);
        (version == 11000 || version == 11001)
            && self.json["crypto"].is_object()
            && self.json["imTokenMeta"].is_object()
    }

    pub fn upgrade(&self, key: &Key, identity_network: &IdentityNetwork) -> Result<Keystore> {
        let version = self.json["version"].as_i64().unwrap_or(0);

        let mut json = self.json.clone();

        let source: &str = json["imTokenMeta"]["source"].as_str().unwrap_or("");
        json["imTokenMeta"]["source"] = match (version, source) {
            (11000, "NEW_IDENTITY") => json!(Source::NewMnemonic.to_string()),
            (11000, "RECOVERED_IDENTITY") => json!(Source::Mnemonic.to_string()),
            (11000, _) => json!(Source::Mnemonic.to_string()),
            (11001, "PRIVATE") => {
                let accounts = json["activeAccounts"]
                    .as_array()
                    .expect("tcx pk keystore accounts");
                let first_account = accounts.first().expect("first tcx activeAccounts");
                if first_account["curve"].as_str().expect("account curve") == "SubSr25519" {
                    json!(Source::SubstrateKeystore.to_string())
                } else {
                    json!(Source::Private.to_string())
                }
            }
            (11001, "WIF") => json!(Source::Wif.to_string()),
            (11001, "KEYSTORE") => json!(Source::KeystoreV3.to_string()),
            (11001, _) => json!(Source::Private.to_string()),
            (_, _) => json!(Source::Private),
        };

        let crypto: Crypto = serde_json::from_value(json["crypto"].clone())?;
        let unlocker = crypto.use_key(key)?;
        let fingerprint = match version {
            11000 => fingerprint_from_mnemonic(&String::from_utf8_lossy(&unlocker.plaintext()?)),
            11001 => fingerprint_from_private_key(unlocker.plaintext()?.as_slice()),
            _ => return Err(anyhow!("unknown_version_when_upgrade_keystore")),
        }?;
        json["sourceFingerprint"] = json!(fingerprint);

        match version {
            11001 => {
                json["version"] = json!(PrivateKeystore::VERSION);
                let private_key = unlocker.plaintext()?;
                json["identity"] = json!(Identity::from_private_key(
                    &private_key.to_hex(),
                    &unlocker,
                    &identity_network,
                )?);

                json["fingerprint"] = json!(fingerprint_from_private_key(&private_key)?);
                if let Some(account_json) = self.json["activeAccounts"]
                    .as_array()
                    .expect("tcx keystore missing accounts")
                    .first()
                {
                    let old_curve_name = account_json["curve"]
                        .as_str()
                        .expect("activeAccounts need contains curve");
                    let new_curve_name = mapping_curve_name(&old_curve_name);
                    json["curve"] = json!(new_curve_name);
                    let chain_type = account_json["coin"]
                        .as_str()
                        .expect("activeAccounts need contains chainType");
                    json["imTokenMeta"]["identifiedChainTypes"] = json!(vec![chain_type]);
                    // tcx pk keystore has lost the original private key
                    let original = self.restore_private_key_original(
                        key,
                        &private_key,
                        chain_type,
                        &new_curve_name,
                        account_json,
                    )?;
                    let enc_pair = unlocker.encrypt_with_random_iv(original.as_bytes())?;
                    json["encOriginal"] = json!(enc_pair);
                }
            }
            11000 => {
                let mnemonic = String::from_utf8(unlocker.plaintext()?)?;
                let seed = mnemonic_to_seed(&mnemonic)?;

                json["fingerprint"] = json!(fingerprint_from_seed(&seed)?);
                json["version"] = json!(HdKeystore::VERSION);
                json["identity"] =
                    json!(Identity::from_seed(&seed, &unlocker, &identity_network,)?);
                let enc_pair = unlocker.encrypt_with_random_iv(mnemonic.as_bytes())?;
                json["encOriginal"] = json!(enc_pair);
            }
            _ => return Err(anyhow!("unknown_version_when_upgrade_keystore")),
        }

        Keystore::from_json(&json.to_string())
    }

    fn restore_private_key_original(
        &self,
        key: &Key,
        private_key_bytes: &[u8],
        chain_type: &str,
        new_curve_name: &str,
        account_json: &Value,
    ) -> Result<String> {
        match chain_type {
            "KUSAMA" | "POLKADOT" => {
                let coin = coin_info_from_param(chain_type, "", "", "")?;
                let Key::Password(password) = key else {
                    return Err(anyhow!("substrate_cannot_use_derived_key"));
                };

                let mut substrate_ks =
                    encode_substrate_keystore(&password, &private_key_bytes, &coin)?;
                let name = self.json["imTokenMeta"]["name"]
                    .as_str()
                    .unwrap_or_default();
                let created_at = self.json["imTokenMeta"]["timestamp"]
                    .as_i64()
                    .unwrap_or_default();
                substrate_ks.meta.name = name.to_string();
                substrate_ks.meta.when_created = created_at;
                let json = serde_json::to_string(&substrate_ks)?;
                Ok(json)
            }
            "TEZOS" => Ok(encode_tezos_private_key(&private_key_bytes.to_hex())?),
            "FILECOIN" => {
                let curve_type = CurveType::from_str(&new_curve_name);
                Ok(KeyInfo::from_private_key(curve_type, &private_key_bytes)?
                    .to_json()?
                    .to_hex())
            }
            "BITCOINCASH" | "LITECOIN" => {
                let network = account_json["network"].as_str().unwrap_or("MAINNET");
                let seg_wit = account_json["segWit"].as_str().unwrap_or("");
                let coin_info = coin_info_from_param(&chain_type, network, seg_wit, "secp256k1")?;
                let typed_pk =
                    TypedPrivateKey::from_slice(CurveType::SECP256k1, &private_key_bytes)?;
                typed_pk.fmt(&coin_info)
            }
            _ => Ok(private_key_bytes.to_hex()),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use tcx_common::ToHex;
    use tcx_constants::{CurveType, TEST_PASSWORD};
    use tcx_crypto::Error::PasswordIncorrect;
    use tcx_crypto::Key;
    use tcx_keystore::{keystore::IdentityNetwork, Source};

    use super::KeystoreUpgrade;

    fn pk_json(version: i64, source: &str, name: &str) -> Value {
        json!(
            {
             "id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b",
             "version":version,
             "keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee",
             "crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c0ecc72839f8a02cc37eb7b0dd0b93ba"},"ciphertext":"1239e5807e19f95d86567f81c162c69a5f4564ea17f487669a277334f4dcc7dc","kdf":"pbkdf2",
                "kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"3c9df9eb95a014c77bbc8b9a06f4f14e0d08170dea71189c7cf377a3b2099404"},"mac":"909a6bfe1ad031901e80927b847a8fa8407fdcde56cfa374f7a732fb3b3a882d"},
             "activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],
            "imTokenMeta":{"name":name.to_string(),"passwordHint":"","timestamp":1576733295,"source":source.to_string()}}
        )
    }

    fn hd_json(version: i64, source: &str, name: &str) -> Value {
        json!(
         { "id":"ae45d424-31d8-49f7-a601-1272b40c566d",
           "version":version,
           "keyHash":"512115eca3ae86646aeb06861d551e403b543509",
           "crypto": {
           "cipher":"aes-128-ctr",
           "cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},
           "ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d",
           "kdf":"pbkdf2",
           "kdfparams": { "c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},
           "mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},
           "activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"secp256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],
           "imTokenMeta":{"name":name.to_string(),"passwordHint":"","timestamp":1576561805,"source": source.to_string() }
         }
        )
    }

    fn hd_derived_key() -> String {
        "9e6c4391999f0f578105284fe25eb9cf1b60ab75473ac155c83091ae36bf2bb64eb6ec5cbe39dab3a100f87442ee580619700291c15e84961fec2a259c808e68".to_owned()
    }

    fn private_derived_key() -> String {
        "f1d0dbb4b6e7ea6ac99b0a59700f8d8e448ef29a721cbc4d0bc307b26887f232e437366ce87f97eb24c22206452daf83025c9c641a4f63000e20bc9bc5d3fb26".to_owned()
    }

    #[test]
    fn test_invalid_versions() {
        let tests = [
            (-10000000, "MNEMONIC", Source::NewMnemonic),
            (2000000, "MNEMONIC", Source::Wif),
        ];

        for t in tests {
            let upgrade_keystore = super::KeystoreUpgrade::new(hd_json(t.0, t.1, "Unknown"));
            let key = Key::DerivedKey(hd_derived_key());

            let upgraded = upgrade_keystore.upgrade(&key, &IdentityNetwork::Mainnet);

            assert!(!upgrade_keystore.need_upgrade());
            assert_eq!(
                upgraded.err().unwrap().to_string(),
                "unknown_version_when_upgrade_keystore"
            );
        }
    }

    #[test]
    fn test_upgrade_with_password() {
        let upgrade_keystore =
            super::KeystoreUpgrade::new(hd_json(11000, "NEW_IDENTITY", "Unknown"));
        let key = Key::Password("imtoken1".to_owned());

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Testnet)
            .unwrap();

        assert!(upgrade_keystore.need_upgrade());
        assert_eq!(upgraded.store().version, 12000);
        assert_eq!(upgraded.store().meta.source, Source::NewMnemonic);
    }

    #[test]
    fn test_upgrade_with_wrong_derived_key() {
        let upgrade_keystore =
            super::KeystoreUpgrade::new(hd_json(11000, "NEW_IDENTITY", "Unknown"));
        let key = Key::DerivedKey("9e6c4391999f0f578105284fe25eb9cf1b60ab75473ac155c83091ae36bf2bb64eb6ec5cbe39dab3a100f87442ee580619700291c15e84961fec2a259c808e69".to_owned());

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Testnet)
            .unwrap();

        assert!(upgrade_keystore.need_upgrade());
        assert_eq!(upgraded.store().version, 12000);
        assert_eq!(upgraded.store().meta.source, Source::NewMnemonic);
    }

    #[test]
    fn test_hd_keystore_upgrade() {
        let tests = [
            ("NEW_IDENTITY", Source::NewMnemonic),
            ("RECOVERED_IDENTITY", Source::Mnemonic),
            ("KEYSTORE", Source::Mnemonic),
            ("PRIVATE", Source::Mnemonic),
            ("WIF", Source::Mnemonic),
            ("OO", Source::Mnemonic),
        ];

        for t in tests {
            let upgrade_keystore = super::KeystoreUpgrade::new(hd_json(11000, t.0, "Unknown"));
            let key = Key::DerivedKey(hd_derived_key());

            let upgraded = upgrade_keystore
                .upgrade(&key, &IdentityNetwork::Testnet)
                .unwrap();

            assert!(upgrade_keystore.need_upgrade());
            assert_eq!(upgraded.store().version, 12000);
            assert_eq!(upgraded.store().meta.source, t.1);
        }
    }

    #[test]
    fn test_upgrade_hd_identity_network() {
        let upgrade_keystore =
            super::KeystoreUpgrade::new(hd_json(11000, "NEW_IDENTITY", "Unknown"));
        let key = Key::DerivedKey(hd_derived_key());

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Testnet)
            .unwrap();

        assert_eq!(
            upgraded.identity().identifier,
            "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg"
        );

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Mainnet)
            .unwrap();

        assert_eq!(
            upgraded.identity().identifier,
            "im14x5GXsdME4JsrHYe2wvznqRz4cUhx2pA4HPf"
        );
    }

    #[test]
    fn test_private_keystore_upgrade() {
        let tests = [
            ("NEW_IDENTITY", Source::Private),
            ("RECOVERED_IDENTITY", Source::Private),
            ("KEYSTORE", Source::KeystoreV3),
            ("PRIVATE", Source::Private),
            ("WIF", Source::Wif),
            ("OO", Source::Private),
        ];

        for t in tests {
            let upgrade_keystore = super::KeystoreUpgrade::new(pk_json(11001, t.0, "vvvvvv"));
            let key = Key::DerivedKey(private_derived_key());

            let upgraded = upgrade_keystore
                .upgrade(&key, &IdentityNetwork::Testnet)
                .unwrap();

            assert!(upgrade_keystore.need_upgrade());
            assert_eq!(upgraded.store().version, 12001);
            assert_eq!(upgraded.store().meta.source, t.1);
        }
    }

    #[test]
    fn test_upgrade_pk_identity_network() {
        let upgrade_keystore = super::KeystoreUpgrade::new(pk_json(11001, "WIF", "vvvvvv"));
        let key = Key::DerivedKey(private_derived_key());

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Testnet)
            .unwrap();

        assert_eq!(
            upgraded.identity().identifier,
            "im18MDUZKTuAALuXb1Wait1XBb984rdjVpFeBgu"
        );

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Mainnet)
            .unwrap();

        assert_eq!(
            upgraded.identity().identifier,
            "im14x5UPbCXmU2HMQ8jfeKcCDrQYhDppRYaa5C6"
        );
    }

    #[test]
    fn test_invalid_version() {
        let upgrade_keystore = super::KeystoreUpgrade::new(pk_json(11002, "PRIVATE", "SSS"));
        let key = Key::DerivedKey(hd_derived_key());

        let upgraded = upgrade_keystore.upgrade(&key, &IdentityNetwork::Testnet);
        assert!(upgraded.is_err());
    }

    #[test]
    fn test_need_upgrade() {
        let upgrade_keystore = super::KeystoreUpgrade::new(pk_json(11001, "PRIVATE", "中文"));
        assert!(upgrade_keystore.need_upgrade());

        let upgrade_keystore = super::KeystoreUpgrade::new(hd_json(11000, "MNEMONIC", "æœ"));
        assert!(upgrade_keystore.need_upgrade());
    }

    #[test]
    fn test_not_need_upgrade() {
        let upgrade_keystore = super::KeystoreUpgrade::new(pk_json(12001, "PRIVATE", "EE"));
        assert!(!upgrade_keystore.need_upgrade());

        let upgrade_keystore = super::KeystoreUpgrade::new(hd_json(12000, "MNEMONIC", "BB"));
        assert!(!upgrade_keystore.need_upgrade());
    }

    #[test]
    fn test_empty_json() {
        let upgrade_keystore = super::KeystoreUpgrade::new(json!({}));
        assert!(!upgrade_keystore.need_upgrade());
    }

    #[test]
    fn test_empty_metadata() {
        let json = json!(
        { "id":"ae45d424-31d8-49f7-a601-1272b40c566d",
          "version":11000,
          "keyHash":"512115eca3ae86646aeb06861d551e403b543509",
          "crypto": {
          "cipher":"aes-128-ctr",
          "cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},
          "ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d",
          "kdf":"pbkdf2",
          "kdfparams": { "c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},
          "mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},
          "activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"secp256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}]
        });

        let upgrade_keystore = super::KeystoreUpgrade::new(json);
        assert!(!upgrade_keystore.need_upgrade());
    }

    #[test]
    fn test_empty_crypto() {
        let json = json!(
        { "id":"ae45d424-31d8-49f7-a601-1272b40c566d",
          "version":11000,
          "keyHash":"512115eca3ae86646aeb06861d551e403b543509",
          "activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"secp256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}]
        });

        let upgrade_keystore = super::KeystoreUpgrade::new(json);
        assert!(!upgrade_keystore.need_upgrade());
    }

    #[test]
    fn test_wrong_password() {
        let upgrade_keystore = super::KeystoreUpgrade::new(pk_json(11001, "PRIVATE", "vvvvvv"));
        let key = Key::Password("imtoken2".to_owned());

        let upgraded = upgrade_keystore.upgrade(&key, &IdentityNetwork::Testnet);
        assert_eq!(
            upgraded.err().unwrap().to_string(),
            PasswordIncorrect.to_string()
        );
    }

    fn pk_json_with_bls(version: i64, source: &str, name: &str) -> Value {
        json!(
            {
             "id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b",
             "version":version,
             "keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee",
             "crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c0ecc72839f8a02cc37eb7b0dd0b93ba"},"ciphertext":"1239e5807e19f95d86567f81c162c69a5f4564ea17f487669a277334f4dcc7dc","kdf":"pbkdf2",
                "kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"3c9df9eb95a014c77bbc8b9a06f4f14e0d08170dea71189c7cf377a3b2099404"},"mac":"909a6bfe1ad031901e80927b847a8fa8407fdcde56cfa374f7a732fb3b3a882d"},
                "activeAccounts": [{"address": "t3qdyntx5snnwgmjkp2ztd6tf6hhcmurxfj53zylrqyympwvzvbznx6vnvdqloate5eviphnzrkupno4wheesa", "curve": "BLS", "coin": "FILECOIN"}],
            "imTokenMeta":{"name":name.to_string(),"passwordHint":"","timestamp":1576733295,"source":source.to_string()}}
        )
    }

    fn pk_json_with_secp256k1(version: i64, source: &str, name: &str) -> Value {
        json!(
            {
             "id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b",
             "version":version,
             "keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee",
             "crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c0ecc72839f8a02cc37eb7b0dd0b93ba"},"ciphertext":"1239e5807e19f95d86567f81c162c69a5f4564ea17f487669a277334f4dcc7dc","kdf":"pbkdf2",
                "kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"3c9df9eb95a014c77bbc8b9a06f4f14e0d08170dea71189c7cf377a3b2099404"},"mac":"909a6bfe1ad031901e80927b847a8fa8407fdcde56cfa374f7a732fb3b3a882d"},
                "activeAccounts": [{"address": "", "curve": "SECP256k1", "coin": "BITCOINCASH"}],
            "imTokenMeta":{"name":name.to_string(),"passwordHint":"","timestamp":1576733295,"source":source.to_string()}}
        )
    }

    fn pk_json_with_ed25519(version: i64, source: &str, name: &str) -> Value {
        json!(
            {
             "id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b",
             "version":version,
             "keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee",
             "crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c0ecc72839f8a02cc37eb7b0dd0b93ba"},"ciphertext":"1239e5807e19f95d86567f81c162c69a5f4564ea17f487669a277334f4dcc7dc","kdf":"pbkdf2",
                "kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"3c9df9eb95a014c77bbc8b9a06f4f14e0d08170dea71189c7cf377a3b2099404"},"mac":"909a6bfe1ad031901e80927b847a8fa8407fdcde56cfa374f7a732fb3b3a882d"},
                "activeAccounts": [{"address": "", "curve": "ED25519", "coin": "TEZOS"}],
            "imTokenMeta":{"name":name.to_string(),"passwordHint":"","timestamp":1576733295,"source":source.to_string()}}
        )
    }

    fn pk_json_with_subsr25519(version: i64, source: &str, name: &str) -> Value {
        json!(
            {
             "id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b",
             "version":version,
             "keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee",
             "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": { "iv": "31deaa1033b2a55cc39916b347453649" },
                "ciphertext": "c52bbc9842da2e9afdf8b905585db5ea4b86920f54f76e5ce686586604a29c3cc152ba9f309d2a1995cddb0ecafbe4d1f43ad033d1e0f5a02e68eda7c2f71687",
                "kdf": "pbkdf2",
                "kdfparams": {
                  "c": 1,
                  "prf": "hmac-sha256",
                  "dklen": 32,
                  "salt": "87436212538c3d747df0988246078a308bed9245388badf88dbeb21806e6dd49"
                },
                "mac": "53af7ee52b69782e775a46def178d0b629c94b04e70fbddc5adafa437b6144e6"
              },
                "activeAccounts": [{"address": "", "curve": "SubSr25519", "coin": "POLKADOT"}],
            "imTokenMeta":{"name":name.to_string(),"passwordHint":"","timestamp":1576733295,"source":source.to_string()}}
        )
    }

    fn pk_json_without_password_hint(version: i64, source: &str, name: &str) -> Value {
        json!(
            {
             "id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b",
             "version":version,
             "keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee",
             "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": { "iv": "31deaa1033b2a55cc39916b347453649" },
                "ciphertext": "c52bbc9842da2e9afdf8b905585db5ea4b86920f54f76e5ce686586604a29c3cc152ba9f309d2a1995cddb0ecafbe4d1f43ad033d1e0f5a02e68eda7c2f71687",
                "kdf": "pbkdf2",
                "kdfparams": {
                  "c": 1,
                  "prf": "hmac-sha256",
                  "dklen": 32,
                  "salt": "87436212538c3d747df0988246078a308bed9245388badf88dbeb21806e6dd49"
                },
                "mac": "53af7ee52b69782e775a46def178d0b629c94b04e70fbddc5adafa437b6144e6"
              },
                "activeAccounts": [{"address": "", "curve": "SubSr25519", "coin": "POLKADOT"}],
            "imTokenMeta":{"name":name.to_string(),"timestamp":1576733295,"source":source.to_string()}}
        )
    }

    #[test]
    fn test_migration_curve() {
        let key = Key::Password("imtoken1".to_owned());

        let upgrade_keystore =
            super::KeystoreUpgrade::new(pk_json_with_bls(11001, "PRIVATE", "vvvvvv"));

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Testnet)
            .unwrap();
        assert_eq!(upgraded.store().curve, Some(CurveType::BLS));

        let upgrade_keystore =
            super::KeystoreUpgrade::new(pk_json_with_ed25519(11001, "PRIVATE", "vvvvvv"));

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Testnet)
            .unwrap();
        assert_eq!(upgraded.store().curve, Some(CurveType::ED25519));

        let upgrade_keystore =
            super::KeystoreUpgrade::new(pk_json_with_subsr25519(11001, "PRIVATE", "vvvvvv"));

        let upgraded = upgrade_keystore
            .upgrade(
                &Key::Password(TEST_PASSWORD.to_string()),
                &IdentityNetwork::Testnet,
            )
            .unwrap();
        assert_eq!(upgraded.store().curve, Some(CurveType::SR25519));

        let upgrade_keystore =
            super::KeystoreUpgrade::new(pk_json_without_password_hint(11001, "PRIVATE", "vvvvvv"));

        let upgraded = upgrade_keystore
            .upgrade(
                &Key::Password(TEST_PASSWORD.to_string()),
                &IdentityNetwork::Testnet,
            )
            .unwrap();
        assert_eq!(upgraded.store().curve, Some(CurveType::SR25519));

        let upgrade_keystore =
            super::KeystoreUpgrade::new(pk_json_with_secp256k1(11001, "PRIVATE", "vvvvvv"));

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Testnet)
            .unwrap();
        assert_eq!(upgraded.store().curve, Some(CurveType::SECP256k1));

        let upgrade_keystore = super::KeystoreUpgrade::new(hd_json(11000, "MNEMONIC", "vvvvvv"));

        let upgraded = upgrade_keystore
            .upgrade(&key, &IdentityNetwork::Testnet)
            .unwrap();
        assert_eq!(upgraded.store().curve, None);
    }

    #[test]
    fn test_original_after_migrate_tron() {
        let json_str = include_str!(
            "../../test-data/wallets-ios-2_14_1/4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca.json"
        );
        let json = serde_json::from_str(json_str).unwrap();
        let old_ks = KeystoreUpgrade::new(json);
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.upgrade(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();
        assert_eq!(
            ori,
            "685634d212eabe016a1cb09d9f1ea1ea757ebe590b9a097d7b1c9379ad280171"
        );

        let ori = ks.backup(&Key::DerivedKey("1a60471067b6c6a3202e0014de2ce9b2d45fd73e2289b3cc3d8e5b58fe99ff242fd61e9fe63e75abbdc0ed87a50756cc10c57daf1d6297b99ec9a3b174eee017".to_string())).unwrap();
        assert_eq!(
            ori,
            "685634d212eabe016a1cb09d9f1ea1ea757ebe590b9a097d7b1c9379ad280171"
        );
    }

    #[test]
    fn test_original_after_migrate_tezos() {
        let json_str = include_str!(
            "../../test-data/wallets-ios-2_14_1/4d5cbfcf-aee1-4908-9991-9d060eb68a0e.json"
        );
        let json = serde_json::from_str(json_str).unwrap();
        let old_ks = KeystoreUpgrade::new(json);
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.upgrade(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();
        assert_eq!(
            ori,
            "edskS3E5CLrkwHRYAbDvw5xC913C9GGseMcyNGeGbeaD57Yvvi2jqizpAAZyzUtRK626UvkKYdJwCYE9oKMcqFCtJeBpDYcrVH"
        );

        let ori = ks.backup(&Key::DerivedKey("b009d3c4e961411836028a9fffbea994e03c71f75589a571cd52125884537f2ac165b92e7bc49c7828d4be0c5c05263a306744f0b9dc785142c8562d45ce4345".to_string())).unwrap();
        assert_eq!(
            ori,
            "edskS3E5CLrkwHRYAbDvw5xC913C9GGseMcyNGeGbeaD57Yvvi2jqizpAAZyzUtRK626UvkKYdJwCYE9oKMcqFCtJeBpDYcrVH"
        );
    }

    #[test]
    fn test_original_after_migrate_lite() {
        let json_str = include_str!(
            "../../test-data/wallets-ios-2_14_1/46e8e653-dd05-4217-b225-faafc8451a2c.json"
        );
        let json = serde_json::from_str(json_str).unwrap();
        let old_ks = KeystoreUpgrade::new(json);
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.upgrade(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();

        assert_eq!(ori, "TBRMznXcDf2HK2jBKJsqjBpsEdaiaZUBGKN8aKdwTMrPnMNB5UQM");
        let ori = ks.backup(&Key::DerivedKey("2e70651f06a28d2f6053a90ee55ab8cb14518ab82182cd922926b4239713286ac6746ad4448608fc1599e6f4e0af33c65f70bc5de13a376933e5e145681d0f80".to_string())).unwrap();

        assert_eq!(ori, "TBRMznXcDf2HK2jBKJsqjBpsEdaiaZUBGKN8aKdwTMrPnMNB5UQM");
    }

    #[test]
    fn test_original_after_migrate_bch() {
        let json_str = include_str!(
            "../../test-data/wallets-ios-2_14_1/483cb13e-5e59-4428-a219-018de4ce60f6.json"
        );
        let json = serde_json::from_str(json_str).unwrap();
        let old_ks = KeystoreUpgrade::new(json);
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.upgrade(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();

        assert_eq!(ori, "L1xDTJYPqhofU8DQCiwjStEBr1X6dhiNfweUhxhoRSgYyMJPcZ6B");

        let ori = ks.backup(&Key::DerivedKey("d175dad756f59a59b6a311f2b369802537d92011c8e3bf6dc2dfaf8df00d942648bf83133bd0204ebc43efcbd0ab79a8d5551c8dcf7ae1f67fc2d1d4aff33c06".to_string())).unwrap();

        assert_eq!(ori, "L1xDTJYPqhofU8DQCiwjStEBr1X6dhiNfweUhxhoRSgYyMJPcZ6B");
    }

    #[test]
    fn test_original_after_migrate_kusama() {
        let json_str = include_str!(
            "../../test-data/wallets-ios-2_14_1/949bada8-776c-4554-ad0c-001e3726a0f8.json"
        );
        let json = serde_json::from_str(json_str).unwrap();
        let old_ks = KeystoreUpgrade::new(json);
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.upgrade(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();
        assert!(ori.contains("FDS7ZJpJg4R7Kd2hzfsEc6mtW5iknjZ3UazX76EsnbH74v8"));
        let ori = ks.backup(&Key::DerivedKey("daa734e276c7420bd7eb6f9d59d39f3072d9ab0c4c0bda09eb410ab930c745302fb39714a2c4ca1935b18d1d216db11455a4c962daf8bf360ba41c65d872a5a8".to_string())).unwrap();
        assert!(ori.contains("FDS7ZJpJg4R7Kd2hzfsEc6mtW5iknjZ3UazX76EsnbH74v8"));
    }

    #[test]
    fn test_original_after_migrate_file_coin() {
        let json_str = include_str!(
            "../../test-data/wallets-ios-2_14_1/a7294912-b24f-44ba-86c1-48d76117808a.json"
        );
        let json = serde_json::from_str(json_str).unwrap();
        let old_ks = KeystoreUpgrade::new(json);
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.upgrade(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();

        let expected_ori =
            r#"{"Type":"secp256k1","PrivateKey":"o5JgTvwvrZwLPaQ7X2mKLj8nDxcNhZkSvg1UdCJ1xfY="}"#;
        assert_eq!(ori, expected_ori.as_bytes().to_hex());

        let ori = ks.backup(&Key::DerivedKey("bee56a3cc9e6536dd22a695742ff1b4a00a797fa6c0ddd6f2c3bfd2ec25d05d61918ab3ceaf5c135f771d957889ee2b361c5d70f1911cc8857299d349a0d9ee6".to_string())).unwrap();
        let expected_ori =
            r#"{"Type":"secp256k1","PrivateKey":"o5JgTvwvrZwLPaQ7X2mKLj8nDxcNhZkSvg1UdCJ1xfY="}"#;
        assert_eq!(ori, expected_ori.as_bytes().to_hex());
    }

    #[test]
    fn test_original_after_migrate_file_coin_bls() {
        let json_str = include_str!(
            "../../test-data/wallets-ios-2_14_1/fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb.json"
        );
        let json = serde_json::from_str(json_str).unwrap();
        let old_ks = KeystoreUpgrade::new(json);
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.upgrade(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();

        let expected_ori =
            r#"{"Type":"bls","PrivateKey":"i7kO+zxc6QS+v7YygcmUYh7MUYSRes6anigiLhKF808="}"#;
        assert_eq!(ori, expected_ori.as_bytes().to_hex());

        let ori = ks.backup(&Key::DerivedKey("f3207a9f25adbdae5eff58bb13a9d9be4d763c6d47269fb14e4bd7a59ed667ba7282f1ba40746c60ae842c3f9dfeba91060f29f547ef2a94a66cfee93573ffaa".to_string())).unwrap();
        let expected_ori =
            r#"{"Type":"bls","PrivateKey":"i7kO+zxc6QS+v7YygcmUYh7MUYSRes6anigiLhKF808="}"#;
        assert_eq!(ori, expected_ori.as_bytes().to_hex());
    }
}
