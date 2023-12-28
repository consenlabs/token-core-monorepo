use failure::format_err;
use serde_json::{json, Value};
use tcx_common::ToHex;
use tcx_crypto::{Crypto, Key};
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::IdentityNetwork;
use tcx_keystore::{
    fingerprint_from_private_key, fingerprint_from_seed, mnemonic_to_seed, HdKeystore, Keystore,
    PrivateKeystore, Result, Source,
};

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

    pub fn upgrade(&self, key: &Key) -> Result<Keystore> {
        let version = self.json["version"].as_i64().unwrap_or(0);

        let mut json = self.json.clone();

        let source = json["imTokenMeta"]["source"].as_str().unwrap_or("");
        json["imTokenMeta"]["source"] = match (version, source) {
            (11000, "NEW_IDENTITY") => json!(Source::NewMnemonic.to_string()),
            (11000, "RECOVERED_IDENTITY") => json!(Source::Mnemonic.to_string()),
            (11000, _) => json!(Source::Mnemonic.to_string()),
            (11001, "PRIVATE") => json!(Source::Private.to_string()),
            (11001, "WIF") => json!(Source::Wif.to_string()),
            (11001, "KEYSTORE") => json!(Source::KeystoreV3.to_string()),
            (11001, _) => json!(Source::Private.to_string()),
            (_, _) => json!(Source::Private),
        };

        json["fingerprint"] = json!("");

        let crypto: Crypto = serde_json::from_value(json["crypto"].clone())?;
        let unlocker = crypto.use_key(key)?;

        let identity_network = match json["meta"]["network"].as_str().unwrap_or("") {
            "TESTNET" => IdentityNetwork::Testnet,
            _ => IdentityNetwork::Mainnet,
        };

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
            }
            11000 => {
                let mnemonic = String::from_utf8(unlocker.plaintext()?)?;
                let seed = mnemonic_to_seed(&mnemonic)?;

                json["fingerprint"] = json!(fingerprint_from_seed(&seed)?);
                json["version"] = json!(HdKeystore::VERSION);
                json["identity"] =
                    json!(Identity::from_seed(&seed, &unlocker, &identity_network,)?);
            }
            _ => return Err(format_err!("invalid version")),
        }

        Keystore::from_json(&json.to_string())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use tcx_common::ToHex;
    use tcx_crypto::Error::PasswordIncorrect;
    use tcx_crypto::Key;
    use tcx_keystore::{Keystore, Source};

    fn pk_json(version: i64, source: &str, name: &str) -> Value {
        json!(
            {
             "id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b",
             "version":version,
             "keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee",
             "crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c0ecc72839f8a02cc37eb7b0dd0b93ba"},"ciphertext":"1239e5807e19f95d86567f81c162c69a5f4564ea17f487669a277334f4dcc7dc","kdf":"pbkdf2",
                "kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"3c9df9eb95a014c77bbc8b9a06f4f14e0d08170dea71189c7cf377a3b2099404"},"mac":"909a6bfe1ad031901e80927b847a8fa8407fdcde56cfa374f7a732fb3b3a882d"},
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

            let upgraded = upgrade_keystore.upgrade(&key);

            assert!(!upgrade_keystore.need_upgrade());
            assert_eq!(upgraded.err().unwrap().to_string(), "invalid version");
        }
    }

    #[test]
    fn test_upgrade_with_password() {
        let upgrade_keystore =
            super::KeystoreUpgrade::new(hd_json(11000, "NEW_IDENTITY", "Unknown"));
        let key = Key::Password("imtoken1".to_owned());

        let upgraded = upgrade_keystore.upgrade(&key).unwrap();

        assert!(upgrade_keystore.need_upgrade());
        assert_eq!(upgraded.store().version, 12000);
        assert_eq!(upgraded.store().meta.source, Source::NewMnemonic);
    }

    #[test]
    fn test_upgrade_with_wrong_derived_key() {
        let upgrade_keystore =
            super::KeystoreUpgrade::new(hd_json(11000, "NEW_IDENTITY", "Unknown"));
        let key = Key::DerivedKey("9e6c4391999f0f578105284fe25eb9cf1b60ab75473ac155c83091ae36bf2bb64eb6ec5cbe39dab3a100f87442ee580619700291c15e84961fec2a259c808e69".to_owned());

        let upgraded = upgrade_keystore.upgrade(&key).unwrap();

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

            let upgraded = upgrade_keystore.upgrade(&key).unwrap();

            assert!(upgrade_keystore.need_upgrade());
            assert_eq!(upgraded.store().version, 12000);
            assert_eq!(upgraded.store().meta.source, t.1);
        }
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

            let mut upgraded = upgrade_keystore.upgrade(&key).unwrap();

            assert!(upgrade_keystore.need_upgrade());
            assert_eq!(upgraded.store().version, 12001);
            assert_eq!(upgraded.store().meta.source, t.1);
        }
    }

    #[test]
    fn test_invalid_version() {
        let upgrade_keystore = super::KeystoreUpgrade::new(pk_json(11002, "PRIVATE", "SSS"));
        let key = Key::DerivedKey(hd_derived_key());

        let upgraded = upgrade_keystore.upgrade(&key);
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

        let upgraded = upgrade_keystore.upgrade(&key);
        assert_eq!(
            upgraded.err().unwrap().to_string(),
            PasswordIncorrect.to_string()
        );
    }
}
