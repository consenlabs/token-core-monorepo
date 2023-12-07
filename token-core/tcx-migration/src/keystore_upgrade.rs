use serde_json::{json, Value};
use std::str::FromStr;
use tcx_crypto::{Crypto, Key};
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::IdentityNetwork;
use tcx_keystore::{HdKeystore, Keystore, PrivateKeystore, Result, Source};

pub struct KeystoreUpgrade {
    json: Value,
}

impl KeystoreUpgrade {
    pub fn new(json: Value) -> Self {
        KeystoreUpgrade { json }
    }

    pub fn need_upgrade(&self) -> bool {
        let version = self.json["version"].as_i64().unwrap_or(0);
        version == 11001 || version == 11000
    }

    pub fn upgrade(&self, key: &Key) -> Result<Keystore> {
        let version = self.json["version"].as_i64().unwrap_or(0);

        let mut json = self.json.clone();

        let source = json["imTokenMeta"]["source"].as_str().unwrap_or("");
        json["imTokenMeta"]["source"] = match source {
            "NEW_IDENTITY" => json!(Source::NewMnemonic.to_string()),
            "RECOVER_IDENTITY" => json!(Source::Mnemonic.to_string()),
            "KEYSTORE" => json!(Source::KeystoreV3.to_string()),
            _ => Source::from_str(source)?.to_string().into(),
        };

        let crypto: Crypto = serde_json::from_value(json["crypto"].clone())?;
        let unlocker = crypto.use_key(key)?;

        let identity_network = match json["meta"]["network"].as_str().unwrap_or("") {
            "TESTNET" => IdentityNetwork::Testnet,
            _ => IdentityNetwork::Mainnet,
        };

        match version {
            11001 => {
                json["version"] = json!(PrivateKeystore::VERSION);
                json["identity"] = json!(Identity::from_private_key(
                    &hex::encode(unlocker.plaintext()?),
                    &unlocker,
                    &identity_network,
                )?);
            }
            11000 => {
                let mnemonic = String::from_utf8(unlocker.plaintext()?)?;
                json["version"] = json!(HdKeystore::VERSION);
                json["identity"] = json!(Identity::from_mnemonic(
                    &mnemonic,
                    &unlocker,
                    &identity_network,
                )?);
            }
            _ => {}
        }

        Ok(Keystore::from_json(&json.to_string())?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tcx_crypto::Key;
    use tcx_keystore::{Keystore, Source};

    #[test]
    fn test_hd_keystore_upgrade() {
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
                "activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],
                "imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"NEW_IDENTITY"}}
        );

        let upgrade_keystore = super::KeystoreUpgrade::new(json);
        let key = Key::Password("imtoken1".to_owned());

        let upgraded = upgrade_keystore.upgrade(&key).unwrap();

        assert!(upgrade_keystore.need_upgrade());
        assert_eq!(upgraded.store().version, 12000);
        assert_eq!(upgraded.store().meta.source, Source::NewMnemonic);
    }

    #[test]
    fn test_private_keystore_upgrade() {
        let json = json!(
            {
             "id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b",
             "version":11001,
             "keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee",
             "crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c0ecc72839f8a02cc37eb7b0dd0b93ba"},"ciphertext":"1239e5807e19f95d86567f81c162c69a5f4564ea17f487669a277334f4dcc7dc","kdf":"pbkdf2",
                "kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"3c9df9eb95a014c77bbc8b9a06f4f14e0d08170dea71189c7cf377a3b2099404"},"mac":"909a6bfe1ad031901e80927b847a8fa8407fdcde56cfa374f7a732fb3b3a882d"},
            "imTokenMeta":{"name":"Unknown","passwordHint":"","timestamp":1576733295,"source":"RECOVER_IDENTITY"}}
        );

        let upgrade_keystore = super::KeystoreUpgrade::new(json);
        let key = Key::Password("imtoken1".to_owned());

        let upgraded = upgrade_keystore.upgrade(&key).unwrap();

        assert!(upgrade_keystore.need_upgrade());
        assert_eq!(upgraded.store().version, 12001);
        assert_eq!(upgraded.store().meta.source, Source::Mnemonic);
    }
}
