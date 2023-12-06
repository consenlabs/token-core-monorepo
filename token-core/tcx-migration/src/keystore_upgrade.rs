use serde_json::{json, Value};
use tcx_crypto::{Crypto, Key};
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::IdentityNetwork;
use tcx_keystore::{HdKeystore, PrivateKeystore, Result, Source};

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

    pub fn upgrade(&self, key: &Key) -> Result<Value> {
        let version = self.json["version"].as_i64().unwrap_or(0);

        let mut json = self.json.clone();

        match json["meta"]["source"].as_str().unwrap_or("") {
            "NEW_IDENTITY" => {
                json["meta"]["source"] = json!(Source::NewMnemonic.to_string());
            }
            "RECOVERED_IDENTITY" => {
                json["meta"]["source"] = json!(Source::Mnemonic.to_string());
            }
            _ => {}
        }

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

        Ok(json)
    }
}

#[cfg(test)]
mod tests {}
