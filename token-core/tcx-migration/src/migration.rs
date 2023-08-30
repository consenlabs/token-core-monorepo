use core::fmt;
use std::str::FromStr;

use failure::format_err;
use serde::{Deserialize, Serialize};
use tcx_atom::address::AtomAddress;
use tcx_chain::{Account, Result, Source};
use tcx_constants::CoinInfo;
use tcx_crypto::{Crypto, EncPair, KdfParams, Key};

use tcx_btc_kin::address::BtcKinAddress;
use tcx_chain::keystore::{Keystore, Metadata};
use tcx_eos::address::EosAddress;
use tcx_eth::address::EthAddress;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OldMetadata {
    pub name: String,
    pub chain_type: String,
    pub network: Option<String>,
    pub password_hint: String,
    pub timestamp: i64,
    pub source: Source,
    pub seg_wit: Option<String>,
}

impl OldMetadata {
    pub fn to_metadata(&self) -> Metadata {
        Metadata {
            name: self.name.clone(),
            password_hint: self.password_hint.clone(),
            timestamp: self.timestamp,
            source: self.source,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyKeystore {
    version: i32,
    id: String,
    crypto: Crypto,
    enc_mnemonic: EncPair,
    address: String,
    mnemonic_path: String,
    im_token_meta: OldMetadata,
}

impl LegacyKeystore {
    fn real_derivation_path(&self) -> String {
        match self.version {
            44 => self.mnemonic_path.clone() + "/0/0",
            10001 => self.mnemonic_path.clone() + "/0'/0/0",
            _ => self.mnemonic_path.clone(),
        }
    }
    pub fn derive_account(&self, keystore: &mut Keystore) -> Result<Account> {
        match self.im_token_meta.chain_type.as_str() {
            "ETHEREUM" => {
                let coin_info = CoinInfo {
                    coin: "ETHEREUM".to_string(),
                    derivation_path: self.real_derivation_path(),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                };
                Ok(keystore.derive_coin::<EthAddress>(&coin_info)?)
            }
            "BITCOIN" => {
                let coin_info = CoinInfo {
                    coin: "BITCOIN".to_string(),
                    derivation_path: self.real_derivation_path(),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: self.im_token_meta.network.clone().unwrap_or("".to_string()),
                    seg_wit: self.im_token_meta.seg_wit.clone().unwrap_or("".to_string()),
                };
                Ok(keystore.derive_coin::<BtcKinAddress>(&coin_info)?)
            }
            "EOS" => {
                let coin_info = CoinInfo {
                    coin: "EOS".to_string(),
                    derivation_path: self.real_derivation_path(),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: self.im_token_meta.network.clone().unwrap_or("".to_string()),
                    seg_wit: "".to_string(),
                };
                Ok(keystore.derive_coin::<EosAddress>(&coin_info)?)
            }
            "COSMOS" => {
                let coin_info = CoinInfo {
                    coin: "COSMOS".to_string(),
                    derivation_path: self.mnemonic_path.clone(),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                };

                Ok(keystore.derive_coin::<AtomAddress>(&coin_info)?)
            }
            _ => unimplemented!(),
        }
    }
    pub fn from_json_str(keystore_str: &str) -> Result<LegacyKeystore> {
        Ok(serde_json::from_str(&keystore_str)?)
    }

    pub fn migrate_to_hd(&self, key: &Key) -> Result<Keystore> {
        let mnemonic_data = self
            .crypto
            .decrypt_enc_pair(key.clone(), &self.enc_mnemonic)?;
        let mnemonic = String::from_utf8(mnemonic_data)?;
        if let Key::Password(password) = key {
            let mut hd_keystore =
                Keystore::from_mnemonic(&mnemonic, password, self.im_token_meta.to_metadata())?;
            hd_keystore.store_mut().id = self.id.to_string();
            hd_keystore.unlock_by_password(password)?;

            self.derive_account(&mut hd_keystore)?;

            return Ok(hd_keystore);
        } else {
            return Err(format_err!("derived_key_not_support"));
        }
    }

    pub fn migrate_to_private(&self, key: &Key) -> Result<Keystore> {
        let mnemonic_data = self
            .crypto
            .decrypt_enc_pair(key.clone(), &self.enc_mnemonic)?;
        let mnemonic = String::from_utf8(mnemonic_data)?;
        if let Key::Password(password) = key {
            let mut hd_keystore =
                Keystore::from_mnemonic(&mnemonic, password, self.im_token_meta.to_metadata())?;
            hd_keystore.store_mut().id = self.id.to_string();
            hd_keystore.unlock_by_password(password)?;

            self.derive_account(&mut hd_keystore)?;

            return Ok(hd_keystore);
        } else {
            return Err(format_err!("derived_key_not_support"));
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tcx_chain::{Keystore, KeystoreGuard, Metadata, PrivateKeystore, Source};
    use tcx_constants::TEST_MNEMONIC;
    use tcx_constants::TEST_PASSWORD;
    use tcx_crypto::crypto::SCryptParams;
    use tcx_crypto::hex;
    use tcx_crypto::Crypto;
    use tcx_crypto::Pbkdf2Params;
    use tcx_crypto::{EncPair, Key};

    use super::LegacyKeystore;

    #[test]
    fn test_eos_with_password() {
        let keystore_str =
            include_str!("../test/fixtures/7f5406be-b5ee-4497-948c-877deab8c994.json");
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks
            .migrate_to_hd(&Key::Password("password".to_string()))
            .unwrap();

        assert_eq!(keystore.accounts().len(), 1);
    }

    #[test]
    fn test_bitcoin_with_password() {
        let keystore_str =
            include_str!("../test/fixtures/02a55ab6-554a-4e78-bc26-6a7acced7e5e.json");
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks
            .migrate_to_hd(&Key::Password("imtoken1".to_string()))
            .unwrap();
        assert_eq!(keystore.accounts().len(), 1);

        assert!(keystore
            .account("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
            .is_some());
    }

    #[test]
    fn test_eth_with_password() {
        let eth_keystore = r#"{
      "crypto": {
        "cipher": "aes-128-ctr",
        "cipherparams": {
          "iv": "3a442e8b02843edf71b8d3a9c9da2c3b"
        },
        "ciphertext": "fcbcceae1d239f9575c55f4c4f81eeba44a6ad9d948f544af2ffee9efef2c038",
        "kdf": "pbkdf2",
        "kdfparams": {
          "c": 65535,
          "dklen": 32,
          "prf": "hmac-sha256",
          "salt": "fa141145a343d9b6c7e2f12e0e56d564bc4d1b46cd48e8f7d898779e06357f1f"
        },
        "mac": "50ee3b40129c5f18f9ff6982db0eb18504ea2e8f3d96e4ac062b4eb5849cf011"
      },
      "id": "175169f7-5a35-4df7-93c1-1ff612168e71",
      "version": 3,
      "address": "6031564e7b2f5cc33737807b2e58daff870b590b",
      "encMnemonic": {
        "encStr": "267bda938e4edbf7c420e89c59c6862f9127c7275d012b1b607f9e91ddb94574e81e94f6d8155e3c85ede03f584e09916122f03c72b67a1f96ddbf291beb46894d9a02d30170a9444692",
        "nonce": "3cfe9f0b32b5d592e5fab54bd28863cd"
      },
      "mnemonicPath": "m/44'/60'/0'/0/0",
      "imTokenMeta": {
        "backup": [],
        "chainType": "ETHEREUM",
        "name": "ETH",
        "passwordHint": "",
        "source": "RECOVERED_IDENTITY",
        "timestamp": 1519611221,
        "walletType": "V3"
      }
    }"#;

        let legacy_kesytore = LegacyKeystore::from_json_str(eth_keystore).unwrap();
        let keystore = legacy_kesytore
            .migrate_to_hd(&Key::Password("imtoken1".to_string()))
            .unwrap();

        assert_eq!(keystore.accounts().len(), 1);
        assert!(keystore
            .account("ETHEREUM", "6031564e7b2f5cc33737807b2e58daff870b590b")
            .is_some());
        assert_eq!(keystore.id(), "175169f7-5a35-4df7-93c1-1ff612168e71")
    }
}
