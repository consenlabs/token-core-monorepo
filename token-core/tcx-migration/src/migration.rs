use core::fmt;
use std::str::FromStr;

use failure::format_err;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tcx_chain::{Account, Result};
use tcx_constants::CoinInfo;
use tcx_crypto::{Crypto, EncPair, KdfParams, Key, Pbkdf2Params, SCryptParams};

use tcx_chain::keystore::{HdKeystore, Keystore, Metadata};
use tcx_eth::address::EthAddress;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyKeystore<T: KdfParams> {
    id: String,
    #[serde(bound(deserialize = "Crypto<T>: Deserialize<'de>"))]
    crypto: Crypto<T>,
    enc_mnemonic: EncPair,
    address: String,
    mnemonic_path: String,
    im_token_meta: Metadata,
}

pub enum Kdf {
    SCrypt(Pbkdf2Params),
    Pbkdf2(SCryptParams),
}

impl fmt::Display for KdfAlgo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KdfAlgo::SCrypt => write!(f, "scrypt"),
            KdfAlgo::Pbkdf2 => write!(f, "pbkdf2"),
        }
    }
}

impl FromStr for KdfAlgo {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<KdfAlgo, Self::Err> {
        match input {
            "scrypt" => Ok(KdfAlgo::SCrypt),
            "pbkdf2" => Ok(KdfAlgo::Pbkdf2),
            _ => Err(format_err!("invalid_kdf")),
        }
    }
}

pub enum ChainType {
    Ethereum,
    Cosmos,
    Eos,
    Bitcoin,
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChainType::Ethereum => write!(f, "ETHEREUM"),
            ChainType::Eos => write!(f, "EOS"),
            ChainType::Bitcoin => write!(f, "BITCOIN"),
            ChainType::Cosmos => write!(f, "COSMOS"),
        }
    }
}

impl FromStr for ChainType {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<ChainType, Self::Err> {
        match input {
            "ETHEREUM" => Ok(ChainType::Ethereum),
            "EOS" => Ok(ChainType::Eos),
            "BITCOIN" => Ok(ChainType::Bitcoin),
            "COSMOS" => Ok(ChainType::Cosmos),
            _ => Err(format_err!("invalid_chain_type")),
        }
    }
}

pub struct LegacyKeystoreInfo {
    kdf_algo: KdfAlgo,
    chain_type: ChainType,
}

fn parse_kdf_info(json: &Value) -> Result<LegacyKeystoreInfo> {
    let kdf_str = json["crypto"]
        .as_object()
        .and_then(|c| c["kdf"].as_str())
        .ok_or(format_err!("kdf field missing"))?;

    let chain_type_str = json["imTokenMeta"]
        .as_object()
        .and_then(|m| m["chainType"].as_str())
        .ok_or(format_err!("meta field missing"))?;
    let kdf_algo = KdfAlgo::from_str(kdf_str)?;
    let chain_type = ChainType::from_str(chain_type_str)?;

    Ok(LegacyKeystoreInfo {
        kdf_algo,
        chain_type,
    })
}

enum LegacyKeystore {
    Pbkdf2Mnemonic(LegacyMnemonicKeystore<Pbkdf2Params>, LegacyKeystoreInfo),
    ScryptMnemonic(LegacyMnemonicKeystore<SCryptParams>, LegacyKeystoreInfo),
}

impl LegacyKeystore {
    pub fn id(&self) -> String {
        match self {
            Self::Pbkdf2Mnemonic(ks, _) => ks.id.to_string(),
            Self::ScryptMnemonic(ks, _) => ks.id.to_string(),
        }
    }

    pub fn path(&self) -> String {
        match self {
            Self::Pbkdf2Mnemonic(ks, _) => ks.mnemonic_path.to_string(),
            Self::ScryptMnemonic(ks, _) => ks.mnemonic_path.to_string(),
        }
    }

    pub fn migrate(&self, key: &Key) -> Result<Keystore> {
        match self {
            Self::Pbkdf2Mnemonic(legacy_ks, keystore_info) => {
                let mut ks = legacy_ks.migrate_to_hd(key)?;
                ks.unlock(key)?;
                self.derive_account(&mut ks, keystore_info)?;
                Ok(ks)
            }
            Self::ScryptMnemonic(legacy_ks, keystore_info) => {
                let mut ks = legacy_ks.migrate_to_hd(key)?;
                ks.unlock(key)?;
                self.derive_account(&mut ks, keystore_info)?;
                Ok(ks)
            }
        }
    }

    pub fn derive_account(
        &self,
        keystore: &mut Keystore,
        keystore_info: &LegacyKeystoreInfo,
    ) -> Result<Account> {
        match keystore_info.chain_type {
            ChainType::Ethereum => {
                let coin_info = CoinInfo {
                    coin: ChainType::Ethereum.to_string(),
                    derivation_path: self.path(),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                };
                Ok(keystore.derive_coin::<EthAddress>(&coin_info)?)
            }
            _ => unimplemented!(),
        }
    }

    pub fn from_json_str(keystore_str: &str) -> Result<LegacyKeystore> {
        let value: Value = serde_json::from_str(&keystore_str)?;
        let keystore_info = parse_kdf_info(&value)?;
        let keystore = match keystore_info.kdf_algo {
            KdfAlgo::Pbkdf2 => {
                LegacyKeystore::Pbkdf2Mnemonic(serde_json::from_str(keystore_str)?, keystore_info)
            }
            KdfAlgo::SCrypt => {
                LegacyKeystore::ScryptMnemonic(serde_json::from_str(keystore_str)?, keystore_info)
            }
        };
        Ok(keystore)
    }
}

impl<T: KdfParams> LegacyMnemonicKeystore<T> {
    pub fn migrate_to_hd(&self, key: &Key) -> Result<Keystore> {
        let mnemonic_data = self
            .crypto
            .decrypt_enc_pair(key.clone(), &self.enc_mnemonic)?;
        let mnemonic = String::from_utf8(mnemonic_data)?;
        if let Key::Password(password) = key {
            let mut hd_keystore =
                HdKeystore::from_mnemonic(&mnemonic, password, self.im_token_meta.clone())?;
            hd_keystore.store_mut().id = self.id.to_string();
            return Ok(Keystore::Hd(hd_keystore));
        } else {
            return Err(format_err!("derived_key_not_support"));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::migration::LegacyMnemonicKeystore;
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
    fn test_bitcoin() {
        let keystore_str =
            include_str!("../test/keystore/02a55ab6-554a-4e78-bc26-6a7acced7e5e.json");
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks.migrate(&Key::Password("imtoken1".to_string())).unwrap();

        assert_eq!(keystore.accounts().len(), 1);
    }

    #[test]
    fn test_eth() {
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
            .migrate(&Key::Password("imtoken1".to_string()))
            .unwrap();

        assert_eq!(keystore.accounts().len(), 1);
        assert!(keystore
            .account("ETHEREUM", "6031564e7b2f5cc33737807b2e58daff870b590b")
            .is_some());
        assert_eq!(keystore.id(), "175169f7-5a35-4df7-93c1-1ff612168e71")
    }
}
