use core::fmt;
use std::str::FromStr;

use failure::format_err;
use serde::{Deserialize, Serialize};
use tcx_atom::address::AtomAddress;
use tcx_chain::{
    key_hash_from_mnemonic, key_hash_from_private_key, Account, HdKeystore, PrivateKeystore,
    Result, Source,
};
use tcx_constants::CoinInfo;
use tcx_crypto::{Crypto, EncPair, KdfParams, Key};

use tcx_btc_kin::address::BtcKinAddress;
use tcx_btc_kin::Error;
use tcx_chain::keystore::{Keystore, Metadata, Store};
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
    enc_mnemonic: Option<EncPair>,
    address: String,
    mnemonic_path: Option<String>,
    im_token_meta: OldMetadata,
}

impl LegacyKeystore {
    fn real_derivation_path(&self) -> String {
        match self.version {
            44 => {
                self.mnemonic_path
                    .as_ref()
                    .expect("the mnemonic path must be set")
                    .clone()
                    + "/0/0"
            }
            _ => self
                .mnemonic_path
                .as_ref()
                .expect("the mnemonic path must be set")
                .clone(),
        }
    }

    fn has_mnemonic(&self) -> bool {
        self.enc_mnemonic.is_some()
    }

    pub fn derive_account(&self, keystore: &mut Keystore) -> Result<Account> {
        let mut derivation_path;
        if self.has_mnemonic() {
            derivation_path = self.real_derivation_path();
        } else {
            derivation_path = "".to_string();
        }

        match self.im_token_meta.chain_type.as_str() {
            "ETHEREUM" => {
                let coin_info = CoinInfo {
                    coin: "ETHEREUM".to_string(),
                    derivation_path,
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                };
                Ok(keystore.derive_coin::<EthAddress>(&coin_info)?)
            }
            "BITCOIN" => {
                let coin_info = CoinInfo {
                    coin: "BITCOIN".to_string(),
                    derivation_path,
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: self.im_token_meta.network.clone().unwrap_or("".to_string()),
                    seg_wit: self.im_token_meta.seg_wit.clone().unwrap_or("".to_string()),
                };
                Ok(keystore.derive_coin::<BtcKinAddress>(&coin_info)?)
            }
            "EOS" => {
                let coin_info = CoinInfo {
                    coin: "EOS".to_string(),
                    derivation_path,
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: self.im_token_meta.network.clone().unwrap_or("".to_string()),
                    seg_wit: "".to_string(),
                };
                Ok(keystore.derive_coin::<EosAddress>(&coin_info)?)
            }
            "COSMOS" => {
                let coin_info = CoinInfo {
                    coin: "COSMOS".to_string(),
                    derivation_path,
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                };

                Ok(keystore.derive_coin::<AtomAddress>(&coin_info)?)
            }
            _ => Err(Error::UnsupportedChain.into()),
        }
    }
    pub fn from_json_str(keystore_str: &str) -> Result<LegacyKeystore> {
        let keystore: LegacyKeystore = serde_json::from_str(&keystore_str)?;
        if keystore.version != 44 && keystore.version != 1 && keystore.version != 3 {
            return Err(format_err!("unsupported version {}", keystore.version));
        }

        Ok(keystore)
    }

    pub fn migrate_to_hd(&self, key: &Key) -> Result<Keystore> {
        let unlocker = self.crypto.use_key(key)?;
        let mnemonic_data = unlocker.decrypt_enc_pair(
            self.enc_mnemonic
                .as_ref()
                .expect("the mnemonic must be set"),
        )?;
        let mnemonic = String::from_utf8(mnemonic_data.to_owned())?;
        let key_hash = key_hash_from_mnemonic(&mnemonic)?;

        let mut store = Store {
            id: self.id.to_string(),
            version: HdKeystore::VERSION,
            key_hash: key_hash.to_string(),
            crypto: self.crypto.clone(),
            active_accounts: vec![],
            meta: self.im_token_meta.to_metadata(),
        };

        let derived_key = unlocker.derived_key();
        store
            .crypto
            .dangerous_rewrite_plaintext(&derived_key, &mnemonic_data)
            .expect("encrypt");

        let mut keystore = Keystore::Hd(HdKeystore::from_store(store));
        keystore.unlock(&key)?;

        self.derive_account(&mut keystore)?;

        Ok(keystore)
    }

    pub fn migrate_to_private(&self, key: &Key) -> Result<Keystore> {
        let unlocker = self.crypto.use_key(key)?;
        let private_key = unlocker.plaintext()?;
        let private_key: Vec<u8> = String::from_utf8(private_key)?.into();
        let key_hash = key_hash_from_private_key(&private_key);

        let mut store = Store {
            id: self.id.to_string(),
            version: PrivateKeystore::VERSION,
            key_hash: key_hash.to_string(),
            crypto: self.crypto.clone(),
            active_accounts: vec![],
            meta: self.im_token_meta.to_metadata(),
        };

        let unlocker = self.crypto.use_key(key)?;
        let derived_key = unlocker.derived_key();
        store
            .crypto
            .dangerous_rewrite_plaintext(&derived_key, &private_key)
            .expect("encrypt");

        let mut keystore = Keystore::PrivateKey(PrivateKeystore::from_store(store));
        keystore.unlock(&key)?;

        self.derive_account(&mut keystore)?;

        Ok(keystore)
    }

    pub fn migrate_identity_wallets(
        &self,
        key: &Key,
        new_keystore: &mut Keystore,
        need_clone: bool,
    ) -> Result<Keystore> {
        let mut keystore = self.migrate_to_hd(key)?;
        keystore.unlock(key)?;

        // generate old 4 chain accounts
        tcx_btc_kin::bitcoin::enable_account("BITCOIN", 0, &mut keystore)?;
        tcx_atom::cosmos::add_account("COSMOS", 0, &mut keystore)?;
        tcx_eth::ethereum::enable_account("ETHEREUM", 0, &mut keystore)?;
        tcx_eos::eos::enable_account("EOS", 0, &mut keystore)?;

        new_keystore.merge(&keystore)?;

        if need_clone {
            new_keystore.store_mut().crypto = keystore.store().crypto.clone();
            new_keystore.store_mut().id = keystore.id().to_string();
        }

        Ok(keystore)
    }

    fn dangerous_copy_crypto_to_keystore(&self, keystore: &mut Keystore) {
        keystore.store_mut().crypto = self.crypto.clone();
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

    fn v44_bitcoin() -> &'static str {
        include_str!("../test/fixtures/02a55ab6-554a-4e78-bc26-6a7acced7e5e.json")
    }

    fn unsupported_eos() -> &'static str {
        include_str!("../test/fixtures/7f5406be-b5ee-4497-948c-877deab8c994.json")
    }

    #[test]
    fn test_is_same_derived_key() {
        let keystore_str = v44_bitcoin();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks
            .migrate_to_hd(&Key::Password("imtoken1".to_string()))
            .unwrap();

        let unlocker1 = ks
            .crypto
            .use_key(&Key::Password("imtoken1".to_string()))
            .unwrap();
        let unlocker2 = keystore
            .store()
            .crypto
            .use_key(&Key::Password("imtoken1".to_string()))
            .unwrap();

        assert_eq!(unlocker1.derived_key(), unlocker2.derived_key());
    }

    #[test]
    fn test_unsupported_version() {
        let keystore_str = unsupported_eos();
        let ks = LegacyKeystore::from_json_str(keystore_str);
        assert!(ks.is_err());
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
