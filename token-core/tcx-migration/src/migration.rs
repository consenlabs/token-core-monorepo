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

    pub fn migrate(&self, key: &Key) -> Result<Keystore> {
        if self.has_mnemonic() {
            self.migrate_to_hd(key)
        } else {
            self.migrate_to_private(key)
        }
    }

    fn migrate_to_hd(&self, key: &Key) -> Result<Keystore> {
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

    fn migrate_to_private(&self, key: &Key) -> Result<Keystore> {
        let unlocker = self.crypto.use_key(key)?;
        let private_key = unlocker.plaintext()?;
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
        tcx_atom::cosmos::enable_account("COSMOS", 0, &mut keystore)?;
        tcx_eth::ethereum::enable_account("ETHEREUM", 0, &mut keystore)?;
        tcx_eos::eos::enable_account("EOS", 0, &mut keystore)?;

        new_keystore.merge(&keystore)?;

        if need_clone {
            new_keystore.store_mut().crypto = keystore.store().crypto.clone();
            new_keystore.store_mut().id = keystore.id().to_string();
        }

        Ok(keystore)
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

    fn v44_bitcoin_mnemonic_1() -> &'static str {
        include_str!("../test/fixtures/02a55ab6-554a-4e78-bc26-6a7acced7e5e.json")
    }

    fn unsupported_eos() -> &'static str {
        include_str!("../test/fixtures/7f5406be-b5ee-4497-948c-877deab8c994.json")
    }

    fn v3_eos_private_key() -> &'static str {
        include_str!("../test/fixtures/42c275c6-957a-49e8-9eb3-43c21cbf583f.json")
    }

    fn v44_bitcoin_mnemonic_2() -> &'static str {
        include_str!("../test/fixtures/3831346d-0b81-405b-89cf-cdb1d010430e.json")
    }

    fn v3_eth_private_key() -> &'static str {
        include_str!("../test/fixtures/045861fe-0e9b-4069-92aa-0ac03cad55e0.json")
    }

    fn v3_eth_mnemonic() -> &'static str {
        include_str!("../test/fixtures/175169f7-5a35-4df7-93c1-1ff612168e71.json")
    }

    fn identity() -> &'static str {
        include_str!("../test/fixtures/identity.json")
    }

    #[test]
    fn test_is_same_derived_key() {
        let keystore_str = v44_bitcoin_mnemonic_1();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks.migrate(&Key::Password("imtoken1".to_string())).unwrap();

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
        let keystore_str = v44_bitcoin_mnemonic_1();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks.migrate(&Key::Password("imtoken1".to_string())).unwrap();
        assert_eq!(keystore.accounts().len(), 1);
        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "02a55ab6-554a-4e78-bc26-6a7acced7e5e");

        assert!(keystore
            .account("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
            .is_some());
    }

    #[test]
    fn test_v3_ethereum_private_key() {
        let keystore_str = v3_eth_private_key();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks
            .migrate(&Key::Password("Insecure Pa55w0rd".to_string()))
            .unwrap();
        assert_eq!(keystore.accounts().len(), 1);
        assert_eq!(keystore.derivable(), false);
        assert_eq!(keystore.id(), "045861fe-0e9b-4069-92aa-0ac03cad55e0");

        println!("{}", keystore.to_json());

        assert!(keystore
            .account("ETHEREUM", "0x41983f2e3af196c1df429a3ff5cdecc45c82c600")
            .is_some());
    }

    #[test]
    fn test_v3_ethereum_mnemonic() {
        let keystore_str = v3_eth_mnemonic();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks.migrate(&Key::Password("imtoken1".to_string())).unwrap();

        assert_eq!(keystore.accounts().len(), 1);
        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "175169f7-5a35-4df7-93c1-1ff612168e71");
        assert!(keystore
            .account("ETHEREUM", "0x6031564e7b2f5cc33737807b2e58daff870b590b")
            .is_some());
    }
}
