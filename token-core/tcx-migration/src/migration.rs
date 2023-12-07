use failure::format_err;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tcx_atom::address::AtomAddress;
use tcx_constants::CoinInfo;
use tcx_crypto::{Crypto, EncPair, Key};
use tcx_keystore::{
    key_hash_from_mnemonic, key_hash_from_private_key, Account, HdKeystore, PrivateKeystore,
    Result, Source,
};

use tcx_btc_kin::address::BtcKinAddress;
use tcx_btc_kin::Error;
use tcx_eos::address::EosAddress;
use tcx_eth::address::EthAddress;
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::{IdentityNetwork, Keystore, Metadata, Store};
use tcx_primitive::{PrivateKey, Secp256k1PrivateKey};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum NumberOrNumberStr {
    Number(i64),
    NumberStr(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OldMetadata {
    pub name: String,
    pub chain_type: Option<String>,
    pub chain: Option<String>,
    pub network: Option<String>,
    pub password_hint: String,
    pub timestamp: NumberOrNumberStr,
    pub source: Source,
    pub seg_wit: Option<String>,
}

impl OldMetadata {
    pub fn to_metadata(&self) -> Metadata {
        let timestamp = match &self.timestamp {
            NumberOrNumberStr::Number(num) => num.clone(),
            NumberOrNumberStr::NumberStr(str) => {
                f64::from_str(&str).expect("f64 from timestamp") as i64
            }
        };

        let network = if self.network.is_some()
            && self
                .network
                .as_ref()
                .unwrap()
                .eq_ignore_ascii_case("TESTNET")
        {
            IdentityNetwork::Testnet
        } else {
            IdentityNetwork::Mainnet
        };
        Metadata {
            name: self.name.clone(),
            password_hint: self.password_hint.clone(),
            timestamp: timestamp,
            source: self.source,
            network,
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
        let derivation_path;
        if self.has_mnemonic() {
            derivation_path = self.real_derivation_path();
        } else {
            derivation_path = "".to_string();
        }

        let chain_type = if self.im_token_meta.chain_type.is_some() {
            self.im_token_meta.chain_type.as_ref().unwrap().to_string()
        } else {
            self.im_token_meta
                .chain
                .as_ref()
                .expect("meta chain")
                .to_string()
        };

        match chain_type.as_str() {
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
        let mut keystore = if self.has_mnemonic() {
            self.migrate_to_hd(key)?
        } else {
            self.migrate_to_private(key)?
        };
        self.derive_account(&mut keystore)?;
        Ok(keystore)
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
        let meta = self.im_token_meta.to_metadata();
        let identity = Identity::from_mnemonic(&mnemonic, &unlocker, &meta.network)?;
        let mut store = Store {
            id: self.id.to_string(),
            version: HdKeystore::VERSION,
            key_hash: key_hash.to_string(),
            crypto: self.crypto.clone(),
            identity: identity,
            meta,
        };

        let derived_key = unlocker.derived_key();
        store
            .crypto
            .dangerous_rewrite_plaintext(&derived_key, &mnemonic_data)
            .expect("encrypt");

        let mut keystore = Keystore::Hd(HdKeystore::from_store(store));
        keystore.unlock(&key)?;

        Ok(keystore)
    }

    fn migrate_to_private(&self, key: &Key) -> Result<Keystore> {
        let unlocker = self.crypto.use_key(key)?;
        let mut private_key = unlocker.plaintext()?;
        if private_key.len() != 32 {
            private_key =
                Secp256k1PrivateKey::from_wif(&String::from_utf8_lossy(&private_key))?.to_bytes()
        }

        let key_hash = key_hash_from_private_key(&private_key);
        let unlocker = self.crypto.use_key(key)?;
        let network = self
            .im_token_meta
            .network
            .clone()
            .and_then(|net| IdentityNetwork::from_str(&net).ok())
            .unwrap_or(IdentityNetwork::Mainnet);
        let identity =
            Identity::from_private_key(&hex::encode(private_key.clone()), &unlocker, &network)?;

        let mut store = Store {
            id: self.id.to_string(),
            version: PrivateKeystore::VERSION,
            key_hash: key_hash.to_string(),
            crypto: self.crypto.clone(),
            meta: self.im_token_meta.to_metadata(),
            identity,
        };

        let unlocker = self.crypto.use_key(key)?;
        let derived_key = unlocker.derived_key();
        store
            .crypto
            .dangerous_rewrite_plaintext(&derived_key, &private_key)
            .expect("encrypt");

        let mut keystore = Keystore::PrivateKey(PrivateKeystore::from_store(store));
        keystore.unlock(&key)?;

        Ok(keystore)
    }

    pub fn migrate_identity_wallets(
        &self,
        key: &Key,
        new_keystore: Option<Keystore>,
    ) -> Result<Keystore> {
        let mut keystore = self.migrate_to_hd(key)?;
        keystore.unlock(key)?;

        // generate old 4 chain accounts
        // tcx_btc_kin::bitcoin::enable_account("BITCOIN", 0, &mut keystore)?;
        // tcx_atom::cosmos::enable_account("COSMOS", 0, &mut keystore)?;
        // tcx_eth::ethereum::enable_account("ETHEREUM", 0, &mut keystore)?;
        // tcx_eos::eos::enable_account("EOS", 0, &mut keystore)?;

        // TODO: Create identity wallets
        if let Some(_exists_keystore) = new_keystore {
            // TODO Backup old file
            // TODO: does this need merge?
            // keystore.merge(&exists_keystore)?;

            // exists_keystore.store_mut().crypto = keystore.store().crypto.clone();
            // exists_keystore.store_mut().id = keystore.id().to_string();
            // keystore.store_mut().id = wallet_id.to_string();
        }

        Ok(keystore)
    }
}

#[cfg(test)]
mod tests {
    use tcx_crypto::Key;
    use tcx_keystore::Keystore;

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

    fn tcx_ks() -> &'static str {
        include_str!("../test/fixtures/b05a0ff9-885a-4a31-9d82-6477d34d1e37.json")
    }

    fn identity() -> &'static str {
        include_str!("../test/fixtures/identity.json")
    }

    fn ios_metadata() -> &'static str {
        include_str!("../test/fixtures/5991857a-2488-4546-b730-463a5f84ea6a")
    }

    #[test]
    fn test_eos_private_key() {
        let keystore_str = v3_eos_private_key();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let mut keystore = ks.migrate(&Key::Password("password".to_string())).unwrap();
        keystore
            .unlock(&Key::Password("password".to_string()))
            .unwrap();

        //TODO: accounts asert
        // assert_eq!(keystore.accounts().len(), 1);
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
        //TODO: accounts asert
        // assert_eq!(keystore.accounts().len(), 1);
        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "02a55ab6-554a-4e78-bc26-6a7acced7e5e");
        //TODO: accounts asert
        // assert!(keystore
        //     .account("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
        //     .is_some());
    }

    #[test]
    fn test_v3_ethereum_private_key() {
        let keystore_str = v3_eth_private_key();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks
            .migrate(&Key::Password("Insecure Pa55w0rd".to_string()))
            .unwrap();
        //TODO: accounts asert
        // assert_eq!(keystore.accounts().len(), 1);
        assert_eq!(keystore.derivable(), false);
        assert_eq!(keystore.id(), "045861fe-0e9b-4069-92aa-0ac03cad55e0");

        println!("{}", keystore.to_json());

        //TODO: accounts asert
        // assert!(keystore
        //     .account("ETHEREUM", "0x41983f2e3af196c1df429a3ff5cdecc45c82c600")
        //     .is_some());
    }

    #[test]
    fn test_v3_ethereum_mnemonic() {
        let keystore_str = v3_eth_mnemonic();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks.migrate(&Key::Password("imtoken1".to_string())).unwrap();

        //TODO: accounts asert
        // assert_eq!(keystore.accounts().len(), 1);
        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "175169f7-5a35-4df7-93c1-1ff612168e71");
        //TODO: accounts asert
        //     assert!(keystore
        //         .account("ETHEREUM", "0x6031564e7b2f5cc33737807b2e58daff870b590b")
        //         .is_some());
    }

    #[test]
    fn test_migrate_dk_keystore() {
        let keystore_str = v3_eth_mnemonic();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();

        let derived_key_hex = "3223cd3abf2422d0ad3503f73aaa6e7e36a555385c6825b383908c1e8acf5e9d9a4c751809473c75599a632fe5b1437f51a3a848e054d9c170f8c3b5c5701b8b";
        let keystore = ks
            .migrate_identity_wallets(&Key::DerivedKey(derived_key_hex.to_string()), None)
            .unwrap();

        //TODO: accounts asert
        // assert_eq!(keystore.accounts().len(), 11);
        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "175169f7-5a35-4df7-93c1-1ff612168e71");
        //TODO: accounts asert
        // assert!(keystore
        //     .account("ETHEREUM", "0x6031564e7b2f5cc33737807b2e58daff870b590b")
        //     .is_some());
    }

    #[test]
    fn test_migrate_dk_exists_keystore() {
        let keystore_str = v3_eth_mnemonic();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();

        let existed_ks = Keystore::from_json(tcx_ks()).unwrap();

        let derived_key_hex = "3223cd3abf2422d0ad3503f73aaa6e7e36a555385c6825b383908c1e8acf5e9d9a4c751809473c75599a632fe5b1437f51a3a848e054d9c170f8c3b5c5701b8b";
        let keystore = ks
            .migrate_identity_wallets(
                &Key::DerivedKey(derived_key_hex.to_string()),
                Some(existed_ks),
            )
            .unwrap();

        //TODO: accounts asert
        // assert_eq!(keystore.accounts().len(), 12);
        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "175169f7-5a35-4df7-93c1-1ff612168e71");
        // assert!(keystore
        //     .account("ETHEREUM", "0x6031564e7b2f5cc33737807b2e58daff870b590b")
        //     .is_some());
        // assert!(keystore
        //     .account("TRON", "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2")
        //     .is_some());
    }

    #[test]
    fn test_ios_metadata() {
        let keystore_str = ios_metadata();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks.migrate(&Key::Password("imtoken1".to_string())).unwrap();

        //TODO: accounts asert
        // assert_eq!(keystore.accounts().len(), 1);
        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "5991857a-2488-4546-b730-463a5f84ea6a");
        //TODO: accounts asert
        // assert!(keystore
        //     .account("ETHEREUM", "0x6031564e7b2f5cc33737807b2e58daff870b590b")
        //     .is_some());
    }
}
