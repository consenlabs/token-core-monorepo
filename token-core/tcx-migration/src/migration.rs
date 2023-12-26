use failure::format_err;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tcx_common::{FromHex, ToHex};
use tcx_constants::{coin_info_from_param, CurveType};
use tcx_crypto::{Crypto, EncPair, Key};
use tcx_eth::address::EthAddress;
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::{IdentityNetwork, Keystore, Metadata, Store};
use tcx_keystore::{
    fingerprint_from_private_key, fingerprint_from_seed, mnemonic_to_seed, Address, HdKeystore,
    PrivateKeystore, Result, Source,
};
use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, TypedPublicKey};

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
    pub source: Option<String>,
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

        let source = self
            .source
            .clone()
            .map_or(Source::Mnemonic, |source| match source.as_str() {
                "RECOVER_IDENTITY" => Source::Mnemonic,
                "NEW_IDENTITY" => Source::NewMnemonic,
                "KEYSTORE" => Source::KeystoreV3,
                _ => Source::from_str(&source).unwrap_or(Source::Mnemonic),
            });

        Metadata {
            name: self.name.clone(),
            password_hint: self.password_hint.clone(),
            timestamp: timestamp,
            source,
            network,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyKeystore {
    pub version: i32,
    pub id: String,
    pub crypto: Crypto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc_mnemonic: Option<EncPair>,
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub im_token_meta: Option<OldMetadata>,
}

impl LegacyKeystore {
    pub fn new_v3(private_key: &[u8], password: &str) -> Result<Self> {
        let crypto = Crypto::new(password, private_key);
        let sec_key = Secp256k1PrivateKey::from_slice(private_key)?;
        let pub_key = TypedPublicKey::Secp256k1(sec_key.public_key());
        let coin_info = coin_info_from_param("ETHEREUM", "", "", CurveType::SECP256k1.as_str())?;
        let address = EthAddress::from_public_key(&pub_key, &coin_info)?.to_string();
        let id = uuid::Uuid::new_v4().to_string();
        Ok(LegacyKeystore {
            version: 3,
            id,
            crypto,
            enc_mnemonic: None,
            address: Some(address),
            mnemonic_path: None,
            im_token_meta: None,
        })
    }

    pub fn validate_v3(&self, password: &str) -> Result<()> {
        let key = Key::Password(password.to_string());
        let unlocker = self.crypto.use_key(&key)?;
        let sec_key_bytes = unlocker.plaintext()?;
        let sec_key = Secp256k1PrivateKey::from_slice(&sec_key_bytes)?;

        let pub_key = TypedPublicKey::Secp256k1(sec_key.public_key());
        let coin_info = coin_info_from_param("ETHEREUM", "", "", CurveType::SECP256k1.as_str())?;

        let calc_address = EthAddress::from_public_key(&pub_key, &coin_info)?.to_string();
        let calc_addr_bytes = &Vec::from_hex_auto(calc_address)?;
        let addr_bytes = &Vec::from_hex_auto(&self.address.clone().unwrap())?;

        if calc_addr_bytes == addr_bytes {
            Ok(())
        } else {
            Err(format_err!("private_key_and_address_not_match"))
        }
    }

    fn has_mnemonic(&self) -> bool {
        self.enc_mnemonic.is_some()
    }

    pub fn from_json_str(keystore_str: &str) -> Result<LegacyKeystore> {
        let keystore: LegacyKeystore = serde_json::from_str(&keystore_str)?;
        if keystore.version != 44
            && keystore.version != 1
            && keystore.version != 3
            && keystore.version != 10001
        {
            return Err(format_err!("unsupported version {}", keystore.version));
        }

        Ok(keystore)
    }

    pub fn migrate(&self, key: &Key) -> Result<Keystore> {
        let keystore = if self.has_mnemonic() {
            self.migrate_to_hd(key)?
        } else {
            self.migrate_to_private(key)?
        };
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
        let seed = mnemonic_to_seed(&mnemonic)?;
        println!("{}, {}", self.id, unlocker.derived_key().to_hex());

        let fingerprint = fingerprint_from_seed(&seed)?;
        let meta = self
            .im_token_meta
            .as_ref()
            .expect("migration to hd need imTokenMeta")
            .to_metadata();

        let identity = Identity::from_seed(&seed, &unlocker, &meta.network)?;
        let mut store = Store {
            id: self.id.to_string(),
            version: HdKeystore::VERSION,
            fingerprint: fingerprint.to_string(),
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
        println!("{}, {}", self.id, unlocker.derived_key().to_hex());
        let mut private_key = unlocker.plaintext()?;
        if private_key.len() != 32 {
            private_key =
                Secp256k1PrivateKey::from_wif(&String::from_utf8_lossy(&private_key))?.to_bytes()
        }

        let fingerprint = fingerprint_from_private_key(&private_key)?;
        let unlocker = self.crypto.use_key(key)?;
        let im_token_meta = self
            .im_token_meta
            .as_ref()
            .expect("migrate to private need imTokenMeta");
        let network = im_token_meta
            .network
            .clone()
            .and_then(|net| IdentityNetwork::from_str(&net).ok())
            .unwrap_or(IdentityNetwork::Mainnet);
        let identity = Identity::from_private_key(&private_key.to_hex(), &unlocker, &network)?;

        let mut store = Store {
            id: self.id.to_string(),
            version: PrivateKeystore::VERSION,
            fingerprint: fingerprint.to_string(),
            crypto: self.crypto.clone(),
            meta: im_token_meta.to_metadata(),
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

        // TODO: merge with exists wallet
        if let Some(_exists_keystore) = new_keystore {

            // exists_keystore.store_mut().crypto = keystore.store().crypto.clone();
            // exists_keystore.store_mut().id = keystore.id().to_string();
            // keystore.store_mut().id = wallet_id.to_string();
        }

        Ok(keystore)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tcx_btc_kin::BtcKinAddress;
    use tcx_common::FromHex;
    use tcx_constants::{CoinInfo, CurveType, TEST_PASSWORD, TEST_PRIVATE_KEY};
    use tcx_crypto::{EncPair, Key};
    use tcx_eos::address::EosAddress;
    use tcx_eth::address::EthAddress;
    use tcx_keystore::{Keystore, KeystoreGuard, Metadata, PrivateKeystore, Source};

    use super::LegacyKeystore;

    fn v44_bitcoin_mnemonic_1() -> (&'static str, &'static str) {
        (
        include_str!("../tests/fixtures/02a55ab6-554a-4e78-bc26-6a7acced7e5e.json"),
            "7f3ebdfe19a22e6a64be6834f61f9c79e9502a60e6b22f89654b1daae19ad2bf0c7556398713452d8bbecaae9cec1dbf116cfea89a15d4b1c23570fb95a34443",
        )
    }

    fn eos() -> &'static str {
        include_str!("../tests/fixtures/7f5406be-b5ee-4497-948c-877deab8c994.json")
    }

    fn v3_eos_private_key() -> (&'static str, &'static str) {
        (include_str!("../tests/fixtures/42c275c6-957a-49e8-9eb3-43c21cbf583f.json"),
            "6ecb361252e42b4f4e2dcd2e0c3331e8a58cb1522aee0dfad6d950b681d48fc78f11a3b12c05a56899339eef24109ea0c7c0287a1427232f04be9004fbf8f7b4")
    }

    fn v3_eth_private_key() -> (&'static str, &'static str) {
        (
            include_str!("../tests/fixtures/045861fe-0e9b-4069-92aa-0ac03cad55e0.json"),
            "d71eb325f9c20b9d84cbf44bb9a952d9a27f92672ea04de44843ca6dca3214de81ed31e0d784cd8389231057f99f9bb7caecefb578b349a355c320cd47fbb6f2",
        )
    }

    fn v3_eth_mnemonic() -> (&'static str, &'static str) {
        (
        include_str!("../tests/fixtures/175169f7-5a35-4df7-93c1-1ff612168e71.json"),
           "3223cd3abf2422d0ad3503f73aaa6e7e36a555385c6825b383908c1e8acf5e9d9a4c751809473c75599a632fe5b1437f51a3a848e054d9c170f8c3b5c5701b8b",
        )
    }

    fn identity() -> &'static str {
        include_str!("../tests/fixtures/identity.json")
    }

    fn ios_metadata() -> (&'static str, &'static str) {
        (
        include_str!("../tests/fixtures/5991857a-2488-4546-b730-463a5f84ea6a"),
        "3223cd3abf2422d0ad3503f73aaa6e7e36a555385c6825b383908c1e8acf5e9d9a4c751809473c75599a632fe5b1437f51a3a848e054d9c170f8c3b5c5701b8b",
        )
    }

    #[test]
    fn test_eos_private_key() {
        let (keystore_str, derived_key) = v3_eos_private_key();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let key = Key::DerivedKey(derived_key.to_owned());
        let mut keystore = ks.migrate(&key).unwrap();

        let coin_info = CoinInfo {
            coin: "EOS".to_string(),
            derivation_path: "m/44'/194'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        keystore.unlock(&key).unwrap();
        let eos_acc = keystore.derive_coin::<EosAddress>(&coin_info).unwrap();
        assert_eq!(
            eos_acc.address,
            "EOS8W4CoVEhTj6RHhazfw6wqtrHGk4kE4fYb2VzCexAk81SjPU1mL"
        );
    }

    #[test]
    fn test_is_same_derived_key() {
        let (keystore_str, derived_key) = v44_bitcoin_mnemonic_1();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks
            .migrate(&Key::DerivedKey(derived_key.to_string()))
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
    fn test_bitcoin_with_password() {
        let (keystore_str, _) = v44_bitcoin_mnemonic_1();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let mut keystore = ks.migrate(&Key::Password("imtoken1".to_string())).unwrap();

        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "02a55ab6-554a-4e78-bc26-6a7acced7e5e");

        let coin_info = CoinInfo {
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "TESTNET".to_string(),
            seg_wit: "NONE".to_string(),
        };

        keystore.unlock_by_password("imtoken1").unwrap();

        let acc = keystore.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
        assert_eq!("mhW3n3x8rvB5MmPXsbYDyfAGs8mhw9GGaW", acc.address);
    }

    #[test]
    fn test_v3_ethereum_private_key() {
        let (keystore_str, derived_key) = v3_eth_private_key();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();

        //password Insecure Pa55w0rd
        let key = Key::DerivedKey(derived_key.to_owned());
        let mut keystore = ks.migrate(&key).unwrap();

        assert_eq!(keystore.derivable(), false);
        assert_eq!(keystore.id(), "045861fe-0e9b-4069-92aa-0ac03cad55e0");

        let coin_info = CoinInfo {
            coin: "ETHEREUM".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        keystore.unlock(&key).unwrap();
        let acc = keystore.derive_coin::<EthAddress>(&coin_info).unwrap();
        assert_eq!("0x41983f2e3Af196C1Df429A3fF5cDECC45c82c600", acc.address);
    }

    #[test]
    fn test_v3_ethereum_mnemonic() {
        let (keystore_str, derived_key) = v3_eth_mnemonic();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        //password imtoken1
        let key = Key::DerivedKey(derived_key.to_owned());
        let mut keystore = ks.migrate(&key).unwrap();

        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "175169f7-5a35-4df7-93c1-1ff612168e71");
        let coin_info = CoinInfo {
            coin: "ETHEREUM".to_string(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        keystore.unlock(&key).unwrap();
        let acc = keystore.derive_coin::<EthAddress>(&coin_info).unwrap();
        assert_eq!("0x6031564e7b2F5cc33737807b2E58DaFF870B590b", acc.address);
    }

    #[test]
    fn test_ios_metadata() {
        let (keystore_str, derived_key) = ios_metadata();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        //password imtoken1
        let key = Key::DerivedKey(derived_key.to_owned());
        let mut keystore = ks.migrate(&key).unwrap();

        assert_eq!(keystore.derivable(), true);
        assert_eq!(keystore.id(), "5991857a-2488-4546-b730-463a5f84ea6a");
        let coin_info = CoinInfo {
            coin: "ETHEREUM".to_string(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        keystore.unlock(&key).unwrap();
        let acc = keystore.derive_coin::<EthAddress>(&coin_info).unwrap();
        assert_eq!("0x6031564e7b2F5cc33737807b2E58DaFF870B590b", acc.address);
    }

    #[test]
    fn test_export_v3_keystore() {
        let private_key_bytes = Vec::from_hex_auto(TEST_PRIVATE_KEY).unwrap();
        let v3_keystore =
            LegacyKeystore::new_v3(&private_key_bytes, TEST_PASSWORD).expect("v3 keystore");
        let keystore_json = serde_json::to_string(&v3_keystore).expect("serde v3");

        let json: Value = serde_json::from_str(&keystore_json).expect("json");

        assert_eq!(json["version"], 3);
        assert_eq!(
            json["address"],
            "0x6031564e7b2F5cc33737807b2E58DaFF870B590b"
        );
    }

    #[test]
    fn test_address_not_match() {
        let private_key_bytes = Vec::from_hex_auto(TEST_PRIVATE_KEY).unwrap();
        let mut v3_keystore =
            LegacyKeystore::new_v3(&private_key_bytes, TEST_PASSWORD).expect("v3 keystore");
        v3_keystore.address = Some("0x6031564e7b2F5cc33737807b2E58DaFF870B5900".to_string()); //wrong address
        let validate_result = v3_keystore.validate_v3(TEST_PASSWORD);
        assert_eq!(
            validate_result.err().unwrap().to_string(),
            "private_key_and_address_not_match".to_string()
        );
    }
}
