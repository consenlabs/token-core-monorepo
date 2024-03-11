use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tcx_common::{FromHex, ToHex};
use tcx_constants::{coin_info_from_param, CurveType};
use tcx_crypto::{Crypto, EncPair, Key};
use tcx_eos::encode_eos_wif;
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
            NumberOrNumberStr::Number(num) => *num,
            NumberOrNumberStr::NumberStr(str) => {
                f64::from_str(str).expect("f64 from timestamp") as i64
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

        let (source, identified_chain_types) =
            self.source
                .clone()
                .map_or((Source::Mnemonic, None), |source| match source.as_str() {
                    "RECOVER_IDENTITY" => (Source::Mnemonic, None),
                    "NEW_IDENTITY" => (Source::NewMnemonic, None),
                    "KEYSTORE" => (Source::KeystoreV3, Some(vec!["ETHEREUM".to_string()])),
                    "PRIVATE" => (Source::Private, Some(vec!["ETHEREUM".to_string()])),
                    "WIF" => (Source::Wif, Some(vec!["BITCOIN".to_string()])),
                    _ => (Source::from_str(&source).unwrap_or(Source::Mnemonic), None),
                });

        Metadata {
            name: self.name.clone(),
            password_hint: self.password_hint.clone(),
            timestamp,
            source,
            network,
            identified_chain_types,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EOSKeyPath {
    pub derived_mode: Option<String>,
    pub path: Option<String>,
    pub public_key: String,
    pub enc_private: Option<EncPair>,
    pub private_key: Option<EncPair>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyKeystore {
    pub version: i32,
    pub id: String,
    pub crypto: Crypto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc_mnemonic: Option<EncPair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xpub: Option<String>,
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub im_token_meta: Option<OldMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path_privates: Option<Vec<EOSKeyPath>>,
}

impl LegacyKeystore {
    pub fn new_v3(private_key: &[u8], password: &str) -> Result<Self> {
        let crypto = Crypto::new(password, private_key);
        let sec_key = Secp256k1PrivateKey::from_slice(private_key)?;
        let pub_key = TypedPublicKey::Secp256k1(sec_key.public_key());
        let coin_info = coin_info_from_param("ETHEREUM", "", "", CurveType::SECP256k1.as_str())?;
        let checksumed_address = EthAddress::from_public_key(&pub_key, &coin_info)?.to_string();
        let address = checksumed_address
            .to_lowercase()
            .strip_prefix("0x")
            .unwrap()
            .to_string();
        let id = uuid::Uuid::new_v4().to_string();
        Ok(LegacyKeystore {
            version: 3,
            id,
            crypto,
            enc_mnemonic: None,
            address: Some(address),
            mnemonic_path: None,
            im_token_meta: None,
            xpub: None,
            key_path_privates: None,
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
        let addr_bytes = &Vec::from_hex_auto(self.address.clone().unwrap())?;

        if calc_addr_bytes == addr_bytes {
            Ok(())
        } else {
            Err(anyhow!("private_key_and_address_not_match"))
        }
    }

    fn has_mnemonic(&self) -> bool {
        self.enc_mnemonic.is_some()
    }

    pub fn from_json_str(keystore_str: &str) -> Result<LegacyKeystore> {
        let keystore: LegacyKeystore = serde_json::from_str(keystore_str)?;
        if keystore.version != 44
            && keystore.version != 1
            && keystore.version != 3
            && keystore.version != 10001
        {
            return Err(anyhow!("unsupported version {}", keystore.version));
        }

        Ok(keystore)
    }

    pub fn migrate(&self, key: &Key, identity_network: &IdentityNetwork) -> Result<Keystore> {
        let keystore = if self.has_mnemonic() {
            self.migrate_to_hd(key, identity_network)?
        } else {
            self.migrate_to_private(key, identity_network)?
        };
        Ok(keystore)
    }

    fn migrate_to_hd(&self, key: &Key, identity_network: &IdentityNetwork) -> Result<Keystore> {
        let unlocker = self.crypto.use_key(key)?;
        let mnemonic_data = unlocker.decrypt_enc_pair(
            self.enc_mnemonic
                .as_ref()
                .expect("the mnemonic must be set"),
        )?;
        let mnemonic = String::from_utf8(mnemonic_data.to_owned())?;
        let seed = mnemonic_to_seed(&mnemonic)?;

        let fingerprint = fingerprint_from_seed(&seed)?;
        let meta = self
            .im_token_meta
            .as_ref()
            .expect("migration to hd need imTokenMeta")
            .to_metadata();

        let identity = Identity::from_seed(&seed, &unlocker, &identity_network)?;

        let enc_original = unlocker.encrypt_with_random_iv(mnemonic.as_bytes())?;
        let mut store = Store {
            id: self.id.to_string(),
            version: HdKeystore::VERSION,
            source_fingerprint: fingerprint,
            crypto: self.crypto.clone(),
            identity,
            meta,
            curve: None,
            enc_original,
        };

        let derived_key = unlocker.derived_key();
        store
            .crypto
            .dangerous_rewrite_plaintext(derived_key, &mnemonic_data)
            .expect("encrypt");

        let keystore = Keystore::Hd(HdKeystore::from_store(store));

        Ok(keystore)
    }

    fn migrate_to_private(
        &self,
        key: &Key,
        identity_network: &IdentityNetwork,
    ) -> Result<Keystore> {
        let unlocker = self.crypto.use_key(key)?;
        let decrypted = unlocker.plaintext()?;
        // Note legacy keystore only contains k1 curve
        let curve = CurveType::SECP256k1;
        let is_wif = decrypted.len() != 32;

        // EOS Wif Keystore store the private key in key paths
        let (private_key, original) = if let Some(key_paths) = &self.key_path_privates {
            let enc_pair_decrypted = if let Some(enc_private) = &key_paths[0].enc_private {
                unlocker.decrypt_enc_pair(enc_private)?
            } else {
                unlocker.decrypt_enc_pair(
                    &key_paths[0]
                        .private_key
                        .as_ref()
                        .expect("ios eos keystore should have private key"),
                )?
            };
            (
                Secp256k1PrivateKey::from_slice(&enc_pair_decrypted)?.to_bytes(),
                encode_eos_wif(&enc_pair_decrypted)?.as_bytes().to_vec(),
            )
        } else if is_wif {
            (
                Secp256k1PrivateKey::from_wif(&String::from_utf8_lossy(&decrypted))?.to_bytes(),
                decrypted,
            )
        } else if self.im_token_meta.is_some()
            && self.im_token_meta.as_ref().unwrap().source == Some("KEYSTORE".to_string())
        {
            let v3_keystore = LegacyKeystore {
                im_token_meta: None,
                ..self.clone()
            };
            let ks_json = serde_json::to_string(&v3_keystore)?;
            (decrypted, ks_json.as_bytes().to_vec())
        } else {
            (decrypted.clone(), decrypted.to_hex().as_bytes().to_vec())
        };

        let fingerprint = fingerprint_from_private_key(&private_key)?;
        let im_token_meta = self
            .im_token_meta
            .as_ref()
            .expect("migrate to private need imTokenMeta");

        let identity =
            Identity::from_private_key(&private_key.to_hex(), &unlocker, &identity_network)?;

        let enc_original = unlocker.encrypt_with_random_iv(&original)?;

        let mut store = Store {
            id: self.id.to_string(),
            version: PrivateKeystore::VERSION,
            source_fingerprint: fingerprint,
            crypto: self.crypto.clone(),
            meta: im_token_meta.to_metadata(),
            identity,
            curve: Some(curve),
            enc_original,
        };

        let unlocker = self.crypto.use_key(key)?;
        let derived_key = unlocker.derived_key();
        store
            .crypto
            .dangerous_rewrite_plaintext(derived_key, &private_key)
            .expect("encrypt");

        let mut keystore = Keystore::PrivateKey(PrivateKeystore::from_store(store));
        keystore.unlock(key)?;

        Ok(keystore)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tcx_btc_kin::BtcKinAddress;
    use tcx_common::FromHex;
    use tcx_constants::{CoinInfo, CurveType, TEST_PASSWORD, TEST_PRIVATE_KEY};
    use tcx_crypto::Key;
    use tcx_eos::address::{EosAddress, EosPublicKeyEncoder};
    use tcx_eth::address::EthAddress;
    use tcx_keystore::{keystore::IdentityNetwork, PublicKeyEncoder};

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
        let mut keystore = ks.migrate(&key, &IdentityNetwork::Testnet).unwrap();

        let coin_info = CoinInfo {
            coin: "EOS".to_string(),
            derivation_path: "m/44'/194'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        keystore.unlock(&key).unwrap();
        let eos_acc = keystore.derive_coin::<EosAddress>(&coin_info).unwrap();
        let address = EosPublicKeyEncoder::encode(&eos_acc.public_key, &coin_info).unwrap();
        assert_eq!(eos_acc.address, "",);

        assert_eq!(
            address,
            "EOS8W4CoVEhTj6RHhazfw6wqtrHGk4kE4fYb2VzCexAk81SjPU1mL",
        );
    }

    #[test]
    fn test_is_same_derived_key() {
        let (keystore_str, derived_key) = v44_bitcoin_mnemonic_1();
        let ks = LegacyKeystore::from_json_str(keystore_str).unwrap();
        let keystore = ks
            .migrate(
                &Key::DerivedKey(derived_key.to_string()),
                &IdentityNetwork::Testnet,
            )
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
        let mut keystore = ks
            .migrate(
                &Key::Password("imtoken1".to_string()),
                &IdentityNetwork::Testnet,
            )
            .unwrap();

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
        let mut keystore = ks.migrate(&key, &IdentityNetwork::Testnet).unwrap();

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
        let mut keystore = ks.migrate(&key, &IdentityNetwork::Testnet).unwrap();

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
        let mut keystore = ks.migrate(&key, &IdentityNetwork::Testnet).unwrap();

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
        assert_eq!(json["address"], "6031564e7b2f5cc33737807b2e58daff870b590b");
    }

    #[test]
    fn test_address_not_match() {
        let private_key_bytes = Vec::from_hex_auto(TEST_PRIVATE_KEY).unwrap();
        let mut v3_keystore =
            LegacyKeystore::new_v3(&private_key_bytes, TEST_PASSWORD).expect("v3 keystore");
        v3_keystore.address = Some("6031564e7b2f5cc33737807b2e58daff870b5900".to_string()); //wrong address
        let validate_result = v3_keystore.validate_v3(TEST_PASSWORD);
        assert_eq!(
            validate_result.err().unwrap().to_string(),
            "private_key_and_address_not_match".to_string()
        );
    }

    #[test]
    fn test_original_after_migrated_wif() {
        let json_str =
            include_str!("../../test-data/wallets-ios-2_14_1/9f4acb4a-7431-4c7d-bd25-a19656a86ea0");
        let old_ks = LegacyKeystore::from_json_str(json_str).unwrap();
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.migrate(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();

        assert_eq!(ori, "L1xDTJYPqhofU8DQCiwjStEBr1X6dhiNfweUhxhoRSgYyMJPcZ6B");
    }

    #[test]
    fn test_original_after_migrated_keystore_json() {
        let json_str =
            include_str!("../../test-data/wallets-ios-2_14_1/60573d8d-8e83-45c3-85a5-34fbb2aad5e1");
        let old_ks = LegacyKeystore::from_json_str(json_str).unwrap();
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.migrate(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();
        // ciphertext is 9b62...
        assert!(ori.contains("9b62a4c07c96ca9b0b82b5b5eae4e7c9b2b7db531a6d2991198eb6809a8c35ac"));
    }

    #[test]
    fn test_original_after_migrated_mnemonic() {
        let json_str =
            include_str!("../../test-data/wallets-ios-2_14_1/0597526e-105f-425b-bb44-086fc9dc9568");
        let old_ks = LegacyKeystore::from_json_str(json_str).unwrap();
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.migrate(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();

        assert_eq!(
            ori,
            "inject kidney empty canal shadow pact comfort wife crush horse wife sketch"
        );
    }

    #[test]
    fn test_original_after_migrated_hex() {
        let json_str =
            include_str!("../../test-data/wallets-ios-2_14_1/f3615a56-cb03-4aa4-a893-89944e49920d");
        let old_ks = LegacyKeystore::from_json_str(json_str).unwrap();
        let key = Key::DerivedKey("0x79c74b67fc73a255bc66afc1e7c25867a19e6d2afa5b8e3107a472de13201f1924fed05e811e7f5a4c3e72a8a6e047a80393c215412bde239ec7ded520896630".to_string());
        let ks = old_ks.migrate(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();

        assert_eq!(
            ori,
            "4b8e7a47497d810cd11f209b8ce9d3b0eec34e85dc8bad5d12cb602425dd3d6b"
        );
    }

    #[test]
    fn test_original_after_migrated_cosmos() {
        let json_str =
            include_str!("../../test-data/wallets-ios-2_14_1/ac59ccc1-285b-47a7-92f5-a6c432cee21a");
        let old_ks = LegacyKeystore::from_json_str(json_str).unwrap();
        let key = Key::Password(TEST_PASSWORD.to_string());
        let ks = old_ks.migrate(&key, &IdentityNetwork::Mainnet).unwrap();
        let ori = ks.backup(&key).unwrap();

        assert_eq!(
            ori,
            "inject kidney empty canal shadow pact comfort wife crush horse wife sketch"
        );
    }
}
