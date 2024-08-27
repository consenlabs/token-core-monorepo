use bip39::{Language, Mnemonic, Seed};

use crate::identity::Identity;
use uuid::Uuid;

use super::{transform_mnemonic_error, Account, Address, Error, Metadata, Result, Store};

use std::collections::{hash_map::Entry, HashMap};

use tcx_common::{FromHex, ToHex};
use tcx_constants::{coin_info::get_xpub_prefix, CoinInfo, CurveType};
use tcx_crypto::{Crypto, Key};
use tcx_primitive::{
    generate_mnemonic, get_account_path, Bip32DeterministicPrivateKey, Derive,
    DeterministicPrivateKey, TypedDeterministicPrivateKey, TypedDeterministicPublicKey,
    TypedPrivateKey,
};

#[derive(Clone)]
struct Cache {
    mnemonic: String,
    keys: HashMap<String, TypedDeterministicPrivateKey>,
}

impl Cache {
    fn get_cache_key(derivation_path: &str, curve: CurveType) -> String {
        format!("{}-{}", derivation_path, curve.as_str())
    }

    pub fn get_or_insert<F>(
        &mut self,
        key: &str,
        curve: CurveType,
        f: F,
    ) -> Result<TypedDeterministicPrivateKey>
    where
        F: FnOnce() -> Result<TypedDeterministicPrivateKey>,
    {
        let cache_key = Cache::get_cache_key(key, curve);
        if let Entry::Vacant(e) = self.keys.entry(cache_key.clone()) {
            let k = f()?;
            e.insert(k.clone());
            Ok(k)
        } else {
            Ok(self.keys[&cache_key].clone())
        }
    }
}

#[derive(Clone)]
pub struct HdKeystore {
    store: Store,
    cache: Option<Cache>,
}

pub fn fingerprint_from_seed(seed: &Seed) -> Result<String> {
    let xprv = Bip32DeterministicPrivateKey::from_seed(seed.as_bytes())?;
    let xpub = xprv.deterministic_public_key();
    let fingerprint = xpub.fingerprint();
    Ok(fingerprint.to_0x_hex())
}

pub fn fingerprint_from_mnemonic(mnemonic: &str) -> Result<String> {
    let mnemonic = &mnemonic.split_whitespace().collect::<Vec<&str>>().join(" ");
    let seed = mnemonic_to_seed(mnemonic)?;
    fingerprint_from_seed(&seed)
}

pub fn mnemonic_to_seed(mnemonic: &str) -> Result<Seed> {
    let m = Mnemonic::from_phrase(mnemonic, Language::English).map_err(transform_mnemonic_error)?;
    Ok(Seed::new(&m, ""))
}

impl HdKeystore {
    pub const VERSION: i64 = 12000i64;

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    pub fn from_store(store: Store) -> Self {
        HdKeystore { store, cache: None }
    }

    pub(crate) fn unlock(&mut self, key: &Key) -> Result<()> {
        let mnemonic_bytes = self.store.crypto.use_key(key)?.plaintext()?;

        self.cache_mnemonic(mnemonic_bytes)
    }

    fn cache_mnemonic(&mut self, mnemonic_bytes: Vec<u8>) -> Result<()> {
        let mnemonic_str = String::from_utf8(mnemonic_bytes)?;
        let _ = mnemonic_to_seed(&mnemonic_str)?;

        let _mnemonic = Mnemonic::from_phrase(&mnemonic_str, Language::English);

        self.cache = Some(Cache {
            mnemonic: mnemonic_str,
            keys: HashMap::new(),
        });

        Ok(())
    }

    pub(crate) fn lock(&mut self) {
        self.cache = None;
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.cache.is_none()
    }

    pub(crate) fn mnemonic(&self) -> Result<String> {
        let cache = self.cache.as_ref().ok_or(Error::KeystoreLocked)?;

        Ok(cache.mnemonic.to_string())
    }

    pub(crate) fn get_deterministic_public_key(
        &mut self,
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<TypedDeterministicPublicKey> {
        let dpk = self.get_deterministic_private_key(curve, derivation_path)?;
        Ok(dpk.deterministic_public_key())
    }

    pub(crate) fn get_deterministic_private_key(
        &mut self,
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<TypedDeterministicPrivateKey> {
        let cache = self.cache.as_mut().ok_or(Error::KeystoreLocked)?;
        let mnemonic = cache.mnemonic.clone();

        let root = cache.get_or_insert("", curve, || {
            TypedDeterministicPrivateKey::from_mnemonic(curve, &mnemonic)
        })?;

        if derivation_path.len() > 0 {
            root.derive(derivation_path)
        } else {
            Ok(root)
        }
    }

    pub(crate) fn get_private_key(
        &mut self,
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<TypedPrivateKey> {
        let dpk = self.get_deterministic_private_key(curve, derivation_path)?;
        Ok(dpk.private_key())
    }

    pub fn new(password: &str, meta: Metadata) -> HdKeystore {
        let mnemonic = generate_mnemonic();

        Self::from_mnemonic(&mnemonic, password, meta).unwrap()
    }

    pub fn from_mnemonic(mnemonic: &str, password: &str, meta: Metadata) -> Result<HdKeystore> {
        let valid_mnemonic = &mnemonic.split_whitespace().collect::<Vec<&str>>().join(" ");
        let seed = mnemonic_to_seed(valid_mnemonic)?;
        let fingerprint = fingerprint_from_seed(&seed)?;

        let crypto: Crypto = Crypto::new(password, valid_mnemonic.as_bytes());
        let unlocker = crypto.use_key(&Key::Password(password.to_string()))?;
        let identity = Identity::from_seed(&seed, &unlocker, &meta.network)?;
        let enc_original = unlocker.encrypt_with_random_iv(mnemonic.as_bytes())?;

        Ok(HdKeystore {
            store: Store {
                source_fingerprint: fingerprint,
                crypto,
                id: Uuid::new_v4().as_hyphenated().to_string(),
                version: Self::VERSION,
                meta,
                identity,
                curve: None,
                enc_original,
            },

            cache: None,
        })
    }

    pub fn derive_coin<A: Address>(&mut self, coin_info: &CoinInfo) -> Result<Account> {
        self.cache.as_ref().ok_or(Error::KeystoreLocked)?;

        let root = self.get_deterministic_private_key(coin_info.curve, "")?;

        let private_key = root.derive(&coin_info.derivation_path)?.private_key();
        let public_key = private_key.public_key();

        let address = A::from_public_key(&public_key, coin_info)?;
        let ext_pub_key = match coin_info.curve {
            CurveType::SR25519 | CurveType::BLS | CurveType::ED25519 => "".to_owned(),
            _ => root
                .derive(&get_account_path(&coin_info.derivation_path)?)?
                .deterministic_public_key()
                .to_ss58check_with_version(&get_xpub_prefix(&coin_info.network)),
        };

        let account = Account {
            address: address.to_string(),
            derivation_path: coin_info.derivation_path.to_string(),
            curve: coin_info.curve,
            coin: coin_info.coin.to_string(),
            network: coin_info.network.to_string(),
            ext_pub_key,
            seg_wit: coin_info.seg_wit.to_string(),
            public_key: public_key,
        };

        Ok(account)
    }

    pub fn identity(&self) -> &Identity {
        &self.store().identity
    }

    pub(crate) fn verify_password(&self, key: &Key) -> bool {
        match key {
            Key::Password(password) => {
                return self.store.crypto.verify_password(password);
            }
            Key::DerivedKey(derived_key_hex) => {
                let Ok(derived_key) = Vec::from_hex_auto(derived_key_hex) else {
                    return false;
                };
                return self.store.crypto.verify_derived_key(&derived_key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{metadata_default_time, IdentityNetwork};

    use crate::keystore::tests::MockAddress;
    use crate::{Keystore, Source};
    use bitcoin_hashes::hex::ToHex;
    use std::string::ToString;
    use tcx_common::FromHex;
    use tcx_constants::{CurveType, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_primitive::{PublicKey, Secp256k1PublicKey, TypedPublicKey};
    use test::Bencher;

    // A mnemonic word separated by a full-width or half-width space
    static MNEMONIC_WITH_WHITESPACE: &'static str =
        "inject　 kidney    empty   canal shadow   pact comfort wife crush horse wife sketch";
    static INVALID_MNEMONIC1: &'static str =
        "inject kidney empty canal shadow pact comfort wife crush horse wife inject";
    static INVALID_MNEMONIC2: &'static str =
        "invalid_word kidney empty canal shadow pact comfort wife crush horse wife sketch";
    static INVALID_MNEMONIC_LEN: &'static str =
        "inject kidney empty canal shadow pact comfort wife crush horse wife";

    #[test]
    fn test_verify_password() {
        let keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();

        let derived_key = Keystore::Hd(keystore.clone())
            .get_derived_key(TEST_PASSWORD)
            .unwrap();
        assert!(keystore.verify_password(&Key::Password(TEST_PASSWORD.to_string())));
        assert!(keystore.verify_password(&Key::DerivedKey(derived_key.to_string())));
        assert!(!keystore.verify_password(&Key::Password("WRONG PASSWORD".to_string())));
        assert!(!keystore.verify_password(&Key::DerivedKey("731dd44109f9897eb39980907161b7531be44714352ddaa40542da22fb4fab7533678f2e132226389174faad4e653c542811a7b0c9391ae3cce4e75039a15adc".to_string())));
    }

    #[test]
    fn default_meta() {
        let meta = Metadata::default();
        let expected = Metadata {
            name: String::from("Unknown"),
            password_hint: None,
            timestamp: metadata_default_time(),
            source: Source::Mnemonic,
            network: IdentityNetwork::Mainnet,
            identified_chain_types: None,
        };

        assert_eq!(meta.name, expected.name);
        assert_eq!(meta.password_hint, expected.password_hint);
        assert_eq!(meta.source, expected.source);
    }

    #[test]
    fn test_new_keystore() {
        let keystore = HdKeystore::new(TEST_PASSWORD, Metadata::default());
        let store = keystore.store;

        assert_eq!(store.version, 12000);
        assert_ne!(store.id, "");
    }

    #[test]
    fn test_lock_unlock_keystore() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        assert!(!keystore.is_locked());
        keystore.lock();

        assert!(keystore.is_locked());
    }

    #[test]
    fn test_from_invalid_mnemonic() {
        let invalid_mnemonic = vec![
            (INVALID_MNEMONIC1, "mnemonic_checksum_invalid"),
            (INVALID_MNEMONIC2, "mnemonic_word_invalid"),
            (INVALID_MNEMONIC_LEN, "mnemonic_length_invalid"),
        ];
        for (mn, err) in invalid_mnemonic {
            let ks = HdKeystore::from_mnemonic(mn, TEST_PASSWORD, Metadata::default());
            assert!(ks.is_err());
            assert_eq!(err, format!("{}", ks.err().unwrap()));
        }
    }

    #[test]
    fn test_derive_account() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let coin_infos = [
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/44'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/49'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/84'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/86'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/49'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/84'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/86'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "TEZOS".to_string(),
                derivation_path: "m/44'/1729'/0'/0'".to_string(),
                curve: CurveType::ED25519,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                hrp: "".to_string(),
            },
        ];

        let excepts = [
            "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8",
            "xpub6Boii2KSAfEv7EhbBuopXKB2Gshi8kMpTGWyHuY9BHwYA8qPeu7ZYdnnXCuUdednhwyjyK2Z8gJD2AfawgBHp3Kkf2GjBjzEQAyJ3uJ4SuG",
            "xpub6CKMszasQeidek6fYD7g5N1mwUK3ouX8YHWs47MZyXh62GxsEQsU57NuN6GTS3Mh3bwykHGa14617A6HQoYFDSM9deJvgjDeEJxBYsfJ1bs",
            "xpub6CHyG1anQPWb9ss5CUeZ7cHnvoxqAZNzJBNx6fpxaWPmybH7YbJMxjp4wFp5gnxqX59hCAAbwbQTVTzAbwJsVYgBw4CYU3eAeCGn2tUajR3",
            "tpubDCpWeoTY6x4BR2PqoTFJnEdfYbjnC4G8VvKoDUPFjt2dvZJWkMRxLST1pbVW56P7zY3L5jq9MRSeff2xsLnvf9qBBN9AgvrhwfZgw5dJG6R",
            "tpubDCwNET9ErXmBracx3ZBfi6rXQZRjYkpitFe23FAW9M3RcCw4aveNC4SAV5yYrFDjtP3b46eFfv4VtiYP3EXoTZsbnJia2yNznExS8EEcACv",
            "tpubDDdrc9EkiHEiTguxsiFmoLVhgtpiqCJQk3zn1vFZPDPfbGvvQBpvsd7eZpiMntvYWGPugWndTrWskkEdyBVSCykDkmd2sCzxyf27fSKWTnB",
            "tpubDCStmH3ozU1kcGXtRW6e3yE1UoLUehvSGKBFGEjAXeE6Nk9xNWvRySanhaALGsZYU1ivo64CFYHMMdZm1EjM2Vw8uWUBqd77SCL4VCyHSoS",
            "",
        ];

        for (i, coin_info) in coin_infos.iter().enumerate() {
            let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
            assert_eq!(acc.ext_pub_key, excepts[i]);
        }
    }

    #[test]
    fn from_blank_space_mnemonic() {
        let mut keystore =
            HdKeystore::from_mnemonic(MNEMONIC_WITH_WHITESPACE, TEST_PASSWORD, Metadata::default())
                .unwrap();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            hrp: "".to_string(),
        };
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();

        let k1_pub_key = Secp256k1PublicKey::from_slice(
            &Vec::from_hex_auto(
                "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            )
            .unwrap(),
        )
        .unwrap();
        let public_key = TypedPublicKey::Secp256k1(k1_pub_key);

        let expected = Account {
            address: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            ext_pub_key: "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            curve: CurveType::SECP256k1,
            coin: "BITCOIN".to_string(),
            public_key,
        };

        assert_eq!(acc, expected);
    }

    #[test]
    fn test_from_mnemonic() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        assert_eq!(keystore.store.version, 12000);
        assert_ne!(keystore.store.id, "");
        let decrypted_bytes = keystore
            .store
            .crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .plaintext()
            .unwrap();
        let decrypted_mnemonic = String::from_utf8(decrypted_bytes).unwrap();
        assert_eq!(decrypted_mnemonic, TEST_MNEMONIC);

        keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let mnemonic = keystore.mnemonic().unwrap();
        assert_eq!(mnemonic, TEST_MNEMONIC);

        let wrong_password_err = keystore
            .unlock(&Key::Password("WrongPassword".to_owned()))
            .err()
            .unwrap();
        assert_eq!(format!("{}", wrong_password_err), "password_incorrect");
    }

    #[test]
    fn test_get_private_key() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();

        keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let public_key = keystore
            .get_private_key(CurveType::SECP256k1, "m/44'/118'/0'/0/0'")
            .unwrap();

        assert_eq!(
            "49389a85697c8e5ce78fe04d4f6bbf691216ef22101120c73853ba9e4d3105d0",
            public_key.to_bytes().to_hex()
        );
    }

    #[test]
    fn test_get_deterministic_public_key() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();

        keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let public_key = keystore
            .get_deterministic_public_key(CurveType::SECP256k1, "m/44'/118'/0'/0/0'")
            .unwrap();

        assert_eq!(
            public_key.to_string(),
            "xpub6HEP8ZcR5CFi5n4BgzE4NxX4igp2wp1yB68KySjzfMHJy3miEqLbTWFsFHbg8HENKWA64mwnikDSJ8xsf672YwsWuARauMzygaURSjqxGxk"
        );
    }

    #[test]
    fn test_derive_key_at_paths() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            hrp: "".to_string(),
        };
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();

        let k1_pub_key = Secp256k1PublicKey::from_slice(
            &Vec::from_hex_auto(
                "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            )
            .unwrap(),
        )
        .unwrap();
        let public_key = TypedPublicKey::Secp256k1(k1_pub_key);

        let expected = Account {
            address: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            ext_pub_key: "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            curve: CurveType::SECP256k1,
            coin: "BITCOIN".to_string(),
            public_key,
        };

        assert_eq!(acc, expected);
    }

    #[test]
    fn test_fingerprint_from_seed() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC).unwrap();
        let fingerprint = fingerprint_from_seed(&seed).unwrap();
        assert_eq!("0x1468dba9c246fe22183c056540ab4d8b04553217", fingerprint);

        let seed = mnemonic_to_seed(
            "risk outer wing rent aerobic hamster island skin mistake high boost swear",
        )
        .unwrap();
        let fingerprint = fingerprint_from_seed(&seed).unwrap();
        assert_eq!("0xf6f232595e79dd9723aa4e840d548e792d44aea6", fingerprint);
    }

    #[test]
    fn test_fingerprint_from_mnemonic() {
        let fingerprint = fingerprint_from_mnemonic(TEST_MNEMONIC).unwrap();
        assert_eq!("0x1468dba9c246fe22183c056540ab4d8b04553217", fingerprint);

        let fingerprint = fingerprint_from_mnemonic(
            "risk outer wing rent aerobic hamster island skin mistake high boost   swear",
        )
        .unwrap();
        assert_eq!("0xf6f232595e79dd9723aa4e840d548e792d44aea6", fingerprint);
    }

    #[test]
    fn test_derive_key_at_paths2() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            hrp: "".to_string(),
        };
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();

        let k1_pub_key = Secp256k1PublicKey::from_slice(
            &Vec::from_hex_auto(
                "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            )
            .unwrap(),
        )
        .unwrap();
        let public_key = TypedPublicKey::Secp256k1(k1_pub_key);
        let expected = Account {
            address: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            ext_pub_key: "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            curve: CurveType::SECP256k1,
            coin: "BITCOIN".to_string(),
            public_key,
        };

        assert_eq!(acc, expected);
    }

    #[bench]
    fn bench_derive_account(m: &mut Bencher) {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            hrp: "".to_string(),
        };

        m.iter(|| {
            let account = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
            assert_eq!(account.ext_pub_key, "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8");
        });
    }

    #[test]
    fn cross_test_tw() {
        let mut keystore =
            HdKeystore::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", TEST_PASSWORD, Metadata::default()).unwrap();
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let coin_infos = [
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/44'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/49'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/84'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/84'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
                hrp: "".to_string(),
            },
            CoinInfo {
                chain_id: "".to_string(),
                coin: "BITCOIN".to_string(),
                derivation_path: "m/84'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
                hrp: "".to_string(),
            },
        ];

        let excepts = [
            "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
            "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7",
            "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V",
            "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V",
            "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V",
        ];

        for (i, coin_info) in coin_infos.iter().enumerate() {
            let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
            assert_eq!(acc.ext_pub_key, excepts[i]);
        }
    }

    #[test]
    fn test_bip49_spec_vertors() {
        let mut keystore =
            HdKeystore::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", TEST_PASSWORD, Metadata::default()).unwrap();
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/49'/1'/0'".to_string(),
            curve: CurveType::SECP256k1,
            network: "TESTNET".to_string(),
            seg_wit: "NONE".to_string(),
            hrp: "".to_string(),
        };
        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
        assert_eq!(acc.ext_pub_key, "tpubDD7tXK8KeQ3YY83yWq755fHY2JW8Ha8Q765tknUM5rSvjPcGWfUppDFMpQ1ScziKfW3ZNtZvAD7M3u7bSs7HofjTD3KP3YxPK7X6hwV8Rk2");

        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/49'/1'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "TESTNET".to_string(),
            seg_wit: "NONE".to_string(),
            hrp: "".to_string(),
        };
        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
        assert_eq!(
            acc.address,
            "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        );
    }

    #[test]
    fn test_bip84_spec_vertors() {
        let mut keystore =
            HdKeystore::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", TEST_PASSWORD, Metadata::default()).unwrap();
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let mut coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/84'/0'/0'".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            hrp: "".to_string(),
        };
        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
        assert_eq!(acc.ext_pub_key, "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V");

        coin_info.derivation_path = "m/84'/0'/0'/0/0".to_string();
        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
        assert_eq!(
            acc.address,
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        );

        coin_info.derivation_path = "m/84'/0'/0'/0/1".to_string();
        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
        assert_eq!(
            acc.address,
            "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77"
        );

        coin_info.derivation_path = "m/84'/0'/0'/1/0".to_string();
        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
        assert_eq!(
            acc.address,
            "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6"
        );
    }
}
