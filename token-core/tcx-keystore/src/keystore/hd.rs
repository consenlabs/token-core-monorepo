use bip39::{Language, Mnemonic, Seed};

use crate::identity::Identity;
use uuid::Uuid;

use super::{transform_mnemonic_error, Account, Address, Error, Metadata, Result, Store};

use std::collections::HashMap;

use tcx_common::ToHex;
use tcx_constants::{CoinInfo, CurveType};
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
        if self.keys.contains_key(&cache_key) {
            Ok(self.keys[&cache_key].clone())
        } else {
            let k = f()?;
            self.keys.insert(cache_key, k.clone());
            Ok(k)
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

pub fn mnemonic_to_seed(mnemonic: &str) -> std::result::Result<Seed, Error> {
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

        cache.get_or_insert(derivation_path, curve, || {
            let root = TypedDeterministicPrivateKey::from_mnemonic(curve, &mnemonic)?;
            root.derive(derivation_path)
        })
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
        let mnemonic = &mnemonic.split_whitespace().collect::<Vec<&str>>().join(" ");
        let seed = mnemonic_to_seed(mnemonic)?;
        let fingerprint = fingerprint_from_seed(&seed)?;

        let crypto: Crypto = Crypto::new(password, mnemonic.as_bytes());
        let unlocker = crypto.use_key(&Key::Password(password.to_string()))?;
        let identity = Identity::from_seed(&seed, &unlocker, &meta.network)?;

        Ok(HdKeystore {
            store: Store {
                fingerprint,
                crypto,
                id: Uuid::new_v4().as_hyphenated().to_string(),
                version: Self::VERSION,
                meta,
                identity,
            },

            cache: None,
        })
    }

    pub fn derive_coin<A: Address>(&mut self, coin_info: &CoinInfo) -> Result<Account> {
        let cache = self.cache.as_ref().ok_or(Error::KeystoreLocked)?;

        let root = TypedDeterministicPrivateKey::from_mnemonic(coin_info.curve, &cache.mnemonic)?;

        let private_key = root.derive(&coin_info.derivation_path)?.private_key();
        let public_key = private_key.public_key();

        let address = A::from_public_key(&public_key, coin_info)?;
        let ext_pub_key = match coin_info.curve {
            CurveType::SR25519 | CurveType::BLS | CurveType::ED25519 => "".to_owned(),
            _ => root
                .derive(&get_account_path(&coin_info.derivation_path)?)?
                .deterministic_public_key()
                .to_hex(),
        };

        let account = Account {
            address: address.to_string(),
            derivation_path: coin_info.derivation_path.to_string(),
            curve: coin_info.curve,
            coin: coin_info.coin.to_string(),
            network: coin_info.network.to_string(),
            ext_pub_key,
            seg_wit: coin_info.seg_wit.to_string(),
            public_key: public_key.to_bytes().to_hex(),
        };

        return Ok(account.clone());
    }

    pub fn identity(&self) -> &Identity {
        &self.store().identity
    }

    pub(crate) fn verify_password(&self, password: &str) -> bool {
        self.store.crypto.verify_password(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{metadata_default_time, IdentityNetwork};

    use crate::keystore::tests::MockAddress;
    use crate::Source;
    use bitcoin_hashes::hex::ToHex;
    use std::string::ToString;
    use tcx_constants::{CurveType, TEST_MNEMONIC, TEST_PASSWORD};

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
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();

        assert!(keystore.verify_password(TEST_PASSWORD));
        assert!(!keystore.verify_password("WrongPassword"));
    }

    #[test]
    fn default_meta() {
        let meta = Metadata::default();
        let expected = Metadata {
            name: String::from("Unknown"),
            password_hint: String::new(),
            timestamp: metadata_default_time(),
            source: Source::Mnemonic,
            network: IdentityNetwork::Mainnet,
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
                coin: "BITCOIN".to_string(),
                derivation_path: "m/44'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "TEZOS".to_string(),
                derivation_path: "m/44'/1729'/0'/0'".to_string(),
                curve: CurveType::ED25519,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
        ];

        let excepts = [
            "03a25f12b68000000044efc688fe25a1a677765526ed6737b4bfcfb0122589caab7ca4b223ffa9bb37029d23439ecb195eb06a0d44a608960d18702fd97e19c53451f0548f568207af77",
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
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();

        let expected = Account {
            address: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            ext_pub_key: "03a25f12b68000000044efc688fe25a1a677765526ed6737b4bfcfb0122589caab7ca4b223ffa9bb37029d23439ecb195eb06a0d44a608960d18702fd97e19c53451f0548f568207af77".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            curve: CurveType::SECP256k1,
            coin: "BITCOIN".to_string(),
            public_key: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string()
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
    fn derive_key_at_paths() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let coin_info = CoinInfo {
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();

        let expected = Account {
            address: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            ext_pub_key: "03a25f12b68000000044efc688fe25a1a677765526ed6737b4bfcfb0122589caab7ca4b223ffa9bb37029d23439ecb195eb06a0d44a608960d18702fd97e19c53451f0548f568207af77".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            curve: CurveType::SECP256k1,
            coin: "BITCOIN".to_string(),
            public_key: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string()
        };

        assert_eq!(acc, expected);
    }

    #[test]
    fn test_fingerprint_from_seed() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC).unwrap();
        let fingerprint = fingerprint_from_seed(&seed).unwrap();
        assert_eq!("0x1468dba9", fingerprint);

        let seed = mnemonic_to_seed(
            "risk outer wing rent aerobic hamster island skin mistake high boost swear",
        )
        .unwrap();
        let fingerprint = fingerprint_from_seed(&seed).unwrap();
        assert_eq!("0xf6f23259", fingerprint);
    }

    #[test]
    fn test_fingerprint_from_mnemonic() {
        let fingerprint = fingerprint_from_mnemonic(TEST_MNEMONIC).unwrap();
        assert_eq!("0x1468dba9", fingerprint);

        let fingerprint = fingerprint_from_mnemonic(
            "risk outer wing rent aerobic hamster island skin mistake high boost   swear",
        )
        .unwrap();
        assert_eq!("0xf6f23259", fingerprint);
    }

    #[test]
    fn derive_key_at_paths2() {
        let mut keystore =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let coin_info = CoinInfo {
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let _ = keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();

        let expected = Account {
            address: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            ext_pub_key: "03a25f12b68000000044efc688fe25a1a677765526ed6737b4bfcfb0122589caab7ca4b223ffa9bb37029d23439ecb195eb06a0d44a608960d18702fd97e19c53451f0548f568207af77".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            curve: CurveType::SECP256k1,
            coin: "BITCOIN".to_string(),
            public_key: "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868".to_string()
        };

        assert_eq!(acc, expected);
    }
}
