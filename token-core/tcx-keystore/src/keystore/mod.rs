use super::{Result, Signer};
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

mod guard;
mod hd;
mod private;

use serde::{Deserialize, Serialize};

use tcx_common::ToHex;
use tcx_constants::{CoinInfo, CurveType};
use tcx_crypto::crypto::Unlocker;

pub use self::{
    guard::KeystoreGuard, hd::key_hash_from_mnemonic, hd::HdKeystore,
    private::key_hash_from_private_key, private::PrivateKeystore,
};

use crate::identity::Identity;
use crate::signer::ChainSigner;
use tcx_crypto::{Crypto, Key};
use tcx_primitive::{Derive, TypedDeterministicPublicKey, TypedPrivateKey, TypedPublicKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Store {
    pub id: String,
    pub version: i64,
    pub key_hash: String,
    pub crypto: Crypto,
    pub identity: Identity,

    #[serde(rename = "imTokenMeta")]
    pub meta: Metadata,
}

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "mnemonic_invalid")]
    MnemonicInvalid,
    #[fail(display = "mnemonic_word_invalid")]
    MnemonicWordInvalid,
    #[fail(display = "mnemonic_length_invalid")]
    MnemonicLengthInvalid,
    #[fail(display = "mnemonic_checksum_invalid")]
    MnemonicChecksumInvalid,
    #[fail(display = "account_not_found")]
    AccountNotFound,
    #[fail(display = "can_not_derive_key")]
    CannotDeriveKey,
    #[fail(display = "keystore_locked")]
    KeystoreLocked,
    #[fail(display = "invalid_version")]
    InvalidVersion,
    #[fail(display = "pkstore_can_not_add_other_curve_account")]
    PkstoreCannotAddOtherCurveAccount,
    #[fail(display = "merge_with_different_key")]
    MergeWithDifferentKey,
}

fn transform_mnemonic_error(err: failure::Error) -> Error {
    let err = err.downcast::<bip39::ErrorKind>().unwrap();
    match err {
        bip39::ErrorKind::InvalidChecksum => Error::MnemonicChecksumInvalid,
        bip39::ErrorKind::InvalidWord => Error::MnemonicWordInvalid,
        bip39::ErrorKind::InvalidWordLength(_) => Error::MnemonicLengthInvalid,
        _ => Error::MnemonicInvalid,
    }
}

/// Account that presents one blockchain wallet on a fixtures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub address: String,
    pub derivation_path: String,
    pub curve: CurveType,
    pub coin: String,
    pub network: String,
    pub seg_wit: String,
    pub ext_pub_key: String,
    pub public_key: String,
}
impl Account {
    pub fn coin_info(&self) -> CoinInfo {
        CoinInfo {
            coin: self.coin.clone(),
            derivation_path: self.derivation_path.clone(),
            curve: self.curve,
            network: self.network.clone(),
            seg_wit: self.seg_wit.clone(),
        }
    }

    pub fn deterministic_public_key(&self) -> Result<TypedDeterministicPublicKey> {
        if !self.ext_pub_key.is_empty() {
            TypedDeterministicPublicKey::from_hex(self.curve, &self.ext_pub_key)
        } else {
            Err(Error::CannotDeriveKey.into())
        }
    }
}

/// Chain address interface, for encapsulate derivation
pub trait Address: ToString + FromStr + Sized + Clone + PartialEq + Eq {
    // Incompatible between the trait `Address:PubKey is not implemented for `&<impl curve::PrivateKey as curve::PrivateKey>::PublicKey`
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self>;

    fn is_valid(address: &str, coin: &CoinInfo) -> bool;
}

/// Source to remember which format it comes from
///
/// NOTE: Identity related type is only for imToken App v2.x
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Source {
    Wif,
    Private,
    KeystoreV3,
    Mnemonic,
    NewMnemonic,
    /*NewIdentity,
    RecoveredIdentity,
     */
}

impl FromStr for Source {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<Source, Self::Err> {
        match input {
            "WIF" => Ok(Source::Wif),
            "PRIVATE" => Ok(Source::Private),
            "KEYSTORE_V3" => Ok(Source::KeystoreV3),
            "MNEMONIC" => Ok(Source::Mnemonic),
            "NEW_MNEMONIC" => Ok(Source::NewMnemonic),
            _ => Err(format_err!("unknown_source")),
        }
    }
}
impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Source::Wif => write!(f, "WIF"),
            Source::Private => write!(f, "PRIVATE"),
            Source::KeystoreV3 => write!(f, "KEYSTORE_V3"),
            Source::Mnemonic => write!(f, "MNEMONIC"),
            Source::NewMnemonic => write!(f, "NEW_MNEMONIC"),
        }
    }
}

/// Source to remember which format it comes from
///
/// NOTE: Identity related type is only for imToken App v2.x
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityNetwork {
    Mainnet,
    Testnet,
}

impl FromStr for IdentityNetwork {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<IdentityNetwork, Self::Err> {
        match input {
            "MAINNET" => Ok(IdentityNetwork::Mainnet),
            "TESTNET" => Ok(IdentityNetwork::Testnet),
            _ => Err(format_err!("unknown_network")),
        }
    }
}

impl fmt::Display for IdentityNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IdentityNetwork::Mainnet => write!(f, "MAINNET"),
            IdentityNetwork::Testnet => write!(f, "TESTNET"),
        }
    }
}

/// Metadata of fixtures, for presenting wallet data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub name: String,
    pub password_hint: String,
    #[serde(default = "metadata_default_time")]
    pub timestamp: i64,
    #[serde(default = "metadata_default_source")]
    pub source: Source,
    #[serde(default = "metadata_default_network")]
    pub network: IdentityNetwork,
}

fn metadata_default_time() -> i64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("get timestamp");
    since_the_epoch.as_secs() as i64
}

fn metadata_default_source() -> Source {
    Source::Mnemonic
}

fn metadata_default_network() -> IdentityNetwork {
    IdentityNetwork::Mainnet
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            name: String::from("Unknown"),
            password_hint: String::new(),
            timestamp: metadata_default_time(),
            source: Source::Mnemonic,
            network: IdentityNetwork::Mainnet,
        }
    }
}

#[derive(Clone)]
pub enum Keystore {
    PrivateKey(PrivateKeystore),
    Hd(HdKeystore),
}

impl Keystore {
    pub fn from_private_key(private_key: &str, password: &str, meta: Metadata) -> Keystore {
        Keystore::PrivateKey(PrivateKeystore::from_private_key(
            private_key,
            password,
            meta,
        ))
    }

    pub fn from_mnemonic(mnemonic: &str, password: &str, metadata: Metadata) -> Result<Keystore> {
        Ok(Keystore::Hd(HdKeystore::from_mnemonic(
            mnemonic, password, metadata,
        )?))
    }

    pub fn id(&self) -> String {
        self.store().id.to_string()
    }

    pub fn set_id(&mut self, id: &str) {
        self.store_mut().id = id.to_string()
    }

    pub fn store(&self) -> &Store {
        match self {
            Keystore::PrivateKey(ks) => ks.store(),
            Keystore::Hd(ks) => ks.store(),
        }
    }

    pub fn store_mut(&mut self) -> &mut Store {
        match self {
            Keystore::PrivateKey(ks) => ks.store_mut(),
            Keystore::Hd(ks) => ks.store_mut(),
        }
    }

    pub fn meta(&self) -> Metadata {
        self.store().meta.clone()
    }

    pub fn key_hash(&self) -> &str {
        &self.store().key_hash
    }

    pub fn unlock_by_password(&mut self, password: &str) -> Result<()> {
        self.unlock(&Key::Password(password.to_owned()))
    }

    pub fn unlock_by_derived_key(&mut self, derived_key: &str) -> Result<()> {
        self.unlock(&Key::DerivedKey(derived_key.to_owned()))
    }

    pub fn unlock(&mut self, key: &Key) -> Result<()> {
        match self {
            Keystore::PrivateKey(ks) => ks.unlock(key),
            Keystore::Hd(ks) => ks.unlock(key),
        }
    }

    pub fn get_derived_key(&mut self, password: &str) -> Result<String> {
        Ok(self
            .store_mut()
            .crypto
            .use_key(&Key::Password(password.to_owned()))?
            .derived_key()
            .to_hex())
    }

    pub fn is_locked(&self) -> bool {
        match self {
            Keystore::PrivateKey(ks) => ks.is_locked(),
            Keystore::Hd(ks) => ks.is_locked(),
        }
    }

    pub fn derivable(&self) -> bool {
        match self {
            Keystore::PrivateKey(_) => false,
            Keystore::Hd(_) => true,
        }
    }

    pub fn export(&self) -> Result<String> {
        match self {
            Keystore::PrivateKey(pk_store) => pk_store.private_key(),
            Keystore::Hd(hd_store) => hd_store.mnemonic(),
        }
    }

    pub fn lock(&mut self) {
        match self {
            Keystore::PrivateKey(ks) => ks.lock(),
            Keystore::Hd(ks) => ks.lock(),
        }
    }

    pub fn derive_coin<A: Address>(&mut self, coin_info: &CoinInfo) -> Result<Account> {
        match self {
            Keystore::PrivateKey(ks) => ks.derive_coin::<A>(coin_info),
            Keystore::Hd(ks) => ks.derive_coin::<A>(coin_info),
        }
    }

    pub fn derive_coins<A: Address>(&mut self, coin_infos: &[CoinInfo]) -> Result<Vec<Account>> {
        let mut accounts = vec![];

        for coin_info in coin_infos {
            accounts.push(self.derive_coin::<A>(coin_info)?);
        }

        Ok(accounts)
    }

    pub fn derive_sub_account<A: Address>(
        xpub: &TypedDeterministicPublicKey,
        coin_info: &CoinInfo,
    ) -> Result<Account> {
        let typed_pk = xpub.derive(&coin_info.derivation_path)?.public_key();
        let address = A::from_public_key(&typed_pk, &coin_info)?.to_string();
        let account = Account {
            address,
            derivation_path: coin_info.derivation_path.to_string(),
            curve: coin_info.curve,
            coin: coin_info.coin.to_string(),
            network: coin_info.network.to_string(),
            seg_wit: coin_info.seg_wit.to_string(),
            ext_pub_key: xpub.to_string(),
            public_key: typed_pk.to_bytes().to_0x_hex(),
        };
        Ok(account)
    }

    pub fn get_private_key(
        &mut self,
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<TypedPrivateKey> {
        match self {
            Keystore::PrivateKey(ks) => ks.get_private_key(curve),
            Keystore::Hd(ks) => ks.get_private_key(curve, derivation_path),
        }
    }

    pub fn get_public_key(
        &mut self,
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<TypedPublicKey> {
        let private_key = match self {
            Keystore::PrivateKey(ks) => ks.get_private_key(curve)?,
            Keystore::Hd(ks) => ks.get_private_key(curve, derivation_path)?,
        };

        Ok(private_key.public_key())
    }

    pub fn get_deterministic_public_key(
        &mut self,
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<TypedDeterministicPublicKey> {
        match self {
            Keystore::Hd(ks) => ks.get_deterministic_public_key(curve, derivation_path),
            _ => Err(Error::CannotDeriveKey.into()),
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.store().identity
    }

    pub fn verify_password(&self, password: &str) -> bool {
        match self {
            Keystore::PrivateKey(ks) => ks.verify_password(password),
            Keystore::Hd(ks) => ks.verify_password(password),
        }
    }

    pub fn from_json(json: &str) -> Result<Keystore> {
        let store: Store = serde_json::from_str(json)?;

        match store.version {
            HdKeystore::VERSION => Ok(Keystore::Hd(HdKeystore::from_store(store))),
            PrivateKeystore::VERSION => {
                Ok(Keystore::PrivateKey(PrivateKeystore::from_store(store)))
            }

            _ => Err(Error::InvalidVersion.into()),
        }
    }

    pub fn to_json(&self) -> String {
        match self {
            Keystore::PrivateKey(ks) => serde_json::to_string(ks.store()).unwrap(),
            Keystore::Hd(ks) => serde_json::to_string(ks.store()).unwrap(),
        }
    }
}

impl Signer for Keystore {
    fn sign_hash(
        &mut self,
        hash: &[u8],
        derivation_path: &str,
        curve: &str,
        sig_alg: &str,
    ) -> Result<Vec<u8>> {
        match (curve, sig_alg.to_uppercase().as_str()) {
            ("SECP256k1", "ECDSA") => self.secp256k1_ecdsa_sign_recoverable(hash, derivation_path),
            ("bls12_381", "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_") => {
                self.bls_sign(hash, derivation_path)
            }
            ("bls12_381", "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_") => self
                .bls_sign_specified_alg(
                    hash,
                    derivation_path,
                    "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                ),
            _ => Err(format_err!("unsupport sig alg")),
        }
    }

    fn secp256k1_ecdsa_sign_recoverable(
        &mut self,
        hash: &[u8],
        derivation_path: &str,
    ) -> Result<Vec<u8>> {
        let private_key = match self {
            Keystore::PrivateKey(ks) => ks.get_private_key(CurveType::SECP256k1)?,
            Keystore::Hd(ks) => ks.get_private_key(CurveType::SECP256k1, derivation_path)?,
        };

        private_key.sign_recoverable(hash)
    }

    fn bls_sign(&mut self, hash: &[u8], derivation_path: &str) -> Result<Vec<u8>> {
        let private_key = match self {
            Keystore::PrivateKey(ks) => ks.get_private_key(CurveType::BLS)?,
            Keystore::Hd(ks) => ks.get_private_key(CurveType::BLS, derivation_path)?,
        };

        private_key.sign(hash)
    }

    fn bls_sign_specified_alg(
        &mut self,
        hash: &[u8],
        derivation_path: &str,
        sig_alg: &str,
    ) -> Result<Vec<u8>> {
        let private_key: TypedPrivateKey = match self {
            Keystore::PrivateKey(ks) => ks.get_private_key(CurveType::BLS)?,
            Keystore::Hd(ks) => ks.get_private_key(CurveType::BLS, derivation_path)?,
        };
        private_key.sign_specified_hash(hash, sig_alg)
    }

    fn schnorr_sign(&mut self, _hash: &[u8], _derivation_path: &str) -> Result<Vec<u8>> {
        todo!()
    }
}

impl ChainSigner for Keystore {
    fn sign_recoverable_hash(
        &mut self,
        data: &[u8],
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<Vec<u8>> {
        self.get_private_key(curve, derivation_path)?
            .sign_recoverable(data)
    }

    fn sign_hash(
        &mut self,
        data: &[u8],
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<Vec<u8>> {
        self.get_private_key(curve, derivation_path)?.sign(data)
    }

    fn sign_specified_hash(
        &mut self,
        data: &[u8],
        curve: CurveType,
        derivation_path: &str,
        dst: &str,
    ) -> Result<Vec<u8>> {
        self.get_private_key(curve, derivation_path)?
            .sign_specified_hash(data, dst)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::keystore::Keystore::{Hd, PrivateKey};
    use crate::{
        Address, ChainSigner, HdKeystore, Keystore, Metadata, PrivateKeystore, SignatureParameters,
        Signer, Source,
    };
    use serde_json::Value;
    use std::str::FromStr;

    use crate::keystore::metadata_default_source;
    use crate::Result;
    use tcx_common::{FromHex, ToHex};
    use tcx_constants::sample_key::WRONG_PASSWORD;
    use tcx_constants::{
        coin_info_from_param, CoinInfo, CurveType, TEST_MNEMONIC, TEST_PASSWORD, TEST_PRIVATE_KEY,
    };
    use tcx_crypto::Key;
    use tcx_primitive::{Ss58Codec, TypedPublicKey};

    #[derive(Clone, PartialEq, Eq)]
    pub(crate) struct MockAddress(Vec<u8>);
    impl Address for MockAddress {
        fn from_public_key(pk: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
            Ok(MockAddress(pk.to_bytes()))
        }

        fn is_valid(_address: &str, _coin: &CoinInfo) -> bool {
            true
        }
    }

    impl FromStr for MockAddress {
        type Err = failure::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Ok(MockAddress(Vec::from_hex(s).unwrap()))
        }
    }

    impl ToString for MockAddress {
        fn to_string(&self) -> String {
            self.0.to_hex()
        }
    }

    static HD_KEYSTORE_JSON: &'static str = r#"
        {
    "id": "7719d1e3-3f67-439f-a18e-d9ae413e00e1",
    "version": 12000,
    "keyHash": "efbe00a55ddd4c5350e295a9533d28f93cac001bfdad8cf4275140461ea03e9e",
    "crypto": {
        "cipher": "aes-128-ctr",
        "cipherparams": {
            "iv": "6006bd4e828f2f93dca31e36590ca4c9"
        },
        "ciphertext": "b06b82b8cda0bc72761177b312dfd46318248ad8473b6c97d46c44aedf6a283f44f0267dd03f210dcddf4ea1a34f85b0b02533dd9c37ce2276cb087af3e43f2a76b968e17c816ca8ea5c",
        "kdf": "pbkdf2",
        "kdfparams": {
            "c": 10240,
            "prf": "hmac-sha256",
            "dklen": 32,
            "salt": "5d85aaf812a613f810cc1cda18d35f46c013f5e537629e25372969f5f87402cd"
        },
        "mac": "56af7c5faf0a791cbb4911c4c20070156e4ad0a03f8253b2a2fb005a68d7a026"
    },
    "identity":{
        "encAuthKey":
            {
                "encStr":"ba382601567c543984778a7914d7bfb2462098a8680f36edd7ceaa1a5039e1ca",
                "nonce":"d117ae86c627850341f1a5d6bd9cd855"
            },
        "encKey":"ef806a542bcc30da7ce60fc37bd6cc91619b482f6f070af3a9d7b042087886f3",
        "identifier":"im14x5GXsdME4JsrHYe2wvznqRz4cUhx2pA4HPf",
        "ipfsId":"QmWqwovhrZBMmo32BzY83ZMEBQaP7YRMqXNmMc8mgrpzs6"
    },
    "imTokenMeta": {
        "name": "test-wallet",
        "passwordHint": "imtoken",
        "timestamp": 1575605134,
        "source": "MNEMONIC",
        "network":"MAINNET"
    }
}
"#;

    static PK_KEYSTORE_JSON: &'static str = r#"
    {"id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b","version":12001,"keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c0ecc72839f8a02cc37eb7b0dd0b93ba"},"ciphertext":"1239e5807e19f95d86567f81c162c69a5f4564ea17f487669a277334f4dcc7dc","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"3c9df9eb95a014c77bbc8b9a06f4f14e0d08170dea71189c7cf377a3b2099404"},"mac":"909a6bfe1ad031901e80927b847a8fa8407fdcde56cfa374f7a732fb3b3a882d"},"identity":{"encAuthKey":{"encStr":"ba382601567c543984778a7914d7bfb2462098a8680f36edd7ceaa1a5039e1ca","nonce":"d117ae86c627850341f1a5d6bd9cd855"},"encKey":"ef806a542bcc30da7ce60fc37bd6cc91619b482f6f070af3a9d7b042087886f3","identifier":"im14x5GXsdME4JsrHYe2wvznqRz4cUhx2pA4HPf","ipfsId":"QmWqwovhrZBMmo32BzY83ZMEBQaP7YRMqXNmMc8mgrpzs6"},"imTokenMeta":{"name":"Unknown","passwordHint":"","timestamp":1576733295,"source":"PRIVATE","network":"MAINNET"}}
    "#;

    static INVALID_PK_KEYSTORE_JSON: &'static str = r#"
    {"id":"89e6fc5d-ac9a-46ab-b53f-342a80f3d28b","version":10001,"keyHash":"4fc213ddcb6fa44a2e2f4c83d67502f88464e6ee","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"c0ecc72839f8a02cc37eb7b0dd0b93ba"},"ciphertext":"1239e5807e19f95d86567f81c162c69a5f4564ea17f487669a277334f4dcc7dc","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"3c9df9eb95a014c77bbc8b9a06f4f14e0d08170dea71189c7cf377a3b2099404"},"mac":"909a6bfe1ad031901e80927b847a8fa8407fdcde56cfa374f7a732fb3b3a882d"},"identity":{"encAuthKey":{"encStr":"ba382601567c543984778a7914d7bfb2462098a8680f36edd7ceaa1a5039e1ca","nonce":"d117ae86c627850341f1a5d6bd9cd855"},"encKey":"ef806a542bcc30da7ce60fc37bd6cc91619b482f6f070af3a9d7b042087886f3","identifier":"im14x5GXsdME4JsrHYe2wvznqRz4cUhx2pA4HPf","ipfsId":"QmWqwovhrZBMmo32BzY83ZMEBQaP7YRMqXNmMc8mgrpzs6"},"imTokenMeta":{"name":"Unknown","passwordHint":"","timestamp":1576733295,"source":"PRIVATE","network":"MAINNET"}}
    "#;

    static OLD_KEYSTORE_JSON: &'static str = r#"
    {
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "437ef8c8553df9910ad117ecec5b8c05"
    },
    "ciphertext": "acabec2bd6fab27d867ebabe0ded9c64c85aebd294d29ecf537e563474ebb931522dbb977e0644830516550255edde02c507863cb083b55f2f0f759c2f8a885a81a6518237e7b65b7cf3e912fb36e42a13a7b2df3d401e5ff778a412a6d4c5516645770c4b12f2e30551542c699eef",
    "kdf": "pbkdf2",
    "kdfparams": {
      "c": 65535,
      "dklen": 32,
      "prf": "hmac-sha256",
      "salt": "33c8f2d27fe994a1e7d51108c7811cdaa2b821cc6760ed760954b4b67a1bcd8c"
    },
    "mac": "6b86a18f4ba9f3f428e256e72a3d832dcf0cd1cb820ec61e413a64d83b012059"
  },
  "id": "02a55ab6-554a-4e78-bc26-6a7acced7e5e",
  "version": 44,
  "address": "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
  "encMnemonic": {
    "encStr": "840fad94f4bf4128f629bc1dec731d156283cc4099e3c7659a3bf382031443fcdce6debaaef444393c446d2b4007064c010f6a442b3ad0ff0851c1bd638ba251afa92d3106457bd78c49",
    "nonce": "4d691a7f0cb6396e96e8dc3e4f35dccd"
  },
  "info": {
    "curve": "spec256k1",
    "purpuse": "sign"
  },
  "mnemonicPath": "m/44'/1'/0'",
  "xpub": "tpubDCpWeoTY6x4BR2PqoTFJnEdfYbjnC4G8VvKoDUPFjt2dvZJWkMRxLST1pbVW56P7zY3L5jq9MRSeff2xsLnvf9qBBN9AgvrhwfZgw5dJG6R",
  "imTokenMeta": {
    "backup": [],
    "chainType": "BITCOIN",
    "network": "TESTNET",
    "name": "BTC",
    "passwordHint": "",
    "source": "RECOVERED_IDENTITY",
    "walletType": "HD",
    "timestamp": 1519611221,
    "segWit": "NONE"
  }
}
    "#;

    #[test]
    fn test_json() {
        let keystore: Keystore = Keystore::from_json(HD_KEYSTORE_JSON).unwrap();
        assert_eq!(
            Value::from_str(&keystore.to_json()).unwrap(),
            Value::from_str(HD_KEYSTORE_JSON).unwrap()
        );

        let keystore: Keystore = Keystore::from_json(PK_KEYSTORE_JSON).unwrap();
        assert_eq!(
            Value::from_str(&keystore.to_json()).unwrap(),
            Value::from_str(PK_KEYSTORE_JSON).unwrap()
        );

        let ret = Keystore::from_json(OLD_KEYSTORE_JSON);
        assert!(ret.is_err());
    }

    fn test_derive_coin() {}

    #[test]
    fn test_sign_hash() {
        let msg = Vec::from_hex("645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76")
            .unwrap();

        let mut keystore: Keystore = Keystore::from_json(HD_KEYSTORE_JSON).unwrap();
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            chain_type: "BITCOINCASH".to_string(),
            derivation_path: "m/44'/145'/0'/0/2".to_string(),
            ..Default::default()
        };

        let ret = keystore.secp256k1_ecdsa_sign_recoverable(&msg, &params.derivation_path);
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "keystore_locked");
        let _ = keystore.unlock_by_password(TEST_PASSWORD);
        let ret = keystore
            .secp256k1_ecdsa_sign_recoverable(&msg, &params.derivation_path)
            .unwrap();
        assert_eq!("a5c14ac7fd46f9f0c951b86d9586595270266ab09b49bf79fc27ebae786625606a7d7841fb740ee190c94dcd156228fc820f5ff5ba8c07748b220d07c51d247a01", hex::encode(ret));

        let mut keystore: Keystore = Keystore::from_json(PK_KEYSTORE_JSON).unwrap();
        let ret = keystore.secp256k1_ecdsa_sign_recoverable(&msg, "m/44'/195'/0'/0/0");
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "keystore_locked");

        let _ = keystore.unlock_by_password("imtoken1");
        let msg = Vec::from_hex("645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76")
            .unwrap();

        let ret = keystore
            .secp256k1_ecdsa_sign_recoverable(&msg, "m/44'/195'/0'/0/0")
            .unwrap();
        assert_eq!(hex::encode(ret), "8d4920cb3a5a46a3f76845e823c9531f4a882eac4ffd61bfeaa29646999a83d35c4c5537816911a8b0eb5f0e7ea09839c37e9e22bace8404d23d064c84d403d500");
    }

    #[test]
    fn test_keystore_non_sensitive() {
        let mut keystore = Keystore::from_json(HD_KEYSTORE_JSON).unwrap();
        assert_eq!(keystore.id(), "7719d1e3-3f67-439f-a18e-d9ae413e00e1");
        keystore.set_id("test_set_id");
        assert_eq!("test_set_id", keystore.id());
        assert_eq!("test-wallet", keystore.meta().name);
        assert!(keystore.derivable());
        assert_eq!(
            "efbe00a55ddd4c5350e295a9533d28f93cac001bfdad8cf4275140461ea03e9e",
            keystore.key_hash()
        );
    }

    #[test]
    fn test_keystore_unlock() {
        let mut keystore = Keystore::from_json(HD_KEYSTORE_JSON).unwrap();

        let export_ret = keystore.export();
        assert!(export_ret.is_err());
        assert_eq!(format!("{}", export_ret.err().unwrap()), "keystore_locked");
        let unlocked_ret = keystore.unlock_by_password("WRONG PASSWORD");
        assert!(unlocked_ret.is_err());
        assert_eq!(
            format!("{}", unlocked_ret.err().unwrap()),
            "password_incorrect"
        );

        assert!(keystore.verify_password(TEST_PASSWORD));
        assert!(!keystore.verify_password("WRONG PASSWORD"));
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        assert_eq!(
            "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            keystore.export().unwrap()
        );

        keystore.lock();
        let export_ret = keystore.export();
        assert!(export_ret.is_err());
        assert_eq!(format!("{}", export_ret.err().unwrap()), "keystore_locked");
    }

    #[test]
    fn test_hd_get_key() {
        let mut keystore = Keystore::from_json(HD_KEYSTORE_JSON).unwrap();
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let pk = keystore
            .get_private_key(CurveType::SECP256k1, "m/44'/0'/0'/0/0")
            .unwrap();
        assert!(pk.as_secp256k1().is_ok());

        let pk = keystore
            .get_private_key(CurveType::SECP256k1, "m/44'/0'/0'/0/0")
            .unwrap();

        /*
        assert_eq!(
                pk.as_secp256k1()
                .unwrap()
                .to_ss58check_with_version(&[0x80]),
            "L39VXyorp19JfsEJfbD7Tfr4pBEX93RJuVXW7E13C51ZYAhUWbYa"
        );

        let public_key = keystore
            .get_deterministic_public_key(
                CurveType::SECP256k1,
                "m/44'/0'/0'/0/0",
            )
            .unwrap();
        assert_eq!(public_key.to_hex(), "031064f6a580000000251d72997d4cf931a7e6819f7da37725166100fc7dae9ca6afc3f8fd8a3d3a7f0303f2f84851514bf2f40a46b5bb9dbf4e5913fbacde1a96968cda08f9fd882caa");

         */
    }

    #[test]
    fn test_pk_get_key() {
        let mut keystore = Keystore::from_json(PK_KEYSTORE_JSON).unwrap();
        keystore.unlock_by_password("imtoken1").unwrap();
        let pk = keystore.get_private_key(CurveType::SECP256k1, "").unwrap();
        assert_eq!(
            pk.to_bytes().to_hex(),
            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6"
        );

        let ret = keystore.get_deterministic_public_key(CurveType::SECP256k1, "m/44'/60'/0/0");
        assert!(ret.is_err())
    }

    #[test]
    fn test_create() {
        let hd_store = HdKeystore::new(TEST_PASSWORD, Metadata::default());
        let keystore = Hd(hd_store);
        assert!(keystore.derivable());

        let hd_store =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let keystore = Hd(hd_store);
        assert!(keystore.derivable());
        assert_eq!(
            keystore.key_hash(),
            "512115eca3ae86646aeb06861d551e403b543509"
        );

        let meta = Metadata {
            name: "test_create".to_string(),
            password_hint: TEST_PASSWORD.to_string(),
            source: Source::Private,
            ..Metadata::default()
        };
        let pk_store = PrivateKeystore::from_private_key(
            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
            TEST_PASSWORD,
            meta,
        );
        let keystore = PrivateKey(pk_store);
        assert!(!keystore.derivable());

        let ret = HdKeystore::from_mnemonic(
            format!("{} hello", TEST_MNEMONIC).as_str(),
            TEST_PASSWORD,
            Metadata::default(),
        );
        assert!(ret.is_err())
    }

    #[test]
    fn test_default_source() {
        assert_eq!(metadata_default_source(), Source::Mnemonic);
    }

    #[test]
    fn test_hd_keystore() {
        let mut keystore =
            Keystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();

        assert!(keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .is_ok());

        assert!(keystore.derivable());
        assert!(!keystore.is_locked());
        assert_ne!(keystore.identity().ipfs_id, "");
        assert!(keystore.identity().identifier.starts_with("im"));
        assert_eq!(keystore.meta().name, "Unknown");
        assert_ne!(keystore.id(), "");

        assert!(keystore.verify_password(&TEST_PASSWORD));
        assert!(!keystore.verify_password(&WRONG_PASSWORD));
    }

    #[test]
    fn test_private_keystore() {
        let mut keystore =
            Keystore::from_private_key(TEST_PRIVATE_KEY, TEST_PASSWORD, Metadata::default());

        assert!(keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .is_ok());

        assert!(!keystore.derivable());
        assert!(!keystore.is_locked());
        assert_ne!(keystore.identity().ipfs_id, "");
        assert!(keystore.identity().identifier.starts_with("im"));
        assert_eq!(keystore.meta().name, "Unknown");
        assert_ne!(keystore.id(), "");

        assert!(keystore.verify_password(&TEST_PASSWORD));
        assert!(!keystore.verify_password(&WRONG_PASSWORD));
    }

    #[test]
    fn test_from_invalid_json() {
        let ret = Keystore::from_json("{}");
        assert!(ret.is_err());

        let ret = Keystore::from_json(INVALID_PK_KEYSTORE_JSON);
        assert_eq!(format!("{}", ret.err().unwrap()), "invalid_version")
    }
}