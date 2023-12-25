use super::Account;
use super::{Address, Metadata};
use tcx_constants::{CoinInfo, CurveType};
use tcx_crypto::{Crypto, Key};

use super::Error;
use super::Result;
use crate::identity::Identity;
use crate::keystore::Store;

use tcx_common::{ripemd160, sha256, FromHex, ToHex};
use tcx_primitive::{
    PrivateKey, PublicKey, Secp256k1PrivateKey, Sr25519PrivateKey, TypedPrivateKey,
};
use uuid::Uuid;

pub fn fingerprint_from_private_key(data: &[u8]) -> Result<String> {
    let public_key_data = if data.len() == 32 {
        let private_key = Secp256k1PrivateKey::from_slice(data)?;
        private_key.public_key().to_compressed()
    } else {
        let private_key = Sr25519PrivateKey::from_slice(data)?;
        private_key.public_key().to_bytes()
    };
    let hashed = ripemd160(&sha256(&public_key_data));
    Ok(hashed[0..4].to_0x_hex())
}

#[derive(Clone)]
pub struct PrivateKeystore {
    store: Store,

    private_key: Option<Vec<u8>>,
}

impl PrivateKeystore {
    pub const VERSION: i64 = 12001i64;
    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    pub fn from_store(store: Store) -> Self {
        PrivateKeystore {
            store,
            private_key: None,
        }
    }

    pub(crate) fn unlock(&mut self, key: &Key) -> Result<()> {
        self.private_key = Some(self.decrypt_private_key(key)?);

        Ok(())
    }

    pub(crate) fn lock(&mut self) {
        self.private_key = None;
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.private_key.is_none()
    }

    pub(crate) fn get_private_key(&self, curve: CurveType) -> Result<TypedPrivateKey> {
        tcx_ensure!(self.private_key.is_some(), Error::KeystoreLocked);

        let private_key = self.private_key.as_ref().unwrap().as_slice();

        TypedPrivateKey::from_slice(curve, private_key)
    }

    pub(crate) fn derive_coin<A: Address>(&mut self, coin_info: &CoinInfo) -> Result<Account> {
        tcx_ensure!(self.private_key.is_some(), Error::KeystoreLocked);

        let sk = self.private_key.as_ref().unwrap();

        let account = Self::private_key_to_account::<A>(coin_info, sk)?;

        Ok(account)
    }

    pub(crate) fn verify_password(&self, password: &str) -> bool {
        self.store.crypto.verify_password(password)
    }

    pub fn from_private_key(
        private_key: &str,
        password: &str,
        meta: Metadata,
    ) -> Result<PrivateKeystore> {
        let key_data: Vec<u8> = Vec::from_hex_auto(private_key)?;
        let fingerprint = fingerprint_from_private_key(&key_data)?;
        let crypto: Crypto = Crypto::new(password, &key_data);
        let unlocker = crypto.use_key(&Key::Password(password.to_string()))?;
        // TODO: if a identity from 64bytes private key
        let identity = Identity::from_private_key(private_key, &unlocker, &meta.network)?;

        let store = Store {
            fingerprint,
            crypto,
            meta,
            id: Uuid::new_v4().as_hyphenated().to_string(),
            version: PrivateKeystore::VERSION,
            identity,
        };

        Ok(PrivateKeystore {
            store,
            private_key: None,
        })
    }

    pub(crate) fn private_key_to_account<A: Address>(
        coin: &CoinInfo,
        private_key: &[u8],
    ) -> Result<Account> {
        let tsk = TypedPrivateKey::from_slice(coin.curve, private_key)?;
        let pub_key = tsk.public_key();
        let address = A::from_public_key(&pub_key, coin)?;

        let acc = Account {
            address: address.to_string(),
            derivation_path: "".to_string(),
            curve: coin.curve,
            coin: coin.coin.to_owned(),
            network: coin.network.to_string(),
            seg_wit: coin.seg_wit.to_string(),
            ext_pub_key: "".to_string(),
            public_key: pub_key.to_bytes().to_hex(),
        };

        Ok(acc)
    }

    fn decrypt_private_key(&self, key: &Key) -> Result<Vec<u8>> {
        self.store.crypto.use_key(key)?.plaintext()
    }

    pub(crate) fn private_key(&self) -> Result<String> {
        tcx_ensure!(self.private_key.is_some(), Error::KeystoreLocked);
        let vec = self.private_key.as_ref().unwrap().to_vec();
        Ok(vec.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use crate::keystore::private::fingerprint_from_private_key;
    use crate::keystore::tests::MockAddress;
    use crate::{Metadata, PrivateKeystore, Source};
    use tcx_common::FromHex;
    use tcx_constants::{CoinInfo, CurveType, TEST_MNEMONIC, TEST_PASSWORD, TEST_PRIVATE_KEY};
    use tcx_crypto::Key;

    #[test]
    fn test_from_private_key() {
        let meta = Metadata {
            name: "from_private_key_test".to_string(),
            source: Source::Private,
            ..Metadata::default()
        };
        let mut keystore = PrivateKeystore::from_private_key(
            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
            TEST_PASSWORD,
            meta,
        )
        .unwrap();

        keystore
            .unlock(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap();

        assert_eq!(keystore.store.version, 12001);
        assert_ne!(keystore.store.id, "");
        assert_eq!(
            keystore.private_key().unwrap(),
            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6"
        );
    }

    #[test]
    fn test_verify_password() {
        let mut keystore =
            PrivateKeystore::from_private_key(TEST_PRIVATE_KEY, TEST_PASSWORD, Metadata::default())
                .unwrap();

        assert!(keystore.verify_password(TEST_PASSWORD));
        assert!(!keystore.verify_password("WrongPassword"));
    }

    #[test]
    fn test_fingerprint_from_private_key() {
        let pk_data = &Vec::<u8>::from_hex(
            "ad87a08796efbdd9276e2ca5a10f938937cb5d2b7d5f698c06a94d8eeed3f6ae",
        )
        .unwrap();
        let fingerprint = fingerprint_from_private_key(&pk_data).unwrap();
        assert_eq!(fingerprint, "0x1468dba9");

        let pk_data = &Vec::<u8>::from_hex(
            "257cd2f8eb13f6930ecb95ac7736dd25e65d231ce1a3b1669e51f6737350b43e",
        )
        .unwrap();
        let fingerprint = fingerprint_from_private_key(&pk_data).unwrap();
        assert_eq!(fingerprint, "0xf6f23259");

        let pk_data = &Vec::<u8>::from_hex(
            "ad87a08796efbdd9276e2ca5a10f938937cb5d2b7d5f698c06a94d8eeed3f600257cd2f8eb13f6930ecb95ac7736dd25e65d231ce1a3b1669e51f6737350b43e",
        )
            .unwrap();
        let fingerprint = fingerprint_from_private_key(&pk_data).unwrap();
        assert_eq!(fingerprint, "0x06bd6171");
    }

    #[test]
    fn test_derive_coin() {
        let mut keystore =
            PrivateKeystore::from_private_key(TEST_PRIVATE_KEY, TEST_PASSWORD, Metadata::default())
                .unwrap();
        keystore
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
            "0280c98b8ea7cab630defb0c09a4295c2193cdee016c1d5b9b0cb18572b9c370fe",
            "a57c4fbab1f0a4ba7b4a2800db95c30d7e94f9e80c699823edb2cd5b9af19097",
        ];

        for (i, coin_info) in coin_infos.iter().enumerate() {
            let acc = keystore.derive_coin::<MockAddress>(&coin_info).unwrap();
            assert_eq!(acc.public_key, excepts[i]);
        }
    }
}
