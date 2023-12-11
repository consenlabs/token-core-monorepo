use super::Account;
use super::{Address, Metadata};
use tcx_constants::{CoinInfo, CurveType};
use tcx_crypto::{Crypto, Key};

use super::Error;
use super::Result;
use crate::identity::Identity;
use crate::keystore::Store;

use tcx_common::{sha256d, FromHex, ToHex};
use tcx_primitive::TypedPrivateKey;
use uuid::Uuid;

pub fn key_hash_from_private_key(data: &[u8]) -> String {
    sha256d(data)[..20].to_hex()
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

    pub(crate) fn unlock_by_password(&mut self, password: &str) -> Result<()> {
        self.private_key = Some(self.decrypt_private_key(&Key::Password(password.to_owned()))?);

        Ok(())
    }

    pub(crate) fn unlock_by_derived_key(&mut self, derived_key: &str) -> Result<()> {
        self.private_key =
            Some(self.decrypt_private_key(&Key::DerivedKey(derived_key.to_owned()))?);

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

    pub fn from_private_key(private_key: &str, password: &str, meta: Metadata) -> PrivateKeystore {
        let key_data: Vec<u8> = Vec::from_hex_auto(private_key).expect("hex can't decode");
        let key_hash = key_hash_from_private_key(&key_data);
        //        let pk_bytes = Vec::from_hex(private_key).expect("valid private_key");
        let crypto: Crypto = Crypto::new(password, &key_data);
        let unlocker = crypto
            .use_key(&Key::Password(password.to_string()))
            .expect("create private keystore to get unlocker");
        let identity = Identity::from_private_key(private_key, &unlocker, &meta.network)
            .expect("identity from private key");

        let store = Store {
            key_hash,
            crypto,
            meta,
            id: Uuid::new_v4().as_hyphenated().to_string(),
            version: PrivateKeystore::VERSION,
            identity,
        };

        PrivateKeystore {
            store,
            private_key: None,
        }
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
    pub(crate) fn private_key(&self) -> Result<String> {
        tcx_ensure!(self.private_key.is_some(), Error::KeystoreLocked);
        let vec = self.private_key.as_ref().unwrap().to_vec();
        Ok(vec.to_hex())
    }

    fn decrypt_private_key(&self, key: &Key) -> Result<Vec<u8>> {
        self.store.crypto.use_key(key)?.plaintext()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Metadata, PrivateKeystore, Source};
    use tcx_constants::TEST_PASSWORD;

    #[test]
    pub fn test_from_private_key() {
        let meta = Metadata {
            name: "from_private_key_test".to_string(),
            source: Source::Private,
            ..Metadata::default()
        };
        let keystore = PrivateKeystore::from_private_key(
            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
            TEST_PASSWORD,
            meta,
        );
        assert_eq!(keystore.store.version, 12001);
        assert_ne!(keystore.store.id, "");
    }
}
