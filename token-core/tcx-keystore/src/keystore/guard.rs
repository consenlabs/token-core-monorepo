use super::Keystore;
use super::Result;

pub struct KeystoreGuard<'a> {
    keystore: &'a mut Keystore,
}

impl<'a> Drop for KeystoreGuard<'a> {
    fn drop(&mut self) {
        self.keystore.lock();
    }
}

impl<'a> KeystoreGuard<'a> {
    pub fn unlock_by_password(ks: &'a mut Keystore, password: &str) -> Result<KeystoreGuard<'a>> {
        ks.unlock_by_password(password)?;

        Ok(KeystoreGuard { keystore: ks })
    }

    pub fn unlock_by_derived_key(
        ks: &'a mut Keystore,
        derived_key: &str,
    ) -> Result<KeystoreGuard<'a>> {
        ks.unlock_by_derived_key(derived_key)?;

        Ok(KeystoreGuard { keystore: ks })
    }

    pub fn keystore_mut(&mut self) -> &mut Keystore {
        self.keystore
    }

    pub fn keystore(&self) -> &Keystore {
        self.keystore
    }
}

#[cfg(test)]
mod tests {
    use crate::{Keystore, KeystoreGuard, Metadata};
    use tcx_common::ToHex;
    use tcx_constants::sample_key::{PRIVATE_KEY, WRONG_PASSWORD};
    use tcx_constants::CurveType::SECP256k1;
    use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};

    #[test]
    fn test_keystore_failure() {
        let mut ks =
            Keystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let mut guard = KeystoreGuard::unlock_by_password(&mut ks, WRONG_PASSWORD);

        assert!(guard.is_err());
    }

    #[test]
    fn test_keystore_guard_drop() {
        let mut ks =
            Keystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        {
            let mut guard = KeystoreGuard::unlock_by_password(&mut ks, TEST_PASSWORD).unwrap();
            let private_key = guard
                .keystore_mut()
                .get_private_key(SECP256k1, "m/44'/60'/0'/0/0")
                .unwrap();

            assert_eq!(private_key.to_bytes().to_0x_hex(), PRIVATE_KEY);
            assert!(!guard.keystore().is_locked());
        }

        assert!(ks.is_locked());

        let mut ks =
            Keystore::from_private_key(PRIVATE_KEY, TEST_PASSWORD, Metadata::default()).unwrap();
        let derived_key = ks.get_derived_key(&TEST_PASSWORD).unwrap();

        {
            let guard = KeystoreGuard::unlock_by_derived_key(&mut ks, &derived_key).unwrap();
            assert!(!guard.keystore().is_locked());
        }

        assert!(ks.is_locked());
    }
}
