use ed25519_dalek::VerifyingKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use std::str::FromStr;

use tcx_common::{FromHex, ToHex};

use super::Result;
use crate::ecc::KeyError;
use crate::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::{Derive, DeterministicPrivateKey, DeterministicPublicKey, PrivateKey, PublicKey};
use bip39::{Language, Mnemonic};

#[derive(Clone)]
pub struct Ed25519DeterministicPrivateKey(ExtendedSigningKey);

#[derive(Clone)]
pub struct Ed25519DeterministicPublicKey(VerifyingKey);

impl Ed25519DeterministicPrivateKey {
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let master = ExtendedSigningKey::from_seed(seed)?;
        Ok(Ed25519DeterministicPrivateKey(master))
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let mn = Mnemonic::from_phrase(mnemonic, Language::English)?;
        let seed = bip39::Seed::new(&mn, "");
        Self::from_seed(seed.as_ref())
    }
}

impl Derive for Ed25519DeterministicPrivateKey {
    fn derive(&self, path: &str) -> Result<Self> {
        let mut extended_key = self.0.clone();
        let derivation_path = DerivationPath::from_str(path);
        if let Err(_e) = derivation_path {
            return Err(KeyError::InvalidDerivationPathFormat.into());
        };
        let path: DerivationPath = path.parse()?;
        extended_key = extended_key.derive(&path)?;
        Ok(Ed25519DeterministicPrivateKey(extended_key))
    }
}

impl Derive for Ed25519DeterministicPublicKey {
    fn derive(&self, _path: &str) -> Result<Self> {
        Err(KeyError::UnsupportEd25519PubkeyDerivation.into())
    }
}

impl DeterministicPrivateKey for Ed25519DeterministicPrivateKey {
    type DeterministicPublicKey = Ed25519DeterministicPublicKey;
    type PrivateKey = Ed25519PrivateKey;

    fn from_seed(seed: &[u8]) -> Result<Self> {
        let master = ExtendedSigningKey::from_seed(seed)?;
        Ok(Ed25519DeterministicPrivateKey(master))
    }

    fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        Ok(Self::from_mnemonic(mnemonic).unwrap())
    }

    fn private_key(&self) -> Self::PrivateKey {
        Ed25519PrivateKey::from_slice(self.0.signing_key.to_bytes().as_slice()).unwrap()
    }

    fn deterministic_public_key(&self) -> Self::DeterministicPublicKey {
        Ed25519DeterministicPublicKey(self.0.signing_key.verifying_key())
    }
}

impl DeterministicPublicKey for Ed25519DeterministicPublicKey {
    type PublicKey = Ed25519PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        Ed25519PublicKey::from_slice(self.0.to_bytes().as_slice()).unwrap()
    }
}

impl ToString for Ed25519DeterministicPrivateKey {
    fn to_string(&self) -> String {
        self.0.signing_key.to_bytes().to_hex()
    }
}

impl ToString for Ed25519DeterministicPublicKey {
    fn to_string(&self) -> String {
        self.0.to_bytes().to_hex()
    }
}

impl ToHex for Ed25519DeterministicPublicKey {
    fn to_hex(&self) -> String {
        self.to_string()
    }
}

impl FromHex for Ed25519DeterministicPublicKey {
    fn from_hex<T: AsRef<[u8]>>(_: T) -> Result<Self> {
        Err(KeyError::UnsupportEd25519PubkeyDerivation.into())
    }
}

#[cfg(test)]
mod test {
    use crate::ed25519_bip32::Ed25519DeterministicPrivateKey;
    use crate::Derive;
    use tcx_common::{FromHex, ToHex};

    #[test]
    fn from_seed_test() {
        let seed = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        //master key
        let esk = Ed25519DeterministicPrivateKey::from_seed(&seed).unwrap();
        assert_eq!(
            esk.0.signing_key.to_bytes().to_hex(),
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
        );
        assert_eq!(
            esk.0.chain_code.to_hex(),
            "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
        );

        //extended key
        let path = "m/0'/2147483647'/1'/2147483646'/2'";
        let derived_result = esk.derive(path).unwrap().0;
        assert_eq!(
            derived_result.signing_key.to_bytes().to_hex(),
            "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
        );
        assert_eq!(
            derived_result.chain_code.to_hex(),
            "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
        );
    }

    #[test]
    fn test_drive_invalid_path() {
        let seed = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let esk = Ed25519DeterministicPrivateKey::from_seed(&seed).unwrap();
        let result = esk.derive("m/0'/0/x");
        assert_eq!(
            result.err().unwrap().to_string(),
            "invalid_derivation_path_format"
        );
    }
}
