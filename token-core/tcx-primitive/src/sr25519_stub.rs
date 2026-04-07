use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use crate::{Derive, Result};
use tcx_common::{FromHex, ToHex};

#[derive(Clone, Debug, PartialEq)]
pub struct Sr25519PublicKey(pub Vec<u8>);

#[derive(Clone)]
pub struct Sr25519PrivateKey(pub Vec<u8>);

impl Sr25519PrivateKey {
    pub fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
        Err(KeyError::InvalidSR25519Key.into())
    }
}

impl TraitPrivateKey for Sr25519PrivateKey {
    type PublicKey = Sr25519PublicKey;

    fn from_slice(_data: &[u8]) -> Result<Self> {
        Err(KeyError::InvalidSR25519Key.into())
    }

    fn public_key(&self) -> Self::PublicKey {
        Sr25519PublicKey(vec![])
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl TraitPublicKey for Sr25519PublicKey {
    fn from_slice(_data: &[u8]) -> Result<Self> {
        Err(KeyError::InvalidSR25519Key.into())
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl std::fmt::Display for Sr25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "")
    }
}

impl ToHex for Sr25519PublicKey {
    fn to_hex(&self) -> String {
        String::new()
    }
}

impl FromHex for Sr25519PublicKey {
    fn from_hex<T: AsRef<[u8]>>(_hex: T) -> Result<Self> {
        Err(KeyError::InvalidSR25519Key.into())
    }
}

impl Derive for Sr25519PrivateKey {
    fn derive(&self, _path: &str) -> Result<Self> {
        Err(KeyError::InvalidSR25519Key.into())
    }
}

impl Derive for Sr25519PublicKey {
    fn derive(&self, _path: &str) -> Result<Self> {
        Err(KeyError::InvalidSR25519Key.into())
    }
}

impl crate::ecc::DeterministicPrivateKey for Sr25519PrivateKey {
    type DeterministicPublicKey = Sr25519PublicKey;
    type PrivateKey = Sr25519PrivateKey;

    fn from_seed(_seed: &[u8]) -> Result<Self> {
        Err(KeyError::InvalidSR25519Key.into())
    }

    fn from_mnemonic(_mnemonic: &str) -> Result<Self> {
        Err(KeyError::InvalidSR25519Key.into())
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.clone()
    }

    fn deterministic_public_key(&self) -> Self::DeterministicPublicKey {
        Sr25519PublicKey(vec![])
    }
}

impl crate::ecc::DeterministicPublicKey for Sr25519PublicKey {
    type PublicKey = Sr25519PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.clone()
    }
}
