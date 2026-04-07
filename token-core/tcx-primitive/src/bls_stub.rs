use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use crate::Result;

#[derive(Clone, Debug, PartialEq)]
pub struct BLSPublicKey;

#[derive(Clone)]
pub struct BLSPrivateKey;

impl BLSPrivateKey {
    pub fn sign(&self, _message: &[u8], _dst: &str) -> Result<Vec<u8>> {
        Err(KeyError::InvalidCurveType.into())
    }
}

impl TraitPrivateKey for BLSPrivateKey {
    type PublicKey = BLSPublicKey;

    fn from_slice(_data: &[u8]) -> Result<Self> {
        Err(KeyError::InvalidBlsKey.into())
    }

    fn public_key(&self) -> Self::PublicKey {
        BLSPublicKey
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl TraitPublicKey for BLSPublicKey {
    fn from_slice(_data: &[u8]) -> Result<Self> {
        Err(KeyError::InvalidBlsKey.into())
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}
