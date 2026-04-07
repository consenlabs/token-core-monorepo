use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use crate::Result;
use tcx_common::{FromHex, ToHex};

#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519PublicKey(pub Vec<u8>);

#[derive(Clone)]
pub struct Ed25519PrivateKey(pub Vec<u8>);

impl Ed25519PrivateKey {
    pub fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Err(KeyError::InvalidCurveType.into())
    }
}

impl TraitPrivateKey for Ed25519PrivateKey {
    type PublicKey = Ed25519PublicKey;

    fn from_slice(data: &[u8]) -> Result<Self> {
        if data.len() != 32 {
            return Err(KeyError::InvalidEd25519Key.into());
        }
        Ok(Ed25519PrivateKey(data.to_vec()))
    }

    fn public_key(&self) -> Self::PublicKey {
        Ed25519PublicKey(self.0.clone())
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl std::fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl TraitPublicKey for Ed25519PublicKey {
    fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(Ed25519PublicKey(data.to_vec()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl ToHex for Ed25519PublicKey {
    fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl FromHex for Ed25519PublicKey {
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self> {
        let bytes = Vec::from_hex(hex)?;
        Ok(Ed25519PublicKey(bytes))
    }
}
