use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use crate::Result;
use schnorrkel::keys::SecretKey;
use std::convert::TryFrom;
use tcx_common::{FromHex, ToHex};

use sp_core::sr25519::{Pair, Public};
use sp_core::Pair as TraitPair;

//use sp_core::crypto::Ss58Codec;

#[derive(Clone, Debug, PartialEq)]
pub struct Sr25519PublicKey(pub Public);

#[derive(Clone)]
pub struct Sr25519PrivateKey(pub Pair);

impl From<Public> for Sr25519PublicKey {
    fn from(pk: Public) -> Self {
        Sr25519PublicKey(pk)
    }
}

impl From<Pair> for Sr25519PrivateKey {
    fn from(sk: Pair) -> Self {
        Sr25519PrivateKey(sk)
    }
}

impl Sr25519PrivateKey {
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(data).0.to_vec())
    }
}

impl TraitPrivateKey for Sr25519PrivateKey {
    type PublicKey = Sr25519PublicKey;

    fn from_slice(data: &[u8]) -> Result<Self> {
        let sec_key =
            SecretKey::from_ed25519_bytes(data).map_err(|_| KeyError::InvalidSR25519Key)?;

        Ok(Sr25519PrivateKey(Pair::from(sec_key)))
    }

    fn public_key(&self) -> Self::PublicKey {
        Sr25519PublicKey(self.0.public())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_raw_vec();
        let secret_key = SecretKey::from_bytes(&bytes).expect("sr25519 uniform key to ed25519 key");
        secret_key.to_ed25519_bytes().to_vec()
    }
}

impl std::fmt::Display for Sr25519PublicKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TraitPublicKey for Sr25519PublicKey {
    fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(Sr25519PublicKey(
            Public::try_from(data).expect("gen sr25519 public key error"),
        ))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl ToHex for Sr25519PublicKey {
    fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl FromHex for Sr25519PublicKey {
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self> {
        let bytes = Vec::from_hex(hex)?;
        let pk = Sr25519PublicKey::from_slice(bytes.as_slice())?;
        Ok(pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tcx_common::ToHex;

    #[test]
    fn test_private_key_from_slice() {
        let pk_bytes: Vec<u8> =
            Vec::from_hex("00ea01b0116da6ca425c477521fd49cc763988ac403ab560f4022936a18a4341016e7df1f5020068c9b150e0722fea65a264d5fbb342d4af4ddf2f1cdbddf1fd")
                .unwrap();
        let pk: Sr25519PrivateKey = Sr25519PrivateKey::from_slice(&pk_bytes).unwrap();
        assert_eq!(
            &pk.to_bytes().to_hex()[64..],
            "016e7df1f5020068c9b150e0722fea65a264d5fbb342d4af4ddf2f1cdbddf1fd"
        );
        let public_key: Sr25519PublicKey = pk.public_key();
        assert_eq!(
            "fc581c897af481b10cf846d88754f1d115e486e5b7bcc39c0588c01b0a9b7a11",
            public_key.to_hex()
        );
        assert_eq!(
            "5Hma6gDS9yY7gPTuAFvmMDNcxPf9JqMZdPsaihfXiyw5NRnQ",
            format!("{}", public_key)
        );
    }

    #[test]
    fn test_sr25519_sec_key_convert() {
        let bytes = Vec::from_0x_hex("0x476c696365202020202020202020202020202020202020202020202020202020d172a74cda4c865912c32ba0a80a57ae69abae410e5ccb59dee84e2f4432db4f").unwrap();
        let ed25519_prv_key = SecretKey::from_ed25519_bytes(&bytes).unwrap();
        let ed25519_bytes = ed25519_prv_key.to_ed25519_bytes();
        let ed25519_prv_key_again = SecretKey::from_ed25519_bytes(&ed25519_bytes).unwrap();
        assert_eq!("0x406c696365202020202020202020202020202020202020202020202020202020d172a74cda4c865912c32ba0a80a57ae69abae410e5ccb59dee84e2f4432db4f", ed25519_prv_key_again.to_ed25519_bytes().to_0x_hex());

        let pair_41 = Pair::from(ed25519_prv_key);
        let pair_again = Pair::from(ed25519_prv_key_again);
        assert_eq!(pair_41.public(), pair_again.public());
    }
}
