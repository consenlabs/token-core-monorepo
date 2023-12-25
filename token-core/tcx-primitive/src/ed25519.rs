use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use tcx_common::{FromHex, ToHex};

use crate::Result;
use sp_core::ed25519::{Pair, Public};
use sp_core::Pair as TraitPair;
use std::convert::TryFrom;

#[derive(Clone)]
pub struct Ed25519PublicKey(pub Public);

#[derive(Clone)]
pub struct Ed25519PrivateKey(pub Pair);

impl From<Public> for Ed25519PublicKey {
    fn from(pk: Public) -> Self {
        Ed25519PublicKey(pk)
    }
}

impl From<Pair> for Ed25519PrivateKey {
    fn from(sk: Pair) -> Self {
        Ed25519PrivateKey(sk)
    }
}

impl TraitPrivateKey for Ed25519PrivateKey {
    type PublicKey = Ed25519PublicKey;

    fn from_slice(data: &[u8]) -> Result<Self> {
        if data.len() != 32 {
            return Err(KeyError::InvalidEd25519Key.into());
        }
        let pair = Pair::from_seed_slice(&data).map_err(|_| KeyError::InvalidEd25519Key)?;
        Ok(Ed25519PrivateKey(pair))
    }

    fn public_key(&self) -> Self::PublicKey {
        Ed25519PublicKey(self.0.public())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(data).0.to_vec())
    }

    fn sign_specified_hash(&self, _: &[u8], _: &str) -> Result<Vec<u8>> {
        Err(KeyError::NotImplement.into())
    }

    fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_raw_vec()
    }
}

impl std::fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TraitPublicKey for Ed25519PublicKey {
    fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(Ed25519PublicKey(
            Public::try_from(data).expect("gen ed25519 public key error"),
        ))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl ToHex for Ed25519PublicKey {
    fn to_hex(&self) -> String {
        self.0 .0.to_hex()
    }
}

impl FromHex for Ed25519PublicKey {
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self> {
        let bytes = Vec::from_hex(hex)?;
        let pk = Ed25519PublicKey::from_slice(bytes.as_slice())?;
        Ok(pk)
    }
}

#[cfg(test)]
mod test {
    use crate::ecc::KeyError;
    use crate::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use crate::{PrivateKey, PublicKey};
    use blake2b_simd::Params;
    use tcx_common::{FromHex, ToHex};
    #[test]
    fn from_slice_test() {
        let pk_bytes: Vec<u8> =
            Vec::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let sk = Ed25519PrivateKey::from_slice(&pk_bytes);
        assert!(sk.is_ok());

        let pubkey_vec = sk.unwrap().public_key();
        assert_eq!(
            pubkey_vec.to_bytes().to_hex(),
            "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        );
        assert_eq!(
            pubkey_vec.to_hex(),
            "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        );

        let public_key_obj = Ed25519PublicKey::from_hex(
            "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        );
        assert!(public_key_obj.is_ok());
    }

    #[test]
    fn sign() {
        let pk_bytes: Vec<u8> =
            Vec::from_hex("2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f")
                .unwrap();
        let sk_result = Ed25519PrivateKey::from_slice(&pk_bytes);
        assert!(sk_result.is_ok());

        let sk = sk_result.ok().unwrap();
        let msg = Vec::from_hex("03ffaa").unwrap();
        let mut params = Params::new();
        params.hash_length(32);
        let generic_hash = params.hash(&msg[..]);
        let sign_result = sk.sign(&generic_hash.as_bytes()).unwrap();
        //        println!("sign result ： {}", hex::encode(sign_result));
        let expected_val = "eaab7f4066217b072b79609a9f76cdfadd93f8dde41763887e131c02324f18c8e41b1009e334baf87f9d2e917bf4c0e73165622e5522409a0c5817234a48cc02";
        assert_eq!(sign_result.to_hex(), expected_val);
    }

    #[test]
    fn tezos_test() {
        //        let s = "edskRoRrqsGXLTjMwAtzLSx8G7s9ipibZQh6ponFhZYSReSwxwPo7qJCkPJoRjdUhz8Hj7uZhZaFp7F5yftHUYBpJwF2ZY6vAc";
        //        Ed25519PrivateKey::from_ss58check_with_version(s);
        //2bf64e07 5740dedadb610333de66ef2db2d91fd648fcbe419dff766f921ae97d536f94ce 4e26dfbb48117c6f3b3cab5049eee4d68cbef0fc0a8176e7ebb36123a28bda84
        let pk_bytes: Vec<u8> =
            Vec::from_hex("5740dedadb610333de66ef2db2d91fd648fcbe419dff766f921ae97d536f94ce")
                .unwrap();
        let sk_result = Ed25519PrivateKey::from_slice(&pk_bytes).unwrap();
        let pk = sk_result.public_key().to_hex();
        println!("{}", pk);
    }

    #[test]
    fn test_ed25519() {
        let private_key = Ed25519PrivateKey::from_slice(
            Vec::from_hex("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab401200")
                .unwrap()
                .as_slice(),
        );
        assert_eq!(
            private_key.err().unwrap().to_string(),
            KeyError::InvalidEd25519Key.to_string()
        );
    }
}
