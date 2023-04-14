use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use crate::Result;
use blst::min_pk::{PublicKey, SecretKey};

#[derive(Clone)]
pub struct BLSPublicKey(PublicKey);

#[derive(Clone)]
pub struct BLSPrivateKey(SecretKey);

impl From<PublicKey> for BLSPublicKey {
    fn from(pk: PublicKey) -> Self {
        BLSPublicKey(pk)
    }
}

impl From<SecretKey> for BLSPrivateKey {
    fn from(sk: SecretKey) -> Self {
        BLSPrivateKey(sk)
    }
}

impl TraitPrivateKey for BLSPrivateKey {
    type PublicKey = BLSPublicKey;

    fn from_slice(data: &[u8]) -> Result<Self> {
        if data.len() < 31 || data.len() > 32 {
            return Err(KeyError::InvalidBlsKey.into());
        }
        let mut temp_data = data.to_vec();
        temp_data.reverse();
        if data.len() == 31 {
            temp_data.insert(0, 0x00);
        }
        Ok(BLSPrivateKey(
            SecretKey::from_bytes(temp_data.to_vec().as_ref()).unwrap(),
        ))
    }

    fn public_key(&self) -> Self::PublicKey {
        BLSPublicKey(self.0.sk_to_pk())
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .0
            .sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_", &[])
            .compress()
            .to_vec())
    }

    fn sign_specified_hash(&self, message: &[u8], dst: &str) -> Result<Vec<u8>> {
        Ok(self
            .0
            .sign(message, dst.as_bytes(), &[])
            .compress()
            .to_vec())
    }

    fn sign_recoverable(&self, _: &[u8]) -> Result<Vec<u8>> {
        Err(KeyError::NotImplement.into())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut private_key = self.0.serialize().to_vec();
        private_key.reverse();
        private_key
    }
}

impl TraitPublicKey for BLSPublicKey {
    fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(BLSPublicKey(PublicKey::from_bytes(data).unwrap()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::bls::BLSPrivateKey;
    use crate::{PrivateKey, PublicKey};

    #[test]
    fn test_bls_private_key() {
        let private_key = BLSPrivateKey::from_slice(
            &hex::decode("0ef71710671a9f1cfc4bd441c017c9b6db68491929facc68ab072a9676e9e23c")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(hex::encode(private_key.public_key().to_bytes()),
                   "b2be11dc8e54ee74dbc07569fd74fe03b5f52ad71cd49a8579b6c6387891f5a20ad980ec2747618c1b9ad35846a68a3e");
    }

    #[test]
    fn test_bls_private_key2() {
        let mut sec_key_bytes =
            hex::decode("068dce0c90cb428ab37a74af0191eac49648035f1aaef077734b91e05985ec55")
                .unwrap();
        sec_key_bytes.reverse();
        let private_key = BLSPrivateKey::from_slice(&sec_key_bytes).unwrap();
        assert_eq!(hex::encode(private_key.public_key().to_bytes()),
                   "99b1f1d84d76185466d86c34bde1101316afddae76217aa86cd066979b19858c2c9d9e56eebc1e067ac54277a61790db");
    }

    #[test]
    fn test_bls_sign() {
        // let private_key = BLSPrivateKey::from_slice(
        //     &hex::decode("068dce0c90cb428ab37a74af0191eac49648035f1aaef077734b91e05985ec55")
        //         .unwrap(),
        // )
        // .unwrap();
        let mut sec_key_bytes =
            hex::decode("068dce0c90cb428ab37a74af0191eac49648035f1aaef077734b91e05985ec55")
                .unwrap();
        sec_key_bytes.reverse();
        let private_key = BLSPrivateKey::from_slice(&sec_key_bytes).unwrap();
        let sign_result = private_key.sign(
            hex::decode("23ba0fe9dc5d2fae789f31fdccb4e28e74b89aec26bafdd6c96ced598542f53e")
                .unwrap()
                .as_slice(),
        );
        assert_eq!(hex::encode(sign_result.unwrap()),
                   "8c8ce9f8aedf380e47548501d348afa28fbfc282f50edf33555a3ed72eb24d710bc527b5108022cffb764b953941ec4014c44106d2708387d26cc84cbc5c546a1e6e56fdc194cf2649719e6ac149596d80c86bf6844b36bd47038ee96dd3962f");
    }
}
