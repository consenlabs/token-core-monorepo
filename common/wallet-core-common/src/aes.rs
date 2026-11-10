pub mod ctr {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use std::error::Error;
    use std::fmt;

    type Aes128CtrEnc = ::ctr::Ctr128BE<aes::Aes128>;
    type Aes128CtrDec = ::ctr::Ctr128BE<aes::Aes128>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AesCtrError {
        InvalidKeyIvLength,
    }

    impl fmt::Display for AesCtrError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                AesCtrError::InvalidKeyIvLength => f.write_str("invalid_key_iv_length"),
            }
        }
    }

    impl Error for AesCtrError {}

    #[inline]
    pub fn encrypt_nopadding(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, AesCtrError> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(AesCtrError::InvalidKeyIvLength);
        }
        let mut cipher =
            Aes128CtrEnc::new_from_slices(key, iv).map_err(|_| AesCtrError::InvalidKeyIvLength)?;
        let mut data_copy = data.to_vec();
        cipher.apply_keystream(&mut data_copy);
        Ok(data_copy)
    }

    #[inline]
    pub fn decrypt_nopadding(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, AesCtrError> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(AesCtrError::InvalidKeyIvLength);
        }
        let mut cipher =
            Aes128CtrDec::new_from_slices(key, iv).map_err(|_| AesCtrError::InvalidKeyIvLength)?;
        let mut data_copy = data.to_vec();
        cipher.apply_keystream(&mut data_copy);
        Ok(data_copy)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encrypts_aes_128_ctr_without_padding() {
            let data = b"TokenCoreX";
            let key = hex::decode("01020304010203040102030401020304").unwrap();
            let iv = hex::decode("01020304010203040102030401020304").unwrap();

            let encrypted = encrypt_nopadding(data, &key, &iv).unwrap();
            assert_eq!(hex::encode(encrypted), "e19e6c5923d33c587cf8");
        }

        #[test]
        fn decrypts_aes_128_ctr_without_padding() {
            let encrypted = hex::decode("e19e6c5923d33c587cf8").unwrap();
            let key = hex::decode("01020304010203040102030401020304").unwrap();
            let iv = hex::decode("01020304010203040102030401020304").unwrap();

            let decrypted = decrypt_nopadding(&encrypted, &key, &iv).unwrap();
            assert_eq!(decrypted, b"TokenCoreX");
        }

        #[test]
        fn rejects_wrong_key_or_iv_length() {
            let data = b"TokenCoreX";
            let key = hex::decode("0102030401020304").unwrap();
            let iv = hex::decode("01020304010203040102030401020304").unwrap();

            assert_eq!(
                encrypt_nopadding(data, &key, &iv).unwrap_err().to_string(),
                "invalid_key_iv_length"
            );

            assert_eq!(
                decrypt_nopadding(data, &key, &iv).unwrap_err().to_string(),
                "invalid_key_iv_length"
            );
        }
    }
}

pub mod cbc {
    use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
    use std::error::Error;
    use std::fmt;

    type Aes128CbcEnc = ::cbc::Encryptor<aes::Aes128>;
    type Aes128CbcDec = ::cbc::Decryptor<aes::Aes128>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AesCbcError {
        InvalidKeyIvLength,
        InvalidCiphertext,
    }

    impl fmt::Display for AesCbcError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                AesCbcError::InvalidKeyIvLength => f.write_str("invalid_key_iv_length"),
                AesCbcError::InvalidCiphertext => f.write_str("invalid_ciphertext"),
            }
        }
    }

    impl Error for AesCbcError {}

    #[inline]
    pub fn encrypt_pkcs7(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, AesCbcError> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(AesCbcError::InvalidKeyIvLength);
        }

        let padding_len = 16 - (data.len() % 16);
        let mut buf = vec![0u8; data.len() + padding_len];
        let ct = Aes128CbcEnc::new_from_slices(key, iv)
            .map_err(|_| AesCbcError::InvalidKeyIvLength)?
            .encrypt_padded_b2b::<Pkcs7>(data, &mut buf)
            .expect("pkcs7 encryption buffer has enough capacity");

        Ok(ct.to_vec())
    }

    #[inline]
    pub fn decrypt_pkcs7(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, AesCbcError> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(AesCbcError::InvalidKeyIvLength);
        }

        let mut buf = vec![0u8; encrypted.len()];
        let pt = Aes128CbcDec::new_from_slices(key, iv)
            .map_err(|_| AesCbcError::InvalidKeyIvLength)?
            .decrypt_padded_b2b::<Pkcs7>(encrypted, &mut buf)
            .map_err(|_| AesCbcError::InvalidCiphertext)?;
        Ok(pt.to_vec())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encrypts_and_decrypts_aes_128_cbc_pkcs7() {
            let data = b"TokenCoreX";
            let key = hex::decode("01020304010203040102030401020304").unwrap();
            let iv = hex::decode("01020304010203040102030401020304").unwrap();

            let encrypted = encrypt_pkcs7(data, &key, &iv).unwrap();
            assert_eq!(hex::encode(&encrypted), "13d567987d7eced9c2154551bc37bc5f");
            assert_eq!(decrypt_pkcs7(&encrypted, &key, &iv).unwrap(), data);
        }

        #[test]
        fn rejects_wrong_key_or_iv_length() {
            let data = b"TokenCoreX";
            let key = hex::decode("0102030401020304").unwrap();
            let iv = hex::decode("01020304010203040102030401020304").unwrap();

            assert_eq!(
                encrypt_pkcs7(data, &key, &iv).unwrap_err().to_string(),
                "invalid_key_iv_length"
            );
        }

        #[test]
        fn rejects_malformed_ciphertext_without_panicking() {
            let key = hex::decode("01020304010203040102030401020304").unwrap();
            let iv = hex::decode("01020304010203040102030401020304").unwrap();
            let encrypted = hex::decode("13d567987d7eced9c2154551bc37bc00").unwrap();

            let err = decrypt_pkcs7(&encrypted, &key, &iv).unwrap_err();
            assert_eq!(err, AesCbcError::InvalidCiphertext);
            assert_eq!(err.to_string(), "invalid_ciphertext");
        }
    }
}
