pub mod cbc {
    use crate::error::CommonError;
    use crate::Result;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    #[inline]
    pub fn encrypt_pkcs7(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(CommonError::InvalidKeyIvLength.into());
        }
        let padding_len = 16 - (data.len() % 16);
        let mut buf = vec![0u8; data.len() + padding_len];
        let ct = Aes128CbcEnc::new(key.into(), iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf)
            .unwrap();

        Ok(ct.to_vec())
    }

    #[inline]
    pub fn decrypt_pkcs7(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(CommonError::InvalidKeyIvLength.into());
        }
        let mut buf = vec![0u8; encrypted.len()];
        let key = GenericArray::from_slice(key);
        let iv = GenericArray::from_slice(iv);
        let pt = Aes128CbcDec::new(key, iv)
            .decrypt_padded_b2b_mut::<Pkcs7>(encrypted, &mut buf)
            .unwrap();
        Ok(pt.to_vec())
    }
}

#[cfg(test)]
mod test {
    use crate::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};
    #[test]
    fn test_encrypt_pkcs7() {
        let data = "TokenCoreX".as_bytes();
        let key = hex::decode("01020304010203040102030401020304").unwrap();
        let iv = hex::decode("01020304010203040102030401020304").unwrap();
        let ret = encrypt_pkcs7(&data, &key, &iv).expect("encrypt_pkcs7");
        let ret_hex = hex::encode(ret.clone());
        assert_eq!("13d567987d7eced9c2154551bc37bc5f", ret_hex);
        let decrypted = decrypt_pkcs7(&ret, &key, &iv).unwrap();
        assert_eq!("TokenCoreX", String::from_utf8(decrypted).unwrap());

        let key = hex::decode("0102030401020304").unwrap();
        let ret = encrypt_pkcs7(&data, &key, &iv);
        assert_eq!(ret.err().unwrap().to_string(), "invalid_key_iv_length");

        let iv = hex::decode("0102030401020304").unwrap();
        let ret = encrypt_pkcs7(&data, &key, &iv);
        assert_eq!(ret.err().unwrap().to_string(), "invalid_key_iv_length");
    }
}
