pub mod cbc {
    use crate::error::CommonError;
    use crate::Result;

    #[inline]
    pub fn encrypt_pkcs7(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        wallet_core_common::aes::cbc::encrypt_pkcs7(data, key, iv)
            .map_err(|_| CommonError::InvalidKeyIvLength.into())
    }

    #[inline]
    pub fn decrypt_pkcs7(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        wallet_core_common::aes::cbc::decrypt_pkcs7(encrypted, key, iv)
            .map_err(|_| CommonError::InvalidKeyIvLength.into())
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
