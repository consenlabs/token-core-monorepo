pub mod ctr {
    use crate::{Error, Result};
    pub use wallet_core_common::aes::ctr::AesCtrError;

    pub fn encrypt_nopadding(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        wallet_core_common::aes::ctr::encrypt_nopadding(data, key, iv)
            .map_err(|_| Error::InvalidKeyIvLength.into())
    }

    pub fn decrypt_nopadding(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        wallet_core_common::aes::ctr::decrypt_nopadding(data, key, iv)
            .map_err(|_| Error::InvalidKeyIvLength.into())
    }
}

pub mod cbc {
    use crate::{Error, Result};
    pub use wallet_core_common::aes::cbc::AesCbcError;

    fn map_error(error: AesCbcError) -> anyhow::Error {
        match error {
            AesCbcError::InvalidKeyIvLength => Error::InvalidKeyIvLength.into(),
            AesCbcError::InvalidCiphertext => Error::InvalidCiphertext.into(),
        }
    }

    pub fn encrypt_pkcs7(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        wallet_core_common::aes::cbc::encrypt_pkcs7(data, key, iv).map_err(map_error)
    }

    pub fn decrypt_pkcs7(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        wallet_core_common::aes::cbc::decrypt_pkcs7(encrypted, key, iv).map_err(map_error)
    }
}
