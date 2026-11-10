pub use wallet_core_common::aes::ctr;

pub mod cbc {
    use crate::error::CommonError;
    use crate::Result;
    pub use wallet_core_common::aes::cbc::AesCbcError;

    fn map_error(error: AesCbcError) -> anyhow::Error {
        match error {
            AesCbcError::InvalidKeyIvLength => CommonError::InvalidKeyIvLength.into(),
            AesCbcError::InvalidCiphertext => error.into(),
        }
    }

    pub fn encrypt_pkcs7(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        wallet_core_common::aes::cbc::encrypt_pkcs7(data, key, iv).map_err(map_error)
    }

    pub fn decrypt_pkcs7(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        wallet_core_common::aes::cbc::decrypt_pkcs7(encrypted, key, iv).map_err(map_error)
    }
}
