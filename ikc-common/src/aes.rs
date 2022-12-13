pub mod cbc {
    extern crate aes_soft;
    extern crate block_modes;
    use crate::Result;
    use aes_soft::Aes128;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Cbc};

    type Aes128Cbc = Cbc<Aes128, Pkcs7>;

    pub fn encrypt_pkcs7(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes128Cbc::new_var(key, iv)?;
        Ok(cipher.encrypt_vec(data))
    }
}
