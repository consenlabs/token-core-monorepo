pub mod aes;
pub mod crypto;

use core::result;
pub use crypto::{Crypto, EncPair, KdfParams, Key, Pbkdf2Params, SCryptParams};
use parking_lot::RwLock;

#[macro_use]
extern crate lazy_static;

pub type Result<T> = result::Result<T, anyhow::Error>;

use thiserror::Error;

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum Error {
    #[error("kdf_params_invalid")]
    KdfParamsInvalid,
    #[error("password_incorrect")]
    PasswordIncorrect,
    #[error("derived_key_not_matched")]
    DerivedKeyNotMatched,
    #[error("invalid_key_iv_length")]
    InvalidKeyIvLength,
    #[error("invalid_ciphertext")]
    InvalidCiphertext,
    #[error("cached_dk_feature_not_support")]
    CachedDkFeatureNotSupport,
}

lazy_static! {
    pub static ref XPUB_COMMON_KEY_128: RwLock<String> =
        RwLock::new("B888D25EC8C12BD5043777B1AC49F872".to_string());
    pub static ref XPUB_COMMON_IV: RwLock<String> =
        RwLock::new("9C0C30889CBCC5E01AB5B2BB88715799".to_string());
    pub static ref KDF_ROUNDS: RwLock<i32> = RwLock::new(262144);
}
