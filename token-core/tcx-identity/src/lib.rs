pub mod constants;
pub mod identity;
pub mod imt_keystore;
pub mod model;
pub mod v3_keystore;
pub mod wallet_api;
#[macro_use]
extern crate failure;

use std::result;

pub type Result<T> = result::Result<T, failure::Error>;

#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum Error {
    #[fail(display = "network_params_invalid")]
    NetworkParamsInvalid,
    #[fail(display = "unsupported_chain")]
    WalletInvalidType,
    #[fail(display = "wallet_not_found")]
    WalletNotFound,
    #[fail(display = "keystore_file_not_exist")]
    KeystoreFileNotExist,
    #[fail(display = "password_incorrect")]
    WalletInvalidPassword,
    #[fail(display = "invalid_mnemonic")]
    InvalidMnemonic,
    #[fail(display = "unsupport_encryption_data_version")]
    UnsupportEncryptionDataVersion,
    #[fail(display = "invalid_encryption_data_signature")]
    InvalidEncryptionDataSignature,
    #[fail(display = "invalid_encryption_data")]
    InvalidEncryptionData,
}