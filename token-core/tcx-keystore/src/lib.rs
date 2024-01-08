//! TokenCore Chain
//! This is an abstract package to define basic chain data structures.
#[cfg_attr(tarpaulin, ignore)]
#[macro_use]
mod macros {
    #[macro_export]
    macro_rules! tcx_ensure {
        ($cond:expr, $e:expr) => {
            if !($cond) {
                return Err($e.into());
            }
        };
    }
}

use core::result;

#[macro_use]
extern crate failure;
extern crate regex;

pub mod identity;
pub mod keystore;
mod signer;

pub use keystore::{
    fingerprint_from_mnemonic, fingerprint_from_private_key, fingerprint_from_seed,
    mnemonic_to_seed, Account, Address, HdKeystore, Keystore, KeystoreGuard, Metadata,
    PrivateKeystore, PublicKeyEncoder, Source,
};

pub use signer::{HashSigner, MessageSigner, SignatureParameters, Signer, TransactionSigner};

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
