//! TokenCore Chain
//! This is an abstract package to define basic chain data structures.
#![feature(test)]
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

use thiserror::Error;

pub type Result<T> = result::Result<T, anyhow::Error>;

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum Error {
    #[error("network_params_invalid")]
    NetworkParamsInvalid,
    #[error("unsupported_chain")]
    WalletInvalidType,
    #[error("wallet_not_found")]
    WalletNotFound,
    #[error("keystore_file_not_exist")]
    KeystoreFileNotExist,
    #[error("password_incorrect")]
    WalletInvalidPassword,
    #[error("invalid_mnemonic")]
    InvalidMnemonic,
    #[error("unsupport_encryption_data_version")]
    UnsupportEncryptionDataVersion,
    #[error("invalid_encryption_data_signature")]
    InvalidEncryptionDataSignature,
    #[error("invalid_encryption_data")]
    InvalidEncryptionData,
}

#[cfg(test)]
extern crate test;
