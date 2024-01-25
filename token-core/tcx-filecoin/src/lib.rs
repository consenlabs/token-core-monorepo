mod address;
mod key_info;
mod signer;
mod transaction;
mod utils;

pub use crate::address::FilecoinAddress;
pub use crate::key_info::KeyInfo;
pub use crate::transaction::{SignedMessage, UnsignedMessage};

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid_curve_type")]
    InvalidCurveType,

    #[error("cannot_found_account")]
    CannotFoundAccount,

    #[error("invalid_address")]
    InvalidAddress,

    #[error("invalid_format")]
    InvalidFormat,

    #[error("invalid_param")]
    InvalidParam,

    #[error("invalid_number")]
    InvalidNumber,

    #[error("invalid_method_id")]
    InvalidMethodId,
}

pub mod filecoin {

    pub static CHAINS: [&str; 1] = ["FILECOIN"];

    pub type Address = crate::FilecoinAddress;

    pub type TransactionInput = crate::UnsignedMessage;

    pub type TransactionOutput = crate::SignedMessage;
}
