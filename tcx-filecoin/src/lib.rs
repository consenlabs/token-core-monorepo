use failure::Fail;

mod address;
mod key_info;
mod signer;
mod transaction;
mod utils;

pub use crate::address::FilecoinAddress;
pub use crate::key_info::KeyInfo;
pub use crate::transaction::{SignedMessage, UnsignedMessage};
#[macro_use]
extern crate failure;

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_curve_type")]
    InvalidCurveType,

    #[fail(display = "cannot_found_account")]
    CannotFoundAccount,

    #[fail(display = "invalid_address")]
    InvalidAddress,

    #[fail(display = "invalid_format")]
    InvalidFormat,

    #[fail(display = "invalid_param")]
    InvalidParam,

    #[fail(display = "invalid_number")]
    InvalidNumber,
}
