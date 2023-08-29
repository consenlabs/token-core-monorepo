pub mod address;
pub mod migration;
pub mod signer;
pub mod transaction;

use core::result;

pub type Result<T> = result::Result<T, failure::Error>;
