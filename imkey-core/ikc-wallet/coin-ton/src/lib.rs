pub mod address;
pub mod signer;
pub mod tonapi;
use core::result;
extern crate anyhow;
pub type Result<T> = result::Result<T, anyhow::Error>;
