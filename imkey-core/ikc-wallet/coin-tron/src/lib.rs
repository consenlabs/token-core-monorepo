pub mod address;
pub mod signer;
pub mod tronapi;
extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
