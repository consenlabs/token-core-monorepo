pub mod address;
pub mod tezosapi;
pub mod transaction;
use core::result;
extern crate anyhow;
pub type Result<T> = result::Result<T, anyhow::Error>;
