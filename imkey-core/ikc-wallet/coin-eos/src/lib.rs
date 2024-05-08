pub mod eosapi;
pub mod pubkey;
pub mod transaction;
extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
