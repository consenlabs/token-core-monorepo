pub mod address;
pub mod cosmosapi;
pub mod transaction;
extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
