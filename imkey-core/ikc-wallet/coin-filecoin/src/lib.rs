pub mod address;
pub mod filecoinapi;
pub mod transaction;
pub mod utils;
use core::result;
extern crate anyhow;
pub type Result<T> = result::Result<T, anyhow::Error>;
