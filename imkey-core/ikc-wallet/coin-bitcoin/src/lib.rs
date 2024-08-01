pub mod address;
pub mod btcapi;
pub mod common;
pub mod psbt;
pub mod transaction;
pub mod usdt_transaction;

extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
