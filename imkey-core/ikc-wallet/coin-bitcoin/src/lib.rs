pub mod address;
pub mod btc_kin_address;
pub mod btcapi;
mod change_candidates;
pub mod common;
mod input_proof;
pub mod message;
mod multisig;
pub mod network;
pub mod psbt;
pub mod transaction;
pub mod usdt_transaction;

extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
