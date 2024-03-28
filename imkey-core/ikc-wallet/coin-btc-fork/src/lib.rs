use core::result;

pub mod address;
pub mod btc_fork_network;
pub mod btcforkapi;
pub mod common;
pub mod transaction;

pub type Result<T> = result::Result<T, anyhow::Error>;
extern crate anyhow;

#[macro_use]
extern crate lazy_static;
