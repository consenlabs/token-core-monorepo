pub mod constants;
pub mod identity;
pub mod imt_keystore;
pub mod model;
pub mod v3_keystore;
pub mod wallet_api;
#[macro_use]
extern crate failure;

use std::result;

pub type Result<T> = result::Result<T, failure::Error>;
