mod identity;
mod model;
pub mod wallet_api;
pub mod wallet_manager;
#[macro_use]
extern crate failure;

use std::result;

pub type Result<T> = result::Result<T, failure::Error>;
