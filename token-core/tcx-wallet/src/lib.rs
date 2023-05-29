pub mod identity;
pub mod model;
pub mod wallet_api;
pub mod wallet_manager;
#[macro_use]
extern crate failure;

use std::result;

pub type Result<T> = result::Result<T, failure::Error>;

#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum Error {
    #[fail(display = "Network_params_invalid")]
    NetworkParamsInvalid,
}
