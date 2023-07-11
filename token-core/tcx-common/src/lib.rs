pub mod util;
use std::result;

#[macro_use]
extern crate failure;
pub type Result<T> = result::Result<T, failure::Error>;
