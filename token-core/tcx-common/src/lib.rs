mod hash;
mod rand;

pub use hash::*;
pub use rand::*;

pub mod util;
use std::result;

extern crate failure;
pub type Result<T> = result::Result<T, failure::Error>;
