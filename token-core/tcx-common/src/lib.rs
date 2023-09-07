mod hash;
mod rand;

mod time;

pub use crate::hash::*;
pub use crate::rand::*;
pub use crate::time::*;

pub mod util;
use std::result;

extern crate failure;
pub type Result<T> = result::Result<T, failure::Error>;
