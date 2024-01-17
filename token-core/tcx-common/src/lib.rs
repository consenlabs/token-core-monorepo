mod hash;
mod rand;

mod errors;
mod hex;
mod time;

mod uint;
mod util;

pub use crate::errors::*;
pub use crate::hash::*;
pub use crate::hex::{FromHex, ToHex};
pub use crate::rand::*;
pub use crate::time::*;
pub use crate::uint::*;
pub use crate::util::*;

use std::result;

extern crate failure;
pub type Result<T> = result::Result<T, failure::Error>;
