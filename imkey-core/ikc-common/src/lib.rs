pub mod aes;
pub mod apdu;
pub mod applet;
pub mod coin_info;
pub mod common;
pub mod constants;
pub mod curve;
pub mod error;
pub mod hex;
pub mod https;
pub mod path;
pub mod utility;

use parking_lot::RwLock;

pub use crate::common::SignParam;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref XPUB_COMMON_KEY_128: RwLock<String> =
        RwLock::new("B888D25EC8C12BD5043777B1AC49F872".to_string());
    pub static ref XPUB_COMMON_IV: RwLock<String> =
        RwLock::new("9C0C30889CBCC5E01AB5B2BB88715799".to_string());
    pub static ref OPERATING_SYSTEM: RwLock<String> = RwLock::new("".to_string());
}

#[macro_use]
extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
