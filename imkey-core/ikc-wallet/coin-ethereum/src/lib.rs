pub mod address;
pub mod ethapi;
pub mod transaction;
pub mod types;
extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
#[macro_use]
extern crate log;
extern crate android_logger;
