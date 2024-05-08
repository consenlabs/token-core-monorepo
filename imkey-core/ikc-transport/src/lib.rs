pub mod error;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod hid_api;
pub mod message;
extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
#[macro_use]
extern crate lazy_static;
