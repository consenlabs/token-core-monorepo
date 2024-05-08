use core::result;

pub mod address;
mod common;
pub mod transaction;
pub type Result<T> = result::Result<T, anyhow::Error>;
extern crate anyhow;
