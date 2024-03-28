pub mod address;
pub mod substrateapi;
pub mod transaction;
use core::result;
extern crate anyhow;
pub type Result<T> = result::Result<T, anyhow::Error>;

pub(crate) const SIGNATURE_TYPE_ED25519: u8 = 0x00;
// pub(crate) const SIGNATURE_TYPE_SR25519: u8 = 0x01;
pub(crate) const PAYLOAD_HASH_THRESHOLD: usize = 256;
