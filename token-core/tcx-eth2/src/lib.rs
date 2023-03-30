extern crate core;

pub mod address;
mod bls_to_execution_change;
pub mod signer;
pub mod transaction;
use failure::Fail;
use tcx_chain::Result;

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_hex_value")]
    InvalidHexValue,
}

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    let result = if value.starts_with("0x") || value.starts_with("0X") {
        hex::decode(&value[2..])
    } else {
        hex::decode(&value[..])
    };
    result.map_err(|_| Error::InvalidHexValue.into())
}
