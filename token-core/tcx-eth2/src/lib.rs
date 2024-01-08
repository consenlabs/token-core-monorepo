extern crate core;

mod bls_to_execution_change;
pub mod signer;
pub mod transaction;
use failure::Fail;

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_eth_address")]
    InvalidEthAddress,
}
