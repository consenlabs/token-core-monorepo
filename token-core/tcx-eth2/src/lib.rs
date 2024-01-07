extern crate core;

mod bls_to_execution_change;
pub mod signer;
pub mod transaction;
use crate::transaction::sign_bls_to_execution_change_param::Key;
use failure::Fail;

impl From<Key> for tcx_crypto::Key {
    fn from(key: Key) -> Self {
        match key {
            Key::Password(password) => Self::Password(password),
            Key::DerivedKey(derived_key) => Self::DerivedKey(derived_key),
        }
    }
}

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_eth_address")]
    InvalidEthAddress,
}
