#![feature(let_chains)]

pub mod address;

pub mod bip143_with_forkid;
pub mod network;
pub mod signer;
pub mod transaction;

use core::result;
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate failure;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;

#[macro_use]
extern crate tcx_chain;
extern crate core;

pub type Result<T> = result::Result<T, failure::Error>;

pub use address::{BtcKinAddress, ScriptPubkey, WIFDisplay};
pub use network::BtcKinNetwork;
pub use transaction::{BtcKinTxInput, BtcKinTxOutput, OmniTxInput, Utxo};

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "decrypt_xpub_error")]
    DecryptXPubError,
    #[fail(display = "unsupported_chain")]
    UnsupportedChain,
    #[fail(display = "missing_network")]
    MissingNetwork,
    #[fail(display = "invalid_utxo")]
    InvalidUtxo,
    #[fail(display = "invalid_address")]
    InvalidAddress,
}

pub mod bitcoin {
    pub const CHAINS: [&'static str; 2] = ["BITCOIN", "LITECOIN"];

    pub type Address = crate::BtcKinAddress;
    pub type TransactionInput = crate::transaction::BtcKinTxInput;
    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}

pub mod omni {
    pub static CHAINS: [&'static str; 1] = ["OMNI"];

    pub type Address = crate::BtcKinAddress;

    pub type TransactionInput = crate::transaction::OmniTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}
