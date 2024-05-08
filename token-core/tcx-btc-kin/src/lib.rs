#![feature(let_chains)]

pub mod address;
pub mod bch_address;
mod bch_sighash;
mod sighash;

pub mod network;
pub mod signer;
pub mod transaction;

use core::result;
use thiserror::Error;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;

#[macro_use]
extern crate tcx_keystore;
extern crate core;

pub type Result<T> = result::Result<T, anyhow::Error>;

pub use address::{BtcKinAddress, WIFDisplay};
pub use bch_address::BchAddress;
pub use network::BtcKinNetwork;
pub use transaction::{BtcKinTxInput, BtcKinTxOutput, OmniTxInput, Utxo};

pub const BITCOIN: &str = "BITCOIN";
pub const BITCOINCASH: &str = "BITCOINCASH";

pub const LITECOIN: &str = "LITECOIN";

pub const OMNI: &str = "OMNI";

#[derive(Error, Debug)]
pub enum Error {
    #[error("decrypt_xpub_error")]
    DecryptXPubError,
    #[error("unsupported_chain")]
    UnsupportedChain,
    #[error("missing_network")]
    MissingNetwork,
    #[error("invalid_utxo")]
    InvalidUtxo,
    #[error("invalid_address")]
    InvalidAddress,
    #[error("bch_convert_to_legacy_address_failed# address: {0}")]
    ConvertToLegacyAddressFailed(String),
    #[error("bch_convert_to_cash_address_failed# address: {0}")]
    ConvertToCashAddressFailed(String),
    #[error("construct_bch_address_failed# address: {0}")]
    ConstructBchAddressFailed(String),
    #[error("unsupported_taproot")]
    UnsupportedTaproot,
}

pub mod bitcoin {
    use crate::{BITCOIN, LITECOIN};
    pub const CHAINS: [&str; 2] = [BITCOIN, LITECOIN];
    pub type Address = crate::BtcKinAddress;
    pub type TransactionInput = crate::transaction::BtcKinTxInput;
    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}

pub mod bitcoincash {
    use crate::BITCOINCASH;

    pub static CHAINS: [&str; 1] = [BITCOINCASH];

    pub type Address = crate::BchAddress;

    pub type TransactionInput = crate::transaction::BtcKinTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}

pub mod omni {
    use crate::OMNI;

    pub static CHAINS: [&str; 1] = [OMNI];

    pub type Address = crate::BtcKinAddress;

    pub type TransactionInput = crate::transaction::OmniTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}
