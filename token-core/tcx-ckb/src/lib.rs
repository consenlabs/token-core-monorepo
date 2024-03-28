mod address;
mod hash;
mod serializer;
mod signer;
mod transaction;
mod transaction_helper;

pub use address::CkbAddress;
pub use serializer::Serializer;
use thiserror::Error;
pub use transaction::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid_output_point")]
    InvalidOutputPoint,

    #[error("invalid_outputs_data_length")]
    InvalidOutputsDataLength,

    #[error("required_witness")]
    RequiredWitness,

    #[error("invalid_input_cells")]
    InvalidInputCells,

    #[error("required_output_data")]
    RequiredOutputsData,

    #[error("witness_group_empty")]
    WitnessGroupEmpty,

    #[error("witness_empty")]
    WitnessEmpty,

    #[error("invalid_tx_hash")]
    InvalidTxHash,

    #[error("invalid_hash_type")]
    InvalidHashType,

    #[error("cell_input_not_cached")]
    CellInputNotCached,

    #[error("invalid_hex_value")]
    InvalidHexValue,
}
pub mod nervos {
    pub const CHAINS: [&str; 1] = ["NERVOS"];

    pub type Address = crate::address::CkbAddress;
    pub type TransactionInput = crate::transaction::CkbTxInput;
    pub type TransactionOutput = crate::transaction::CkbTxOutput;
}
