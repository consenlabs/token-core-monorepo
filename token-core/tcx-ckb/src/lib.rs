mod address;
mod hash;
mod serializer;
mod signer;
mod transaction;
mod transaction_helper;

use failure::Fail;

pub use address::CkbAddress;
pub use serializer::Serializer;
pub use transaction::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_output_point")]
    InvalidOutputPoint,

    #[fail(display = "invalid_outputs_data_length")]
    InvalidOutputsDataLength,

    #[fail(display = "required_witness")]
    RequiredWitness,

    #[fail(display = "invalid_input_cells")]
    InvalidInputCells,

    #[fail(display = "required_output_data")]
    RequiredOutputsData,

    #[fail(display = "witness_group_empty")]
    WitnessGroupEmpty,

    #[fail(display = "witness_empty")]
    WitnessEmpty,

    #[fail(display = "invalid_tx_hash")]
    InvalidTxHash,

    #[fail(display = "invalid_hash_type")]
    InvalidHashType,

    #[fail(display = "cell_input_not_cached")]
    CellInputNotCached,

    #[fail(display = "invalid_hex_value")]
    InvalidHexValue,
}
pub mod nervos {
    pub const CHAINS: [&str; 1] = ["NERVOS"];

    pub type Address = crate::address::CkbAddress;
    pub type TransactionInput = crate::transaction::CkbTxInput;
    pub type TransactionOutput = crate::transaction::CkbTxOutput;
}
