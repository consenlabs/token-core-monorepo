pub mod address;
pub mod hash;
pub mod nervosapi;
pub mod serializer;
pub mod signer;
pub mod transaction_helper;
extern crate failure;
use core::result;
pub type Result<T> = result::Result<T, failure::Error>;
use failure::Fail;
pub use nervosapi::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};
pub use serializer::Serializer;

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

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    let result = if value.starts_with("0x") || value.starts_with("0X") {
        hex::decode(&value[2..])
    } else {
        hex::decode(&value[..])
    };

    result.map_err(|_| Error::InvalidHexValue.into())
}

#[cfg(test)]
mod tests {
    use crate::hex_to_bytes;

    #[test]
    pub fn hex_convert() {
        let v: Vec<u8> = vec![];
        assert_eq!(v, hex_to_bytes("0x").unwrap());
        assert_eq!(vec![0x01], hex_to_bytes("0x01").unwrap());
        assert_eq!(vec![0x02], hex_to_bytes("0x02").unwrap());
        assert_eq!(vec![0x02, 0x11], hex_to_bytes("0x0211").unwrap());
    }
}
