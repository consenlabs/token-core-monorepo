use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommonError {
    #[error("invalid_address")]
    InvalidAddress,
    #[error("invalid_address_checksum")]
    InvalidAddressChecksum,
}
