use failure::Fail;

#[derive(Fail, Debug)]
pub enum CommonError {
    #[fail(display = "invalid_address")]
    InvalidAddress,
    #[fail(display = "invalid_address_checksum")]
    InvalidAddressChecksum,
}
