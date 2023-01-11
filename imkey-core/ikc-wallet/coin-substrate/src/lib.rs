pub mod address;
pub mod substrateapi;
pub mod transaction;
use core::result;
pub type Result<T> = result::Result<T, failure::Error>;
#[macro_use]
extern crate failure;

pub(crate) const SIGNATURE_TYPE_ED25519: u8 = 0x00;
pub(crate) const SIGNATURE_TYPE_SR25519: u8 = 0x01;
pub(crate) const PAYLOAD_HASH_THRESHOLD: usize = 256;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
