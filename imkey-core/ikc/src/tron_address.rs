use crate::api::{AddressParam, AddressResult};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_tron::address::TronAddress;
use prost::Message;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address = TronAddress::get_address(param.path.as_ref())?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

pub fn display_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address = TronAddress::display_address(param.path.as_ref())?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}
