use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_ethereum::address::EthAddress;

use crate::api::{AddressParam, AddressResult};
use prost::Message;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address = EthAddress::get_address(&param.path)?;
    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

pub fn register_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address = EthAddress::display_address(&param.path)?;
    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}
