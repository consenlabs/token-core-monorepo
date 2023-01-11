use crate::api::{AddressParam, AddressResult};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_substrate::address::{AddressType, SubstrateAddress};
use prost::Message;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address_type = match param.chain_type.as_str() {
        "POLKADOT" => AddressType::Polkadot,
        "KUSAMA" => AddressType::Kusama,
        _ => panic!("address type not support"),
    };
    let address = SubstrateAddress::get_address(param.path.as_ref(), &address_type)?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

pub fn display_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address_type = match param.chain_type.as_str() {
        "POLKADOT" => AddressType::Polkadot,
        "KUSAMA" => AddressType::Kusama,
        _ => panic!("address type not support"),
    };
    let address = SubstrateAddress::display_address(param.path.as_ref(), &address_type)?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}
