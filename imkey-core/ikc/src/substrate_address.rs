use crate::api::{AddressParam, AddressResult};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use anyhow::anyhow;
use coin_substrate::address::{AddressType, SubstrateAddress};

fn address_type(chain_type: &str) -> Result<AddressType> {
    match chain_type {
        "POLKADOT" => Ok(AddressType::Polkadot),
        "KUSAMA" => Ok(AddressType::Kusama),
        _ => Err(anyhow!("unsupported_chain")),
    }
}

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address_type = address_type(param.chain_type.as_str())?;
    let address = SubstrateAddress::get_address(param.path.as_ref(), &address_type)?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

pub fn display_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address_type = address_type(param.chain_type.as_str())?;
    let address = SubstrateAddress::display_address(param.path.as_ref(), &address_type)?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}
