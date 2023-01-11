use crate::api::{AddressParam, AddressResult, PubKeyParam, PubKeyResult};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_tezos::address::TezosAddress;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address = TezosAddress::get_address(param.path.as_ref())?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

pub fn display_tezos_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address = TezosAddress::display_address(param.path.as_ref())?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

pub fn get_pub_key(param: &PubKeyParam) -> Result<Vec<u8>> {
    let pub_key = TezosAddress::get_base58_pub_key(param.path.as_ref())?;

    let apub_key_message = PubKeyResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        pub_key,
        derived_mode: "".to_string(),
    };
    encode_message(apub_key_message)
}
