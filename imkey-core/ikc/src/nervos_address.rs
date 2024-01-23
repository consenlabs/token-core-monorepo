use crate::api::{AddressParam, AddressResult, BtcForkWallet};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;
use coin_ckb::address::CkbAddress;
use ikc_common::path::get_account_path;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address = CkbAddress::get_address(param.network.as_ref(), param.path.as_ref())?;
    let account_path = get_account_path(&param.path)?;
    let enc_xpub = CkbAddress::get_enc_xpub(&param.network, &account_path)?;

    let address_message = BtcForkWallet {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
        enc_x_pub: enc_xpub,
    };
    encode_message(address_message)
}

pub fn display_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address = CkbAddress::display_address(param.network.as_ref(), param.path.as_ref())?;

    let address_message = AddressResult {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}
