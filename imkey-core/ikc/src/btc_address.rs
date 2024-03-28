use crate::api::{
    AddressParam, AddressResult, BitcoinWallet, ExternalAddress, ExternalAddressParam,
};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::network::constants::Network;
use coin_bitcoin::address::BtcAddress;
use ikc_common::utility::network_convert;
use prost::Message;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = network_convert(param.network.as_ref());
    let account_path = param.path.to_string();
    let main_address: String;
    let receive_address: String;

    if param.is_seg_wit {
        main_address =
            BtcAddress::get_segwit_address(network, format!("{}/0/0", account_path).as_str())?;
        receive_address =
            BtcAddress::get_segwit_address(network, format!("{}/0/1", account_path).as_str())?;
    } else {
        main_address = BtcAddress::get_address(network, format!("{}/0/0", account_path).as_str())?;
        receive_address =
            BtcAddress::get_address(network, format!("{}/0/1", account_path).as_str())?;
    }

    let enc_xpub = get_enc_xpub(network, param.path.as_ref())?;

    let external_address = ExternalAddress {
        address: receive_address,
        derived_path: "0/1".to_string(),
        r#type: "EXTERNAL".to_string(),
    };

    let address_message = BitcoinWallet {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address: main_address,
        enc_x_pub: enc_xpub,
        external_address: Some(external_address),
    };
    encode_message(address_message)
}

pub fn calc_external_address(param: &ExternalAddressParam) -> Result<Vec<u8>> {
    let network = network_convert(param.network.as_ref());
    let account_path = param.path.to_string();
    let external_path = format!("{}/0/{}", account_path, param.external_idx);
    let receive_address: String;

    if param.seg_wit.to_uppercase() == "P2WPKH" {
        receive_address = BtcAddress::get_segwit_address(network, external_path.as_str())?;
    } else {
        receive_address = BtcAddress::get_address(network, external_path.as_str())?;
    }

    let external_address = ExternalAddress {
        address: receive_address,
        derived_path: format!("0/{}", param.external_idx),
        r#type: "EXTERNAL".to_string(),
    };

    encode_message(external_address)
}

pub fn get_enc_xpub(network: Network, path: &str) -> Result<String> {
    let xpub = BtcAddress::get_xpub(network, path)?;
    let key = ikc_common::XPUB_COMMON_KEY_128.read();
    let iv = ikc_common::XPUB_COMMON_IV.read();
    let key_bytes = hex::decode(&*key)?;
    let iv_bytes = hex::decode(&*iv)?;
    let encrypted = ikc_common::aes::cbc::encrypt_pkcs7(&xpub.as_bytes(), &key_bytes, &iv_bytes)?;
    Ok(base64::encode(&encrypted))
}

pub fn register_btc_address(param: &AddressParam) -> Result<Vec<u8>> {
    if param.is_seg_wit {
        display_segwit_address(param)
    } else {
        display_btc_legacy_address(param)
    }
}

pub fn display_btc_legacy_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = network_convert(param.network.as_ref());
    let address = BtcAddress::display_address(network, &param.path)?;

    let address_message = AddressResult {
        address,
        path: param.path.to_string(),
        chain_type: param.chain_type.to_string(),
    };
    encode_message(address_message)
}

pub fn display_segwit_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = network_convert(param.network.as_ref());
    let address = BtcAddress::display_segwit_address(network, &param.path)?;

    let address_message = AddressResult {
        path: param.path.to_string(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

pub fn derive_account(param: &AddressParam) -> Result<Vec<u8>> {
    let network = network_convert(param.network.as_ref());
    let path = format!("{}/0/0", param.path);
    let address = BtcAddress::display_segwit_address(network, &path)?;

    let address_message = AddressResult {
        path: param.path.to_string(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}
