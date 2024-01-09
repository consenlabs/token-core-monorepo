use crate::api::{AddressParam, AddressResult, BtcForkWallet};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;
use coin_ckb::address::CkbAddress;
use ikc_common::path::get_account_path;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = match param.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };

    let address = CkbAddress::get_address(param.network.as_ref(), param.path.as_ref())?;
    let account_path = get_account_path(&param.path)?;
    let enc_xpub = CkbAddress::get_enc_xpub(network, &account_path)?;

    let address_message = BtcForkWallet {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address: address,
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

#[cfg(test)]
mod tests {
    use crate::api::AddressParam;
    use crate::nervos_address::get_address;
    use ikc_common::{XPUB_COMMON_IV, XPUB_COMMON_KEY_128};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_btc_fork_address() {
        bind_test();
        *XPUB_COMMON_KEY_128.write() = "4A2B655485ABBAB54BD30298BB0A5B55".to_string();
        *XPUB_COMMON_IV.write() = "73518399CB98DCD114D873E06EBF4BCC".to_string();

        let param = AddressParam {
            chain_type: "NERVOS".to_string(),
            path: "m/44'/309'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            is_seg_wit: false,
        };
        let message = get_address(&param);
    }
}
