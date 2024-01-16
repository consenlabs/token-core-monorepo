use crate::api::{AddressParam, BtcForkWallet};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;
use coin_btc_fork::address::BtcForkAddress;
use coin_btc_fork::btc_fork_network::network_from_param;
use ikc_common::path::get_account_path;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let address: String;

    if param.is_seg_wit {
        let set_wit = "P2WPKH";
        let network = network_from_param(&param.chain_type, &param.network, &set_wit).unwrap();
        address = BtcForkAddress::p2shwpkh(&network, &param.path)?;
    } else {
        let set_wit = "NONE";
        let network = network_from_param(&param.chain_type, &param.network, &set_wit).unwrap();
        address = BtcForkAddress::p2pkh(&network, &param.path)?;
    }

    let network = match param.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };
    let account_path = get_account_path(&param.path)?;
    let enc_xpub = BtcForkAddress::get_enc_xpub(network, &account_path)?;

    let address_message = BtcForkWallet {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address: address,
        enc_x_pub: enc_xpub,
    };

    encode_message(address_message)
}

#[cfg(test)]
mod tests {
    use crate::api::AddressParam;
    use crate::btc_fork_address::get_address;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_btc_fork_address() {
        bind_test();
        let param = AddressParam {
            chain_type: "LITECOIN".to_string(),
            path: "m/44'/2'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            is_seg_wit: false,
        };
        let message = get_address(&param);
        assert_eq!("0a0f6d2f3434272f32272f30272f302f3012084c495445434f494e1a224c64666465677833684a796744754644554137526b7a6a6a783867664668503944502298014d77444d465856574445755776426f67655731762f4d4f4d46446e476e6e666c6d324a4150764a614a5a4f3448587038664373574554413775384d7a4f57334b61506b73676c7055484c4e33786b44723251574d45517130546577465a6f5a334b736a6d4c57304b474d524e3758514b716f2f6f6d6b5345735066616c566e70395a786d326c7078566d49616371766c65726e5653673d3d", hex::encode(message.unwrap()));

        let param = AddressParam {
            chain_type: "LITECOIN".to_string(),
            path: "m/44'/2'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            is_seg_wit: true,
        };
        let message = get_address(&param);
        assert_eq!("0a0f6d2f3434272f32272f30272f302f3012084c495445434f494e1a224d37786f314d693167554c5a5377677675375656457672774d52716e676d466b56642298014d77444d465856574445755776426f67655731762f4d4f4d46446e476e6e666c6d324a4150764a614a5a4f3448587038664373574554413775384d7a4f57334b61506b73676c7055484c4e33786b44723251574d45517130546577465a6f5a334b736a6d4c57304b474d524e3758514b716f2f6f6d6b5345735066616c566e70395a786d326c7078566d49616371766c65726e5653673d3d", hex::encode(message.unwrap()));
    }
}
