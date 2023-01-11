use crate::api::{AddressParam, BtcForkWallet};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;
use coin_btc_fork::address::BtcForkAddress;
use coin_btc_fork::btc_fork_network::network_from_param;

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
    let account_path = ikc_common::utility::get_account_path(&param.path)?;
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
        assert_eq!("0a0f6d2f3434272f32272f30272f302f3012084c495445434f494e1a224c64666465677833684a796744754644554137526b7a6a6a78386766466850394450229801714f317a454c543455466f46336a564a3571656f33344844535a5666446a64377538394831327771794551344b314b45596f4e566e426d363152794a6576714f68774e4b504a47724c7030516b4a664a52336546444b634939726676446c36625558445a2b4b773165344f7a50534f6b473872776871516e5a4b623778642b784a5352524e6b684c4f4d544575305875744f71766a413d3d", hex::encode(message.unwrap()));

        let param = AddressParam {
            chain_type: "LITECOIN".to_string(),
            path: "m/44'/2'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            is_seg_wit: true,
        };
        let message = get_address(&param);
        assert_eq!("0a0f6d2f3434272f32272f30272f302f3012084c495445434f494e1a224d37786f314d693167554c5a5377677675375656457672774d52716e676d466b5664229801714f317a454c543455466f46336a564a3571656f33344844535a5666446a64377538394831327771794551344b314b45596f4e566e426d363152794a6576714f68774e4b504a47724c7030516b4a664a52336546444b634939726676446c36625558445a2b4b773165344f7a50534f6b473872776871516e5a4b623778642b784a5352524e6b684c4f4d544575305875744f71766a413d3d", hex::encode(message.unwrap()));
    }
}
