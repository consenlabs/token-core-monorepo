use crate::api::{AddressParam, BtcForkWallet};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;
use coin_bch::address::BchAddress;
use coin_btc_fork::address::BtcForkAddress;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = match param.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };

    let address = BchAddress::get_address(network, &param.path)?;
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
    use crate::api::{
        AddressParam, AddressResult, BitcoinWallet, ExternalAddress, ExternalAddressParam,
    };
    use crate::bch_address::get_address;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_btc_fork_address() {
        bind_test();

        let param = AddressParam {
            chain_type: "BITCOINCASH".to_string(),
            path: "m/44'/145'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            is_seg_wit: true,
        };
        let message = get_address(&param);
        assert_eq!("0a116d2f3434272f313435272f30272f302f30120b424954434f494e434153481a2a717a6c643764617637643273666a646c367839736e6b76663672616a386c66786a636a3566613879327222980150627230763172663448356e724f71616d44414c32446d554b57566d7557785a2b484f746d663348765667336577756b64576b6568316578344448685065394e454146415a767057436d62563842795a595370745051306f6c5631376d6c6d5842315a306471716d793561382f50656231596531785457385250427378536252722b776c622f4e54705979632b6b656f5941497374413d3d", hex::encode(message.unwrap()));

        let param = AddressParam {
            chain_type: "BITCOINCASH".to_string(),
            path: "m/44'/145'/0'/0/0".to_string(),
            network: "TESTNET".to_string(),
            is_seg_wit: true,
        };
        let message = get_address(&param);
        assert_eq!("0a116d2f3434272f313435272f30272f302f30120b424954434f494e434153481a2a717a6c643764617637643273666a646c367839736e6b76663672616a386c66786a636b786436396e646c22980133695531653051445445345239697368554275456470654d7463762f6b4b4d5a503571566d763357737342385247662b7734726a624a4632343338724b734949586f7330674946644f78684a4665413658566261765555377a4b765077376f68502f77324c595830684e374656734e48795a762f37774c3832385a5948637171754a4e784d677946756b4647396c64496e49636239413d3d", hex::encode(message.unwrap()));
    }
}
