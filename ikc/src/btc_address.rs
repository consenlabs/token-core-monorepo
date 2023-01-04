use crate::api::{
    AddressParam, AddressResult, BitcoinWallet, ExternalAddress, ExternalAddressParam,
};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::network::constants::Network;
use coin_bitcoin::address::BtcAddress;
use coin_bitcoin::btcapi::{BtcXpubReq, BtcXpubRes};
use ikc_common::constants::{BTC_LEGACY_PATH_PRE, BTC_NATIVE_SEGWIT_PATH_PRE, BTC_SEGWIT_PATH_PRE};
use prost::Message;

pub fn get_btc_xpub(data: &[u8]) -> Result<Vec<u8>> {
    let input: BtcXpubReq = BtcXpubReq::decode(data).expect("imkey_illegal_param");

    let network = match input.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };

    let xpub = BtcAddress::get_xpub(network, input.path.as_ref())?;

    let address_message = BtcXpubRes { xpub };
    encode_message(address_message)
}

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = match param.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };

    let account_path = param.path.to_string();
    let mut main_address: String = "".to_string();
    let mut receive_address: String = "".to_string();
    let mut enc_xpub: String = "".to_string();

    let path_array: Vec<&str> = account_path.split(";").collect();

    for (index, path) in path_array.iter().enumerate() {
        let mut address_0_0 = "".to_string();
        let mut address_0_1 = "".to_string();
        if path.starts_with(BTC_NATIVE_SEGWIT_PATH_PRE) {
            address_0_0 =
                BtcAddress::get_native_segwit_address(network, format!("{}/0/0", path).as_str())?;
            address_0_1 =
                BtcAddress::get_native_segwit_address(network, format!("{}/0/1", path).as_str())?;
        } else if path.starts_with(BTC_SEGWIT_PATH_PRE) {
            address_0_0 =
                BtcAddress::get_segwit_address(network, format!("{}/0/0", path).as_str())?;
            address_0_1 =
                BtcAddress::get_segwit_address(network, format!("{}/0/1", path).as_str())?;
        } else {
            address_0_0 = BtcAddress::get_address(network, format!("{}/0/0", path).as_str())?;
            address_0_1 = BtcAddress::get_address(network, format!("{}/0/1", path).as_str())?;
        }
        let xpub = get_enc_xpub(network, path.as_ref())?;
        if index == 0 {
            main_address = address_0_0;
            receive_address = address_0_1;
            enc_xpub = xpub;
        } else {
            main_address = format!("{};{}", main_address, address_0_0);
            receive_address = format!("{};{}", receive_address, address_0_1);
            enc_xpub = format!("{};{}", enc_xpub, xpub);
        }
    }

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
    let network = match param.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };

    let account_path = param.path.to_string();
    let mut receive_address: String = "".to_string();
    let path_array: Vec<&str> = account_path.split(";").collect();

    for (index, path) in path_array.iter().enumerate() {
        let external_path = format!("{}/0/{}", path, param.external_idx);
        let mut address = "".to_string();
        if path.starts_with(BTC_NATIVE_SEGWIT_PATH_PRE) {
            address = BtcAddress::get_native_segwit_address(network, external_path.as_str())?;
        } else if path.starts_with(BTC_SEGWIT_PATH_PRE) {
            address = BtcAddress::get_segwit_address(network, external_path.as_str())?;
        } else {
            address = BtcAddress::get_address(network, external_path.as_str())?;
        }
        if index == 0 {
            receive_address = address;
        } else {
            receive_address = format!("{};{}", receive_address, address);
        }
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
    match param.seg_wit.to_uppercase().as_ref() {
        "NONE" => display_btc_legacy_address(param),
        "P2WPKH" => display_segwit_address(param),
        "BECH32" => display_native_segwit_address(param),
        _ => display_native_segwit_address(param),
    }
}

pub fn display_btc_legacy_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = match param.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };

    let path = format!("{}/0/0", param.path);
    let address = BtcAddress::display_address(network, &path)?;

    let address_message = AddressResult {
        address,
        path: param.path.to_string(),
        chain_type: param.chain_type.to_string(),
    };
    encode_message(address_message)
}

pub fn display_segwit_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = match param.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };

    let path = format!("{}/0/0", param.path);
    let address = BtcAddress::display_segwit_address(network, &path)?;

    let address_message = AddressResult {
        path: param.path.to_string(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

pub fn display_native_segwit_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = match param.network.as_ref() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    };

    let path = format!("{}/0/0", param.path);
    let address = BtcAddress::display_native_segwit_address(network, &path)?;

    let address_message = AddressResult {
        path: param.path.to_string(),
        chain_type: param.chain_type.to_string(),
        address,
    };
    encode_message(address_message)
}

#[cfg(test)]
mod tests {
    use crate::api::{AddressParam, AddressResult, ExternalAddressParam};
    use crate::btc_address::{calc_external_address, get_address};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_btc_address() {
        bind_test();

        let param = AddressParam {
            chain_type: "BITCOIN".to_string(),
            path: "m/84'/0'/0';m/49'/0'/0';m/44'/0'/0'".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };
        let message = get_address(&param);
        assert_eq!("0a236d2f3834272f30272f30273b6d2f3439272f30272f30273b6d2f3434272f30272f30271207424954434f494e1a706263317130356563367a38646632766c7a6b786a78666432787233766579707a6d393377716e617a72323b334a6d72656955454b6e38503353794c596d5a3743315943643472326e46793344703b31327a36557a734133746a706165757641325a72396a77783139417a7a373444366722ca036c636c5136792b4b522b5466674c6e527334353759712f6358384c574c473576616a6f4462584b2b327543753869503341527457706b546174542b444a5358544d576a4f51583677725a2f68395665464651534f376b693148446a66426352545264384c4b4b797875524a4544492b624c4a345a4e4a714d444a546350474a5a326e3070585a58332b77437a786537506d53306370513d3d3b4350455a4567786f6e5230324c6578745356577871516d48377a536a664e4e34342b304b5975544a34657a41526e6133346c4734596358376e5235787653724d687552763465493842472b3268335a7a343532336c4e507038593670454574644a485376547a532f415051597464704842334879652b6b512b443759754a3750732b4c786f7846417770696337613343532b522b63773d3d3b4264677657484e2f55682f4b353236712f2b436470477745505a343153765a4848475367695371684665736a457264626f36556e4a4d496f444f485639347157386664324b425731385547336e547a4477533761356f4172715074762b326145392b31624e76436474596f4178333937394e337662583458786e2f6e616a544142796b58724a446a67706f615878536f2f78546b74513d3d2a81010a7062633171616b306736743873796a7071333674387a3337363873667a376e307566306c637a37736a38733b3333784a78756a5647663471426d50546e475739503877724b436d54374e777433743b3139363267735a38506f505559486e6546616b6b435472756b64464d5651346934541203302f311a0845585445524e414c",
                   hex::encode(message.unwrap()));
    }

    #[test]
    fn test_calc_external_address() {
        bind_test();

        let param = ExternalAddressParam {
            chain_type: "BITCOIN".to_string(),
            path: "m/84'/0'/0';m/49'/0'/0';m/44'/0'/0'".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            external_idx: 1 as i32,
        };
        let message = calc_external_address(&param);
        assert_eq!("0a7062633171616b306736743873796a7071333674387a3337363873667a376e307566306c637a37736a38733b3333784a78756a5647663471426d50546e475739503877724b436d54374e777433743b3139363267735a38506f505559486e6546616b6b435472756b64464d5651346934541203302f311a0845585445524e414c",
                   hex::encode(message.unwrap()));
    }
}
