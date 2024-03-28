use crate::common::get_xpub_data;
use crate::Result;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use bitcoin::{Address, PublicKey};
use ikc_common::apdu::{ApduCheck, BtcApdu, CoinCommonApdu};
use ikc_common::error::CommonError;
use ikc_common::path::check_path_validity;
use ikc_transport::message::send_apdu;
use secp256k1::PublicKey as Secp256k1PublicKey;
use std::str::FromStr;

pub struct BtcAddress();

impl BtcAddress {
    /**
    get btc xpub by path
    */
    pub fn get_xpub(network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub data
        let xpub_data = get_xpub_data(path, true)?;
        let xpub_data = &xpub_data[..194].to_string();

        //get public key and chain code
        let pub_key = &xpub_data[..130];
        let chain_code = &xpub_data[130..];

        //build parent public key obj
        let parent_xpub = get_xpub_data(Self::get_parent_path(path)?, true)?;
        let parent_xpub = &parent_xpub[..130].to_string();
        // let mut parent_pub_key_obj = PublicKey::from_str(parent_xpub)?;
        // parent_pub_key_obj.compressed = true;
        let parent_pub_key_obj = Secp256k1PublicKey::from_str(parent_xpub)?; //TODO 是否是压缩公钥

        //build child public key obj
        // let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        // pub_key_obj.compressed = true;
        let pub_key_obj = Secp256k1PublicKey::from_str(pub_key)?; //TODO 是否是压缩公钥

        //get parent public key fingerprint
        let chain_code_obj = ChainCode::from(hex::decode(chain_code).unwrap().as_slice());
        let parent_ext_pub_key = ExtendedPubKey {
            network: network,
            depth: 0 as u8,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: parent_pub_key_obj,
            chain_code: chain_code_obj,
        };
        let fingerprint_obj = parent_ext_pub_key.fingerprint();

        //build extend public key obj
        let chain_code_obj = ChainCode::from(hex::decode(chain_code).unwrap().as_slice());
        let chain_number_vec: Vec<ChildNumber> = DerivationPath::from_str(path)?.into();
        let extend_public_key = ExtendedPubKey {
            network: network,
            depth: chain_number_vec.len() as u8,
            parent_fingerprint: fingerprint_obj,
            child_number: *chain_number_vec.get(chain_number_vec.len() - 1).unwrap(),
            public_key: pub_key_obj,
            chain_code: chain_code_obj,
        };
        //get and return xpub
        Ok(extend_public_key.to_string())
    }

    /**
    get btc address by path
    */
    pub fn get_address(network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub
        let xpub_data = get_xpub_data(path, true)?;
        let pub_key = &xpub_data[..130];

        let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        pub_key_obj.compressed = true;

        Ok(Address::p2pkh(&pub_key_obj, network).to_string())
    }

    /**
    get segwit address by path
    */
    pub fn get_segwit_address(network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub
        let xpub_data = get_xpub_data(path, true)?;
        let pub_key = &xpub_data[..130];

        let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        pub_key_obj.compressed = true;

        Ok(Address::p2shwpkh(&pub_key_obj, network)?.to_string())
    }

    pub fn get_pub_key(path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub
        let xpub_data = get_xpub_data(path, true)?;
        let pub_key = &xpub_data[..130];

        Ok(pub_key.to_string())
    }

    /**
    get parent public key path
    */
    pub fn get_parent_path(path: &str) -> Result<&str> {
        if path.is_empty() {
            return Err(CommonError::ImkeyPathIllegal.into());
        }

        let mut end_flg = path.rfind("/").unwrap();
        if path.ends_with("/") {
            let path = &path[..path.len() - 1];
            end_flg = path.rfind("/").unwrap();
        }
        Ok(&path[..end_flg])
    }

    pub fn display_address(network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;
        let address_str = Self::get_address(network, path)?;
        //        let apdu_res = send_apdu(BtcApdu::btc_coin_reg(address_str.clone().into_bytes()))?;
        let apdu_res = send_apdu(BtcApdu::register_address(
            &address_str.clone().into_bytes().to_vec(),
        ))?;
        ApduCheck::check_response(apdu_res.as_str())?;
        Ok(address_str)
    }

    pub fn display_segwit_address(network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;
        let address_str = Self::get_segwit_address(network, path)?;
        //        let apdu_res = send_apdu(BtcApdu::btc_coin_reg(address_str.clone().into_bytes()))?;
        let apdu_res = send_apdu(BtcApdu::register_address(
            &address_str.clone().into_bytes().to_vec(),
        ))?;
        ApduCheck::check_response(apdu_res.as_str())?;
        Ok(address_str)
    }
}

#[cfg(test)]
mod test {
    use crate::address::BtcAddress;
    use bitcoin::Network;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn get_xpub_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'/0'/0'/0/0";
        let get_xpub_result = BtcAddress::get_xpub(version, path);
        assert!(get_xpub_result.is_ok());
        let xpub = get_xpub_result.ok().unwrap();
        assert_eq!("xpub6FuzpGNBc46EfvmcvECyqXjrzGcKErQgpQcpvhw1tiC5yXvi1jUkzudMpdg5AaguiFstdVR5ASDbSceBswKRy6cAhpTgozmgxMUayPDrLLX", xpub);
    }

    #[test]
    fn get_xpub_path_error_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'";
        let get_xpub_result = BtcAddress::get_xpub(version, path);
        assert!(get_xpub_result.is_err());
    }

    #[test]
    fn get_xpub_path_is_null_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "";
        let get_xpub_result = BtcAddress::get_xpub(version, path);
        assert!(get_xpub_result.is_err());
    }

    #[test]
    fn get_address_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'/0'/0'/0/0";
        let get_btc_address_result = BtcAddress::get_address(version, path);

        assert!(get_btc_address_result.is_ok());
        let btc_address = get_btc_address_result.ok().unwrap();
        assert_eq!("12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g", btc_address);
    }

    #[test]
    fn get_segwit_address_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "m/49'/0'/0'/0/22";
        let segwit_address_result = BtcAddress::get_segwit_address(version, path);

        assert!(segwit_address_result.is_ok());
        let segwit_address = segwit_address_result.ok().unwrap();
        assert_eq!("37E2J9ViM4QFiewo7aw5L3drF2QKB99F9e", segwit_address);
    }

    #[test]
    fn get_parent_path_test() {
        let path = "m/44'/0'/0'/0/0";
        assert_eq!(
            BtcAddress::get_parent_path(path).ok().unwrap(),
            "m/44'/0'/0'/0"
        );

        let path = "m/44'/0'/0'/0/";
        assert_eq!(
            BtcAddress::get_parent_path(path).ok().unwrap(),
            "m/44'/0'/0'"
        );
    }

    #[test]
    fn get_parent_path_path_is_empty_test() {
        let path = "";
        assert!(BtcAddress::get_parent_path(path).is_err());
    }

    #[test]
    fn display_address_test() {
        bind_test();
        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'/0'/0'/0/0";
        let result = BtcAddress::display_address(version, path);

        assert!(result.is_ok());
        let btc_address = result.ok().unwrap();
        assert_eq!("12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g", btc_address);
    }

    #[test]
    fn display_segwit_address_test() {
        bind_test();
        let network: Network = Network::Bitcoin;
        let path: &str = "m/49'/0'/0'/0/22";
        let result = BtcAddress::display_segwit_address(network, path);

        assert!(result.is_ok());
        let segwit_address = result.ok().unwrap();
        assert_eq!("37E2J9ViM4QFiewo7aw5L3drF2QKB99F9e", segwit_address);
    }
}
