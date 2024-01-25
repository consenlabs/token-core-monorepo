use crate::Result;
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use bitcoin::Network;
use hex;
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, EthApdu};
use ikc_common::path::{check_path_validity, get_parent_path};
use ikc_common::utility::hex_to_bytes;
use ikc_transport::message::send_apdu;
use keccak_hash::keccak;
use regex::Regex;
use secp256k1::PublicKey;
use std::str::FromStr;

#[derive(Debug)]
pub struct EthAddress {}

impl EthAddress {
    pub fn from_pub_key(pub_key: Vec<u8>) -> Result<String> {
        let pub_key_hash = keccak(pub_key[1..].as_ref());
        let addr_bytes = &pub_key_hash[12..];
        let address = EthAddress::address_checksum(&hex::encode(addr_bytes));
        Ok(address)
    }

    pub fn address_checksum(address: &str) -> String {
        let re = Regex::new(r"^0x").expect("address_checksummed");
        let address = address.to_lowercase();
        let address = re.replace_all(&address, "").to_string();

        let mut checksum_address = "0x".to_string();

        let address_hash = keccak(&address);
        let address_hash_hex = hex::encode(address_hash);

        for i in 0..address.len() {
            let n = i64::from_str_radix(&address_hash_hex.chars().nth(i).unwrap().to_string(), 16)
                .unwrap();
            let ch = address.chars().nth(i).unwrap();
            // make char uppercase if ith character is 9..f
            if n > 7 {
                checksum_address = format!("{}{}", checksum_address, ch.to_uppercase().to_string());
            } else {
                checksum_address = format!("{}{}", checksum_address, ch.to_string());
            }
        }

        return checksum_address;
    }

    pub fn get_address(path: &str) -> Result<String> {
        check_path_validity(path)?;

        let select_apdu = EthApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public
        let msg_pubkey = EthApdu::get_xpub(&path, false);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let pubkey_raw = hex_to_bytes(&res_msg_pubkey[..130]).unwrap();

        let address_checksum = EthAddress::from_pub_key(pubkey_raw.clone())?;
        Ok(address_checksum)
    }

    pub fn display_address(path: &str) -> Result<String> {
        let address = EthAddress::get_address(path).unwrap();
        let reg_apdu = EthApdu::register_address(address.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
    }

    pub fn get_pub_key(path: &str) -> Result<String> {
        check_path_validity(path)?;

        let select_apdu = EthApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public
        let msg_pubkey = EthApdu::get_xpub(&path, false);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        Ok(res_msg_pubkey[..194].to_string())
    }

    pub fn get_xpub(path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub data
        let xpub_data = Self::get_pub_key(path)?;
        let xpub_data = &xpub_data[..194];

        //get public key and chain code
        let pub_key = &xpub_data[..130];
        let sub_chain_code = &xpub_data[130..];
        let pub_key_obj = PublicKey::from_str(pub_key)?;

        //build parent public key obj
        let parent_xpub_data = Self::get_pub_key(get_parent_path(path)?)?;
        let parent_xpub_data = &parent_xpub_data[..194];
        let parent_pub_key = &parent_xpub_data[..130];
        let parent_chain_code = &parent_xpub_data[130..];
        let parent_pub_key_obj = PublicKey::from_str(parent_pub_key)?;

        //get parent public key fingerprint
        let parent_chain_code = ChainCode::from(hex::decode(parent_chain_code)?.as_slice());
        let parent_ext_pub_key = ExtendedPubKey {
            network: Network::Bitcoin,
            depth: 0 as u8,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: parent_pub_key_obj,
            chain_code: parent_chain_code,
        };
        let fingerprint_obj = parent_ext_pub_key.fingerprint();

        //build extend public key obj
        let sub_chain_code_obj = ChainCode::from(hex::decode(sub_chain_code)?.as_slice());

        let chain_number_vec: Vec<ChildNumber> = DerivationPath::from_str(path)?.into();
        let extend_public_key = ExtendedPubKey {
            network: Network::Bitcoin,
            depth: chain_number_vec.len() as u8,
            parent_fingerprint: fingerprint_obj,
            child_number: *chain_number_vec.get(chain_number_vec.len() - 1).unwrap(),
            public_key: pub_key_obj,
            chain_code: sub_chain_code_obj,
        };
        //get and return xpub
        Ok(extend_public_key.to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::address::EthAddress;
    use ikc_common::constants;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_pubkey_to_address() {
        let pubkey_string = "04efb99d9860f4dec4cb548a5722c27e9ef58e37fbab9719c5b33d55c216db49311221a01f638ce5f255875b194e0acaa58b19a89d2e56a864427298f826a7f887";

        let address_derived =
            EthAddress::from_pub_key(hex::decode(pubkey_string).unwrap()).unwrap();
        assert_eq!(
            address_derived,
            "0xC2D7CF95645D33006175B78989035C7c9061d3F9".to_string()
        );
    }

    #[test]
    fn test_checksummed_address() {
        let address_orignial = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359";
        let address_checksum = EthAddress::address_checksum(address_orignial);
        println!("checksummed address is {}", address_checksum);
        assert_eq!(
            address_checksum,
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359".to_string()
        );
    }

    #[test]
    fn test_get_address() {
        bind_test();
        let address = EthAddress::get_address(constants::ETH_PATH).unwrap();
        println!("address:{}", &address);
        assert_eq!(&address, "0x6031564e7b2F5cc33737807b2E58DaFF870B590b");
    }

    #[test]
    fn test_display_address() {
        bind_test();
        let address = EthAddress::display_address(constants::ETH_PATH).unwrap();
        println!("address:{}", &address);
        assert_eq!(&address, "0x6031564e7b2F5cc33737807b2E58DaFF870B590b");
    }
}
