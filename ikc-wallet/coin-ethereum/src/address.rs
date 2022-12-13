use crate::Result;
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, EthApdu};
use ikc_common::path::check_path_validity;
use ikc_common::utility::hex_to_bytes;
use hex;
use keccak_hash::keccak;
use regex::Regex;
use ikc_transport::message::send_apdu;

#[derive(Debug)]
pub struct EthAddress {}

impl EthAddress {
    pub fn address_from_pubkey(pubkey: Vec<u8>) -> Result<String> {
        let pubkey_hash = keccak(pubkey[1..].as_ref());
        let addr_bytes = &pubkey_hash[12..];
        Ok(hex::encode(addr_bytes))
    }

    pub fn address_checksummed(address: &str) -> String {
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

        let address_main = EthAddress::address_from_pubkey(pubkey_raw.clone())?;
        let address_checksum = EthAddress::address_checksummed(&address_main);
        Ok(address_checksum)
    }

    pub fn display_address(path: &str) -> Result<String> {
        let address = EthAddress::get_address(path).unwrap();
        let reg_apdu = EthApdu::register_address(address.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
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
            EthAddress::address_from_pubkey(hex::decode(pubkey_string).unwrap()).unwrap();
        println!("address is {}", address_derived);
        assert_eq!(
            address_derived,
            "c2d7cf95645d33006175b78989035c7c9061d3f9".to_string()
        );
    }

    #[test]
    fn test_checksummed_address() {
        let address_orignial = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359";
        let address_checksummed = EthAddress::address_checksummed(address_orignial);
        println!("checksummed address is {}", address_checksummed);
        assert_eq!(
            address_checksummed,
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
