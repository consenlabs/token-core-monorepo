use crate::utils::{digest, HashSize};
use crate::Result;

use base32::Alphabet;
use hex;
use ikc_common::apdu::{Apdu, ApduCheck, Secp256k1Apdu};
use ikc_common::constants::FILECOIN_AID;
use ikc_common::error::CoinError;
use ikc_common::path;
use ikc_common::utility;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message;

const MAINNET_PREFIX: &'static str = "f";
const TESTNET_PREFIX: &'static str = "t";

#[derive(Clone, Copy)]
pub enum Protocol {
    Secp256k1 = 1,
    BLS = 3,
}

#[derive(Debug)]
pub struct FilecoinAddress {}

impl FilecoinAddress {
    pub fn get_pub_key(path: &str) -> Result<String> {
        path::check_path_validity(path)?;

        let select_apdu = Apdu::select_applet(FILECOIN_AID);
        let select_response = message::send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = utility::secp256k1_sign(&key_manager_obj.pri_key, &path.as_bytes())?;

        let mut apdu_pack: Vec<u8> = vec![];
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.push(0x01);
        apdu_pack.push(path.as_bytes().len() as u8);
        apdu_pack.extend(path.as_bytes());

        //get public
        let msg_pubkey = Secp256k1Apdu::get_xpub(&apdu_pack);
        let res_msg_pubkey = message::send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let sign_source_val = &res_msg_pubkey[..194];
        let sign_result = &res_msg_pubkey[194..res_msg_pubkey.len() - 4];

        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let uncomprs_pubkey: String = res_msg_pubkey.chars().take(130).collect();
        Ok(uncomprs_pubkey)
    }

    fn checksum(ingest: &[u8]) -> Vec<u8> {
        digest(ingest, HashSize::Checksum)
    }

    fn address_hash(ingest: &[u8]) -> Vec<u8> {
        digest(ingest, HashSize::Payload)
    }

    pub fn get_address(path: &str, network: &str) -> Result<String> {
        let ntwk = match network {
            "TESTNET" => TESTNET_PREFIX,
            _ => MAINNET_PREFIX,
        };

        let uncomprs_pubkey = Self::get_pub_key(path).unwrap();
        let pub_key_bytes = hex::decode(uncomprs_pubkey).unwrap();
        let protocol = Protocol::Secp256k1;

        let payload = Self::address_hash(&pub_key_bytes);
        let cksm = Self::checksum(&[vec![protocol as u8], payload.clone().to_vec()].concat());

        Ok(format!(
            "{}{}{}",
            ntwk,
            protocol as i8,
            base32::encode(
                Alphabet::RFC4648 { padding: false },
                &[payload, cksm].concat()
            )
            .to_lowercase()
        ))
    }

    pub fn display_address(path: &str, network: &str) -> Result<String> {
        let address = Self::get_address(path, network).unwrap();
        let filecoin_menu_name = "FIL".as_bytes();
        let reg_apdu = Secp256k1Apdu::register_address(filecoin_menu_name, address.as_bytes());
        let res_reg = message::send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
    }
}

#[cfg(test)]
mod test {
    use crate::address::FilecoinAddress;
    use ikc_common::constants;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_get_pub_key() {
        bind_test();

        let uncomprs_pubkey = FilecoinAddress::get_pub_key(constants::FILECOIN_PATH).unwrap();
        assert_eq!(
            &uncomprs_pubkey,
            "044B9C3C0E1CEFD90897798E7CE471FEFF0D1BE4C6BA24061D7D9F68CFDB19A0EC0192392A94B121743ADB91C7029C6F3C80FD18B6E34E8B8F9EA87E559C68FDC4"
        );
    }

    #[test]
    fn test_get_address() {
        bind_test();

        let address = FilecoinAddress::get_address(constants::FILECOIN_PATH, "MAINNET").unwrap();
        assert_eq!(&address, "f1o2ph66tg7o7obyrqa7eiwiinrltauzxitkuk4ay");
    }

    #[test]
    fn test_display_address() {
        bind_test();
        let address =
            FilecoinAddress::display_address(constants::FILECOIN_PATH, "MAINNET").unwrap();
        assert_eq!(&address, "f1o2ph66tg7o7obyrqa7eiwiinrltauzxitkuk4ay");
    }
}
