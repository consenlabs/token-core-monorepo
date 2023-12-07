use crate::Result;
use bitcoin::util::base58;
use ikc_common::apdu::{Apdu, ApduCheck, Secp256k1Apdu};
use ikc_common::constants::TRON_AID;
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility;
use ikc_common::utility::secp256k1_sign;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::send_apdu;
use keccak_hash::keccak;

pub struct TronAddress {}

impl TronAddress {
    pub fn address_from_pubkey(pubkey: &[u8]) -> Result<String> {
        let pubkey_hash = keccak(pubkey[1..].as_ref());
        let address = [vec![0x41], pubkey_hash[12..].to_vec()].concat();
        let base58_address = base58::check_encode_slice(&address);
        Ok(base58_address)
    }

    pub fn get_address(path: &str) -> Result<String> {
        check_path_validity(path).unwrap();

        let select_apdu = Apdu::select_applet(TRON_AID);
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &path.as_bytes())?;

        let mut apdu_pack: Vec<u8> = vec![];
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.push(0x01);
        apdu_pack.push(path.as_bytes().len() as u8);
        apdu_pack.extend(path.as_bytes());

        //get public
        let msg_pubkey = Secp256k1Apdu::get_xpub(&apdu_pack);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let sign_source_val = &res_msg_pubkey[..194];
        let sign_result = &res_msg_pubkey[194..res_msg_pubkey.len() - 4];

        //verify
        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let pubkey_raw = hex::decode(&res_msg_pubkey[..130]).unwrap();

        let address = TronAddress::address_from_pubkey(pubkey_raw.as_slice())?;
        Ok(address)
    }

    pub fn display_address(path: &str) -> Result<String> {
        let address = TronAddress::get_address(path).unwrap();
        let tron_menu_name = "TRX".as_bytes();
        let reg_apdu = Secp256k1Apdu::register_address(tron_menu_name, address.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use crate::address::TronAddress;
    use ikc_common::constants;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn tron_address() {
        let bytes = hex::decode("04DAAC763B1B3492720E404C53D323BAF29391996F7DD5FA27EF0D12F7D50D694700684A32AD97FF4C09BF9CF0B9D0AC7F0091D9C6CB8BE9BB6A1106DA557285D8").unwrap();

        assert_eq!(
            TronAddress::address_from_pubkey(&bytes).unwrap(),
            "THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acotq"
        );
    }

    #[test]
    fn test_get_address() {
        bind_test();
        let address = TronAddress::get_address(constants::TRON_PATH).unwrap();
        assert_eq!(&address, "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2");
    }

    #[test]
    fn test_display_address() {
        bind_test();
        let address = TronAddress::display_address(constants::TRON_PATH).unwrap();
        println!("address:{}", &address);
        assert_eq!(&address, "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2");
    }
}
