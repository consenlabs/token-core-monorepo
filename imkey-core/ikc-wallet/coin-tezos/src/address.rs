use crate::Result;
use bitcoin::util::base58;
use blake2b_simd::Params;
use ikc_common::apdu::{Apdu, ApduCheck, Ed25519Apdu};
use ikc_common::constants::TEZOS_AID;
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{secp256k1_sign, secp256k1_sign_verify, sha256_hash};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::send_apdu;

pub struct TezosAddress();

impl TezosAddress {
    pub fn get_address(path: &str) -> Result<String> {
        //get public key
        let pubkey = Self::get_pub_key(path)?;
        let pubkey_bytes = hex::decode(pubkey)?;
        //Perform Blake2B hashing on the public key（no prefix）
        let mut params = Params::new();
        params.hash_length(20);
        let generic_hash = params.hash(&pubkey_bytes[..]);
        //sha256Twice(prefix<3> + public key hash<20>)
        let mut prefixed_generic_hash = vec![];
        let tz1_prefix = hex::decode("06A19F")?;
        prefixed_generic_hash.extend_from_slice(tz1_prefix.as_ref());
        prefixed_generic_hash.extend_from_slice(generic_hash.as_bytes());
        let double_hash_result = sha256_hash(&sha256_hash(&prefixed_generic_hash));
        prefixed_generic_hash.extend_from_slice(&double_hash_result[..4]);
        //base58Encode(prefix<3> + public key hash<20> + checksum<4>)
        let address = base58::encode_slice(prefixed_generic_hash.as_slice());
        Ok(address)
    }

    pub fn get_pub_key(path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        let select_apdu = Apdu::select_applet(TEZOS_AID);
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, path.as_bytes())?;

        let mut apdu_pack: Vec<u8> = vec![];
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.push(0x01);
        apdu_pack.push(path.as_bytes().len() as u8);
        apdu_pack.extend(path.as_bytes());

        //get public
        let msg_pubkey = Ed25519Apdu::get_xpub(&apdu_pack);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let pubkey = &res_msg_pubkey[..64];
        let sign_result = &res_msg_pubkey[64..res_msg_pubkey.len() - 4];
        println!("pubkey: {}", pubkey);

        //verify
        let sign_verify_result = secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(pubkey).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        Ok(pubkey.to_string())
    }

    pub fn get_base58_pub_key(path: &str) -> Result<String> {
        let pub_key = Self::get_pub_key(path)?;
        let edpk_prefix: Vec<u8> = vec![0x0D, 0x0F, 0x25, 0xD9];

        let pub_key_bytes = hex::decode(pub_key)?;
        let to_hash = [edpk_prefix, pub_key_bytes].concat();
        let hashed = sha256_hash(&sha256_hash(&to_hash));
        let hash_with_checksum = [to_hash, hashed[0..4].to_vec()].concat();
        let edpk = base58::encode_slice(&hash_with_checksum);

        Ok(edpk.to_string())
    }

    pub fn display_address(path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        let address_str = Self::get_address(path)?;
        let tezos_menu_name = "TEZOS".as_bytes();
        let apdu_res = send_apdu(Ed25519Apdu::register_address(
            tezos_menu_name,
            address_str.as_bytes(),
        ))?;
        ApduCheck::check_response(apdu_res.as_str())?;
        Ok(address_str)
    }
}

#[cfg(test)]
mod test {
    use crate::address::TezosAddress;
    use ikc_device::device_binding::bind_test;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    fn get_address_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        bind_test();
        let address = TezosAddress::get_address("m/44'/1729'/0'/0'").unwrap();
        assert_eq!(address, "tz1d2TfcvWBwtPqo7f21DVv7HSSCoNAVp8gz".to_string());
    }

    #[test]
    fn display_address_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        bind_test();
        let result = TezosAddress::display_address("m/44'/1729'/0'/0'").unwrap();
        assert_eq!(result, "tz1d2TfcvWBwtPqo7f21DVv7HSSCoNAVp8gz".to_string());
    }
}
