use crate::hash::blake2b_160;
use crate::Result;
use bech32::{ToBase32, Variant};
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use ikc_common::apdu::{Apdu, ApduCheck, Secp256k1Apdu};
use ikc_common::constants::NERVOS_AID;
use ikc_common::error::{CoinError, CommonError};
use ikc_common::path::check_path_validity;
use ikc_common::utility::{network_convert, secp256k1_sign, secp256k1_sign_verify};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::send_apdu;
use secp256k1::hashes::hex::FromHex;
use secp256k1::{PublicKey as Secp256k1PublicKey, PublicKey};
use std::str::FromStr;

pub struct CkbAddress {}

impl CkbAddress {
    pub fn from_public_key(network: &str, pubkey: &[u8]) -> Result<String> {
        let prefix = match network {
            "TESTNET" => "ckt",
            _ => "ckb",
        };
        let pub_key_hash = blake2b_160(PublicKey::from_slice(pubkey)?.serialize());

        let mut buf = vec![];
        buf.extend(vec![0x1, 0x00]); // append short version for locks with popular codehash and default code hash index
        buf.extend(pub_key_hash);

        Ok(bech32::encode(prefix, buf.to_base32(), Variant::Bech32)?)
    }

    pub fn get_public_key(path: &str) -> Result<String> {
        check_path_validity(path)?;

        let select_apdu = Apdu::select_applet(NERVOS_AID);
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
        let msg_pubkey = Secp256k1Apdu::get_xpub(&apdu_pack);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let sign_source_val = &res_msg_pubkey[..194];
        let sign_result = &res_msg_pubkey[194..res_msg_pubkey.len() - 4];

        //verify
        let sign_verify_result = secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let pub_key = &res_msg_pubkey[0..130];
        Ok(pub_key.to_string())
    }

    pub fn get_address(network: &str, path: &str) -> Result<String> {
        let pub_key = CkbAddress::get_public_key(path)?;
        let address = CkbAddress::from_public_key(network, &Vec::from_hex(&pub_key)?)?;
        Ok(address)
    }

    pub fn display_address(network: &str, path: &str) -> Result<String> {
        let address = CkbAddress::get_address(network, path)?;
        let menu_name = "CKB".as_bytes();
        let reg_apdu = Secp256k1Apdu::register_address(menu_name, address.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
    }

    pub fn get_enc_xpub(network: &str, path: &str) -> Result<String> {
        let xpub = Self::get_xpub(network, path)?;
        let key = ikc_common::XPUB_COMMON_KEY_128.read();
        let iv = ikc_common::XPUB_COMMON_IV.read();
        let key_bytes = hex::decode(&*key)?;
        let iv_bytes = hex::decode(&*iv)?;
        let encrypted =
            ikc_common::aes::cbc::encrypt_pkcs7(&xpub.as_bytes(), &key_bytes, &iv_bytes)?;
        Ok(base64::encode(&encrypted))
    }

    pub fn get_xpub(network: &str, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub data
        let xpub_data = CkbAddress::get_xpub_data(path)?;
        let xpub_data = &xpub_data[..194];

        //get public key and chain code
        let pub_key = &xpub_data[..130];
        let sub_chain_code = &xpub_data[130..];
        let pub_key_obj = Secp256k1PublicKey::from_str(pub_key)?;

        //build parent public key obj
        let parent_xpub_data = CkbAddress::get_xpub_data(Self::get_parent_path(path)?)?;
        let parent_xpub_data = &parent_xpub_data[..194];
        let parent_pub_key = &parent_xpub_data[..130];
        let parent_chain_code = &parent_xpub_data[130..];
        let parent_pub_key_obj = Secp256k1PublicKey::from_str(parent_pub_key)?;

        //get parent public key fingerprint
        let parent_chain_code = ChainCode::from(hex::decode(parent_chain_code)?.as_slice());
        let network = network_convert(network);
        let parent_ext_pub_key = ExtendedPubKey {
            network,
            depth: 0u8,
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
            network: network,
            depth: chain_number_vec.len() as u8,
            parent_fingerprint: fingerprint_obj,
            child_number: *chain_number_vec.get(chain_number_vec.len() - 1).unwrap(),
            public_key: pub_key_obj,
            chain_code: sub_chain_code_obj,
        };
        //get and return xpub
        Ok(extend_public_key.to_string())
    }

    pub fn get_xpub_data(path: &str) -> Result<String> {
        let select_apdu = Apdu::select_applet(NERVOS_AID);
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

        let apdu_xpub = Secp256k1Apdu::get_xpub(&apdu_pack);
        let xpub_data = send_apdu(apdu_xpub)?;
        ApduCheck::check_response(&xpub_data)?;
        Ok(xpub_data)
    }

    fn get_parent_path(path: &str) -> Result<&str> {
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
}

#[cfg(test)]
mod tests {
    use crate::address::CkbAddress;
    use ikc_common::constants;
    use ikc_common::{XPUB_COMMON_IV, XPUB_COMMON_KEY_128};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_from_public_key() {
        let bytes =
            hex::decode("024a501efd328e062c8675f2365970728c859c592beeefd6be8ead3d901330bc01")
                .expect("hex decode error");
        let network = "TESTNET";
        assert_eq!(
            CkbAddress::from_public_key(network, &bytes).expect("invalid public key"),
            "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqswmu83"
        );

        let bytes =
            hex::decode("024a501efd328e062c8675f2365970728c859c592beeefd6be8ead3d901330bc01")
                .expect("hex decode error");
        let network = "MAINNET";
        assert_eq!(
            CkbAddress::from_public_key(network, &bytes).expect("invalid public key"),
            "ckb1qyqrdsefa43s6m882pcj53m4gdnj4k440axqdt9rtd"
        );
    }

    #[test]
    fn test_get_public_key() {
        bind_test();

        let _network = "TESTNET";
        let pk = CkbAddress::get_public_key(constants::NERVOS_PATH).expect("get pubkey fail");
        assert_eq!(&pk, "04554851980004FF256888612BF0D64D9B1002BF82331450FD5A7405D1B23CC5BD2F4DDA9D71F6502CD761AFB29B1A89AECEBC832851CD361D3351216F08635BBF");
    }

    #[test]
    fn test_get_address() {
        bind_test();

        let network = "TESTNET";
        let address =
            CkbAddress::get_address(network, constants::NERVOS_PATH).expect("get address fail");
        assert_eq!(&address, "ckt1qyqtr684u76tu7r8efkd24hw8922xfvhnazskzdzy6");
    }

    #[test]
    fn test_display_address() {
        bind_test();

        let network = "TESTNET";
        let address =
            CkbAddress::display_address(network, constants::NERVOS_PATH).expect("get address fail");
        println!("address:{}", &address);
        assert_eq!(&address, "ckt1qyqtr684u76tu7r8efkd24hw8922xfvhnazskzdzy6");
    }

    #[test]
    fn get_xpub_test() {
        bind_test();
        *XPUB_COMMON_KEY_128.write() = "4A2B655485ABBAB54BD30298BB0A5B55".to_string();
        *XPUB_COMMON_IV.write() = "73518399CB98DCD114D873E06EBF4BCC".to_string();

        let path: &str = "m/44'/309'/0'";
        let get_xpub_result = CkbAddress::get_xpub("MAINNET", path);
        assert!(get_xpub_result.is_ok());
        let xpub = get_xpub_result.ok().unwrap();
        assert_eq!("xpub6CyvXfYwHJjJ9syYjG7qZMva1yMx93SUmqUcKHvoReUadCzqJA8mMXrrXQjRvzveuahgdQmCsdsuiCkMRsLec63DW83Wwu5UqKJQmsonKpo", xpub);

        let path: &str = "m/44'/309'/0'";
        let get_enc_xpub_result = CkbAddress::get_enc_xpub("MAINNET", path);
        let enc_xpub = get_enc_xpub_result.ok().unwrap();
        assert_eq!("xkpmspgDJhDx7nBk/se+P0CRS/fbPKYivQiqocPEdXFIsNLCHy5lZEc59LGLbsFFamWX7j8TUs5ugKynEign+y0hDQIhm3y1PypmU+frhoWckc7vgkdzbd9xGdMTVv7J+JW4Zlenksb8a9UNkRfrJg==", enc_xpub);
    }
}
