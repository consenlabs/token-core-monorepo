use crate::Result;
use anyhow::anyhow;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::base58;
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use bitcoin::Network;
use bitcoin_hashes::{ripemd160, Hash};
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, EosApdu, Secp256k1Apdu};
use ikc_common::constants::EOS_AID;
use ikc_common::error::CoinError;
use ikc_common::path::{check_path_validity, get_parent_path};
use ikc_common::{path, utility};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_apple_version;
use ikc_transport::message::send_apdu;
use std::str::FromStr;

#[derive(Debug)]
pub struct EosPubkey {}

impl EosPubkey {
    pub fn get_pubkey(path: &str) -> Result<String> {
        let version = get_apple_version(EOS_AID)?;
        match version.as_str() {
            "0.0.1" => Self::get_pubkey_for_eos(path),
            _ => Self::get_pubkey_for_k1(path),
        }
    }

    pub fn get_pubkey_for_eos(path: &str) -> Result<String> {
        path::check_path_validity(path)?;

        let select_apdu = EosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public key
        let msg_pubkey = EosApdu::get_xpub(&path, true);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let sign_source_val = &res_msg_pubkey[..194];
        let sign_result = &res_msg_pubkey[194..res_msg_pubkey.len() - 4];

        let key_manager_obj = KEY_MANAGER.lock();

        //use se public key verify sign
        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(anyhow!("imkey_signature_verify_fail"));
        }

        //compressed key
        let uncomprs_pubkey: String = res_msg_pubkey
            .chars()
            .take(res_msg_pubkey.len() - 4)
            .collect();
        let comprs_pubkey = utility::uncompress_pubkey_2_compress(&uncomprs_pubkey);

        //checksum base58
        let mut comprs_pubkey_slice = hex::decode(comprs_pubkey).expect("Decoding failed");
        let pubkey_hash = ripemd160::Hash::hash(&comprs_pubkey_slice);
        let check_sum = &pubkey_hash[0..4];
        comprs_pubkey_slice.extend(check_sum);
        let eos_pk = "EOS".to_owned() + base58::encode_slice(&comprs_pubkey_slice).as_ref();

        Ok(eos_pk)
    }

    pub fn get_pubkey_for_k1(path: &str) -> Result<String> {
        path::check_path_validity(path)?;

        let select_apdu = EosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public key
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
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
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

        let comprs_pubkey = utility::uncompress_pubkey_2_compress(&sign_source_val);

        //checksum base58
        let mut comprs_pubkey_slice = hex::decode(comprs_pubkey).expect("Decoding failed");
        let pubkey_hash = ripemd160::Hash::hash(&comprs_pubkey_slice);
        let check_sum = &pubkey_hash[0..4];
        comprs_pubkey_slice.extend(check_sum);
        let eos_pk = "EOS".to_owned() + base58::encode_slice(&comprs_pubkey_slice).as_ref();

        Ok(eos_pk)
    }

    pub fn get_sub_pubkey(path: &str) -> Result<String> {
        path::check_path_validity(path)?;

        let select_apdu = EosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public key
        let msg_pubkey = EosApdu::get_xpub(&path, true);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let sign_source_val = &res_msg_pubkey[..194];
        let sign_result = &res_msg_pubkey[194..res_msg_pubkey.len() - 4];

        let key_manager_obj = KEY_MANAGER.lock();

        //use se public key verify sign
        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(anyhow!("imkey_signature_verify_fail"));
        }

        Ok(sign_source_val.to_string())
    }

    pub fn get_xpub(path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub data
        let xpub_data = Self::get_sub_pubkey(path)?;

        //get public key and chain code
        let pub_key = &xpub_data[..130];
        let sub_chain_code = &xpub_data[130..];
        let pub_key_obj = PublicKey::from_str(pub_key)?;

        //build parent public key obj
        let parent_xpub_data = Self::get_sub_pubkey(get_parent_path(path)?)?;
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

    pub fn pubkey_from_response(response: &str) -> Result<String> {
        //compressed key
        let uncomprs_pubkey: String = response.chars().take(response.len() - 4).collect();
        let comprs_pubkey = utility::uncompress_pubkey_2_compress(&uncomprs_pubkey);

        //checksum base58
        let mut comprs_pubkey_slice = hex::decode(comprs_pubkey).expect("Decoding failed");
        let pubkey_hash = ripemd160::Hash::hash(&comprs_pubkey_slice);
        let check_sum = &pubkey_hash[0..4];
        comprs_pubkey_slice.extend(check_sum);
        let eos_pk = "EOS".to_owned() + base58::encode_slice(&comprs_pubkey_slice).as_ref();

        Ok(eos_pk)
    }

    pub fn display_pubkey(path: &str) -> Result<String> {
        let version = get_apple_version(EOS_AID)?;
        match version.as_str() {
            "0.0.1" => Self::display_pubkey_for_eos(path),
            _ => Self::display_pubkey_for_k1(path),
        }
    }

    pub fn display_pubkey_for_eos(path: &str) -> Result<String> {
        let pubkey = EosPubkey::get_pubkey(path)?;
        let reg_apdu = EosApdu::register_address(pubkey.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(pubkey)
    }

    pub fn display_pubkey_for_k1(path: &str) -> Result<String> {
        let pubkey = EosPubkey::get_pubkey(path)?;
        let eos_menu_name = "EOS".as_bytes();
        let reg_apdu = Secp256k1Apdu::register_address(eos_menu_name, pubkey.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(pubkey)
    }

    pub fn from_pub_key(pub_key: &[u8]) -> Result<String> {
        let mut compressed_pub_key = PublicKey::from_slice(pub_key)?.serialize().to_vec();
        //checksum base58
        let pub_key_hash = ripemd160::Hash::hash(&compressed_pub_key);
        let check_sum = &pub_key_hash[0..4];
        compressed_pub_key.extend(check_sum);
        let eos_pk = "EOS".to_owned() + base58::encode_slice(&compressed_pub_key).as_ref();
        Ok(eos_pk)
    }
}

#[cfg(test)]
mod tests {
    use crate::pubkey::EosPubkey;
    use ikc_common::constants;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_get_pubkey() {
        bind_test();

        let pubkey = EosPubkey::get_pubkey(constants::EOS_PATH);
        assert_eq!(
            format!("{}", pubkey.unwrap()),
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF"
        );
    }

    #[test]
    fn pubkey_from_response() {
        let response = "04AAF80E479AAC0813B17950C390A16438B307AEE9A814689D6706BE4FB4A4E30A4D2A7F75EF43344FA80580B5B1FBF9F233C378D99D5ADB5CAC9AE86F562803E13DC6BED90C9CE56BB58C24F200D64966E9553CCAAA731DD6B0B2C1C7708C55E53045022012B1393FAED0B88BD8FFC1333DC61F0D7FC862454339574A3A550D555F0ACCD2022100AF1C929FECB18F3226E0DB511731FA9D7016C23CB8E7AD30F5327B4CF681DD729000";
        let pubkey = EosPubkey::pubkey_from_response(response);
        assert_eq!(
            format!("{}", pubkey.unwrap()),
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF"
        );
    }

    #[test]
    fn test_display_pubkey() {
        bind_test();

        let pubkey = EosPubkey::display_pubkey(constants::EOS_PATH);
        assert_eq!(
            format!("{}", pubkey.unwrap()),
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF"
        );
    }
}
