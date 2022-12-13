use crate::Result;
use bitcoin::util::base58;
use bitcoin_hashes::{ripemd160, Hash};
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, EosApdu};
use ikc_common::{path, utility};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message;

#[derive(Debug)]
pub struct EosPubkey {}

impl EosPubkey {
    pub fn get_pubkey(path: &str) -> Result<String> {
        path::check_path_validity(path)?;

        let select_apdu = EosApdu::select_applet();
        let select_response = message::send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public key
        let msg_pubkey = EosApdu::get_xpub(&path, true);
        let res_msg_pubkey = message::send_apdu(msg_pubkey)?;
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
            return Err(format_err!("imkey_signature_verify_fail"));
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
        let pubkey = EosPubkey::get_pubkey(path).unwrap();
        let reg_apdu = EosApdu::register_address(pubkey.as_bytes());
        let res_reg = message::send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(pubkey)
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
