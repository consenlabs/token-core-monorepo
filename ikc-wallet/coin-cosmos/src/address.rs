use crate::Result;
// use bech32::bech32::Bech32;
use bech32::{encode, ToBase32, Variant};
use bitcoin::bech32::convert_bits;
use bitcoin_hashes::hex::{FromHex, ToHex};
use bitcoin_hashes::{hash160, Hash};
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, CosmosApdu};
use ikc_common::error::CoinError;
use ikc_common::path;
use ikc_common::utility;
use ikc_device::device_binding::KEY_MANAGER;
use hex;
use ikc_transport::message;

#[derive(Debug)]
pub struct CosmosAddress {}

impl CosmosAddress {
    pub fn get_pub_key(path: &str) -> Result<String> {
        path::check_path_validity(path)?;

        let select_apdu = CosmosApdu::select_applet();
        let select_response = message::send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public
        let msg_pubkey = CosmosApdu::get_xpub(&path, true);
        let res_msg_pubkey = message::send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let sign_source_val = &res_msg_pubkey[..194];
        let sign_result = &res_msg_pubkey[194..res_msg_pubkey.len() - 4];

        let key_manager_obj = KEY_MANAGER.lock();

        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let uncomprs_pubkey: String = res_msg_pubkey
            .chars()
            .take(res_msg_pubkey.len() - 4)
            .collect();
        let comprs_pubkey = utility::uncompress_pubkey_2_compress(&uncomprs_pubkey);

        Ok(comprs_pubkey)
    }

    pub fn get_address(path: &str) -> Result<String> {
        let comprs_pubkey = CosmosAddress::get_pub_key(path).unwrap();
        //hash160
        let pub_key_bytes = hex::decode(comprs_pubkey).unwrap();
        let pub_key_hash = hash160::Hash::hash(&pub_key_bytes).to_hex();
        let hh = Vec::from_hex(&pub_key_hash).unwrap();
        let address = encode("cosmos", hh.to_base32(), Variant::Bech32)?;
        Ok(address)
    }

    pub fn display_address(path: &str) -> Result<String> {
        let address = CosmosAddress::get_address(path).unwrap();
        let reg_apdu = CosmosApdu::register_address(address.as_bytes());
        let res_reg = message::send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use crate::address::CosmosAddress;
    use bech32::{ToBase32, Variant};
    use ikc_common::constants;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_get_pub_key() {
        bind_test();

        let comprs_pubkey = CosmosAddress::get_pub_key(constants::COSMOS_PATH).unwrap();
        assert_eq!(
            &comprs_pubkey,
            "0232C1EF21D73C19531B0AA4E863CF397C2B982B2F958F60CDB62969824C096D65"
        );
    }

    #[test]
    fn test_get_address() {
        bind_test();

        let address = CosmosAddress::get_address(constants::COSMOS_PATH).unwrap();
        assert_eq!(&address, "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992");
    }

    #[test]
    fn test_display_address() {
        bind_test();
        let address = CosmosAddress::display_address(constants::COSMOS_PATH).unwrap();
        assert_eq!(&address, "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992");
    }

    #[test]
    fn test_bech32() {
        let b32 = bech32::encode(
            "bech32",
            vec![0x00, 0x01, 0x02].to_base32(),
            Variant::Bech32,
        );
        let address = match b32 {
            Ok(s) => s,
            Err(_e) => return,
        };
        assert_eq!(address, "bech321qqqsyrhqy2a".to_string());
    }
}
