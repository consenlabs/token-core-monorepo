use crate::Result;
use bech32::{encode, ToBase32, Variant};
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use bitcoin::Network;
use bitcoin_hashes::hex::{FromHex, ToHex};
use bitcoin_hashes::{hash160, Hash};
use hex;
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, CosmosApdu, Secp256k1Apdu};
use ikc_common::constants::{COSMOS_AID, COSMOS_LEGACY_APPLET_VERSION};
use ikc_common::error::CoinError;
use ikc_common::path;
use ikc_common::path::{check_path_validity, get_parent_path};
use ikc_common::utility;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_apple_version;
use ikc_transport::message::send_apdu;
use secp256k1::PublicKey;
use std::str::FromStr;

#[derive(Debug)]
pub struct CosmosAddress {}

impl CosmosAddress {
    pub fn get_pub_key(path: &str) -> Result<String> {
        let version = get_apple_version(COSMOS_AID)?;
        match version.as_str() {
            COSMOS_LEGACY_APPLET_VERSION => Self::get_pub_key_for_cosmos(path),
            _ => Self::get_pub_key_for_k1(path),
        }
    }

    pub fn get_pub_key_for_cosmos(path: &str) -> Result<String> {
        path::check_path_validity(path)?;

        let select_apdu = CosmosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public
        let msg_pubkey = CosmosApdu::get_xpub(&path, true);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
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

        Ok(sign_source_val.to_string())
    }

    pub fn get_pub_key_for_k1(path: &str) -> Result<String> {
        path::check_path_validity(path)?;

        let select_apdu = CosmosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get public
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

        Ok(sign_source_val.to_string())
    }

    pub fn get_address(path: &str) -> Result<String> {
        let compress_pubkey =
            utility::uncompress_pubkey_2_compress(&CosmosAddress::get_pub_key(path)?);
        //hash160
        let pub_key_bytes = hex::decode(compress_pubkey).unwrap();
        let pub_key_hash = hash160::Hash::hash(&pub_key_bytes).to_hex();
        let hh = Vec::from_hex(&pub_key_hash).unwrap();
        let address = encode("cosmos", hh.to_base32(), Variant::Bech32)?;
        Ok(address)
    }

    pub fn display_address(path: &str) -> Result<String> {
        let version = get_apple_version(COSMOS_AID)?;
        match version.as_str() {
            COSMOS_LEGACY_APPLET_VERSION => Self::display_address_for_cosmos(path),
            _ => Self::display_address_for_k1(path),
        }
    }

    pub fn display_address_for_cosmos(path: &str) -> Result<String> {
        let address = CosmosAddress::get_address(path).unwrap();
        let reg_apdu = CosmosApdu::register_address(address.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
    }

    pub fn display_address_for_k1(path: &str) -> Result<String> {
        let address = Self::get_address(path).unwrap();
        let cosmos_menu_name = "ATOM".as_bytes();
        let reg_apdu = Secp256k1Apdu::register_address(cosmos_menu_name, address.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
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

    pub fn from_pub_key(pub_key: Vec<u8>) -> Result<String> {
        let public_key = PublicKey::from_slice(pub_key.as_slice())?;
        let compressed_pubkey = public_key.serialize();
        let pub_key_hash = hash160::Hash::hash(&compressed_pubkey).to_vec();
        let address = encode("cosmos", pub_key_hash.to_base32(), Variant::Bech32)?;
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
            "0432C1EF21D73C19531B0AA4E863CF397C2B982B2F958F60CDB62969824C096D658AEDE012F4A4B2E3A893B71A787617FEB04F19D2E3BAC5CEE989AA55E8057458CCAAB803B2556DC264D2EE7836AC20B3E2FADB725DA9167F87BD10013D9E48F3"
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
