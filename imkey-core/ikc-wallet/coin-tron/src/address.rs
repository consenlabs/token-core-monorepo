use crate::Result;
use bitcoin::util::base58;
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use bitcoin::Network;
use byteorder::{BigEndian, ByteOrder};
use ikc_common::apdu::{Apdu, ApduCheck, Secp256k1Apdu};
use ikc_common::constants::TRON_AID;
use ikc_common::error::CoinError;
use ikc_common::path::{check_path_validity, get_parent_path};
use ikc_common::utility;
use ikc_common::utility::secp256k1_sign;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::send_apdu;
use keccak_hash::keccak;
use secp256k1::PublicKey;
use std::convert::TryFrom;
use std::str::FromStr;

pub struct TronAddress {}

impl TronAddress {
    pub fn from_pub_key(pub_key: &[u8]) -> Result<String> {
        let public_key = PublicKey::from_slice(pub_key)?.serialize_uncompressed();
        let keccak_hash = keccak(public_key[1..].as_ref());
        let address = [vec![0x41], keccak_hash[12..].to_vec()].concat();
        let base58_address = base58::check_encode_slice(&address);
        Ok(base58_address)
    }

    pub fn get_address(path: &str) -> Result<String> {
        check_path_validity(path)?;

        let pubkey_raw = TronAddress::get_pub_key(path)?;

        let address = TronAddress::from_pub_key(&pubkey_raw[..65])?;
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

    pub fn get_pub_key(path: &str) -> Result<Vec<u8>> {
        check_path_validity(path)?;

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

        // Ok(hex::decode(&res_msg_pubkey[..130])?)
        Ok(hex::decode(sign_source_val)?)
    }

    pub fn get_xpub(path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        let pub_key = hex::encode(Self::get_pub_key(get_parent_path(path)?)?);
        let sub_pub_key = PublicKey::from_str(&pub_key[..130])?;
        let chain_code_obj = ChainCode::try_from(hex::decode(&pub_key[130..])?.as_slice())?;
        let ext_pub_key = ExtendedPubKey {
            network: Network::Testnet,
            depth: 0u8,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: sub_pub_key,
            chain_code: chain_code_obj,
        };
        let fingerprint_obj = ext_pub_key.fingerprint();

        let pub_key = hex::encode(Self::get_pub_key(path)?);
        let sub_pub_key = PublicKey::from_str(&pub_key[..130])?;
        let chain_code_obj = ChainCode::try_from(hex::decode(&pub_key[130..])?.as_slice())?;
        let chain_number_vec: Vec<ChildNumber> = DerivationPath::from_str(path)?.into();
        let ext_pub_key = ExtendedPubKey {
            network: Network::Bitcoin,
            depth: chain_number_vec.len() as u8,
            parent_fingerprint: fingerprint_obj,
            child_number: *chain_number_vec.get(chain_number_vec.len() - 1).unwrap(),
            public_key: sub_pub_key,
            chain_code: chain_code_obj,
        };

        Ok(ext_pub_key.to_string())
    }

    fn to_ss58check_with_version(extended_key: ExtendedPubKey, version: &[u8]) -> String {
        let mut ret = [0; 78];
        // let extended_key = self.0;
        ret[0..4].copy_from_slice(version);
        ret[4] = extended_key.depth;
        ret[5..9].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[9..13], u32::from(extended_key.child_number));

        ret[13..45].copy_from_slice(&extended_key.chain_code[..]);
        ret[45..78].copy_from_slice(&extended_key.public_key.serialize()[..]);
        base58::check_encode_slice(&ret[..])
    }
}

#[cfg(test)]
mod tests {
    use crate::address::TronAddress;
    use bitcoin::util::bip32::ExtendedPubKey;
    use ikc_common::constants;
    use ikc_common::path::get_account_path;
    use ikc_device::device_binding::bind_test;
    use std::str::FromStr;

    #[test]
    fn tron_address() {
        let bytes = hex::decode("04DAAC763B1B3492720E404C53D323BAF29391996F7DD5FA27EF0D12F7D50D694700684A32AD97FF4C09BF9CF0B9D0AC7F0091D9C6CB8BE9BB6A1106DA557285D8").unwrap();

        assert_eq!(
            TronAddress::from_pub_key(&bytes).unwrap(),
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

    #[test]
    fn test_get_xpub() {
        bind_test();
        let xpub = TronAddress::get_xpub(&get_account_path("m/44'/195'/0'/0/0").unwrap()).unwrap();
        let extended_pub_key = ExtendedPubKey::from_str(&xpub).unwrap();
        let res = TronAddress::to_ss58check_with_version(
            extended_pub_key,
            &hex::decode("043587cf").unwrap(),
        );
        assert_eq!("tpubDCxD6k9PreNhSacpfSZ3iErESZnncY1n7qU7e3stZXLPh84xVVt5ERMAqKeefUU8jswx2GpCkQpeYow4xH3PGx2iim6ftPa32GNvTKAtknz", res);
    }
}
