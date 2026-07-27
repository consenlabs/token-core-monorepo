use crate::Result;
use ikc_common::apdu::{Apdu, ApduCheck, Ed25519Apdu};
use ikc_common::constants::TEZOS_AID;
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{secp256k1_sign, secp256k1_sign_verify};
use ikc_device::async_device_manager::AsyncApduTransport;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::send_apdu;

pub struct TezosAddress();

impl TezosAddress {
    async fn send_checked<T>(transport: &T, apdu: String) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        let response = transport.send_apdu(&apdu, 20).await?;
        ApduCheck::check_response(&response)?;
        Ok(response)
    }

    pub async fn get_address_async<T>(transport: &T, path: &str) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        let pubkey = Self::get_pub_key_async(transport, path).await?;
        let pubkey_bytes = hex::decode(pubkey)?;
        wallet_core_common::tezos::tz1_address_from_public_key(&pubkey_bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid_public_key"))
    }

    pub async fn get_pub_key_async<T>(transport: &T, path: &str) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        check_path_validity(path)?;

        let select_apdu = Apdu::try_select_applet(TEZOS_AID)?;
        Self::send_checked(transport, select_apdu).await?;

        let (bind_signature, se_pub_key) = {
            let key_manager_obj = KEY_MANAGER.lock();
            (
                secp256k1_sign(&key_manager_obj.pri_key, path.as_bytes())?,
                key_manager_obj.se_pub_key.clone(),
            )
        };

        let mut apdu_pack: Vec<u8> = vec![];
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.push(0x01);
        apdu_pack.push(path.len() as u8);
        apdu_pack.extend(path.as_bytes());

        let msg_pubkey = Ed25519Apdu::try_get_xpub(&apdu_pack)?;
        let res_msg_pubkey = Self::send_checked(transport, msg_pubkey).await?;

        let pubkey = res_msg_pubkey.get(..64).ok_or(CoinError::InvalidParam)?;
        let sign_result_end = res_msg_pubkey
            .len()
            .checked_sub(4)
            .ok_or(CoinError::InvalidParam)?;
        let sign_result = res_msg_pubkey
            .get(64..sign_result_end)
            .ok_or(CoinError::InvalidParam)?;

        let sign_verify_result = secp256k1_sign_verify(
            &se_pub_key,
            hex::decode(sign_result)?.as_slice(),
            hex::decode(pubkey)?.as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        Ok(pubkey.to_string())
    }

    pub async fn get_base58_pub_key_async<T>(transport: &T, path: &str) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        let pub_key = Self::get_pub_key_async(transport, path).await?;
        let pub_key_bytes = hex::decode(pub_key)?;
        Ok(wallet_core_common::tezos::encode_ed25519_public_key(
            &pub_key_bytes,
        ))
    }

    pub async fn display_address_async<T>(transport: &T, path: &str) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        check_path_validity(path)?;

        let address_str = Self::get_address_async(transport, path).await?;
        let tezos_menu_name = "TEZOS".as_bytes();
        let apdu_res = Self::send_checked(
            transport,
            Ed25519Apdu::register_address(tezos_menu_name, address_str.as_bytes())?,
        )
        .await?;
        ApduCheck::check_response(apdu_res.as_str())?;
        Ok(address_str)
    }

    pub fn get_address(path: &str) -> Result<String> {
        //get public key
        let pubkey = Self::get_pub_key(path)?;
        let pubkey_bytes = hex::decode(pubkey)?;
        wallet_core_common::tezos::tz1_address_from_public_key(&pubkey_bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid_public_key"))
    }

    pub fn get_pub_key(path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        let select_apdu = Apdu::try_select_applet(TEZOS_AID)?;
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, path.as_bytes())?;

        let mut apdu_pack: Vec<u8> = vec![];
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.push(0x01);
        apdu_pack.push(path.len() as u8);
        apdu_pack.extend(path.as_bytes());

        //get public
        let msg_pubkey = Ed25519Apdu::try_get_xpub(&apdu_pack)?;
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let pubkey = res_msg_pubkey.get(..64).ok_or(CoinError::InvalidParam)?;
        let sign_result_end = res_msg_pubkey
            .len()
            .checked_sub(4)
            .ok_or(CoinError::InvalidParam)?;
        let sign_result = res_msg_pubkey
            .get(64..sign_result_end)
            .ok_or(CoinError::InvalidParam)?;
        println!("pubkey: {}", pubkey);

        //verify
        let sign_verify_result = secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result)?.as_slice(),
            hex::decode(pubkey)?.as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        Ok(pubkey.to_string())
    }

    pub fn get_base58_pub_key(path: &str) -> Result<String> {
        let pub_key = Self::get_pub_key(path)?;
        let pub_key_bytes = hex::decode(pub_key)?;
        Ok(wallet_core_common::tezos::encode_ed25519_public_key(
            &pub_key_bytes,
        ))
    }

    pub fn display_address(path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        let address_str = Self::get_address(path)?;
        let tezos_menu_name = "TEZOS".as_bytes();
        let apdu_res = send_apdu(Ed25519Apdu::register_address(
            tezos_menu_name,
            address_str.as_bytes(),
        )?)?;
        ApduCheck::check_response(apdu_res.as_str())?;
        Ok(address_str)
    }
}

// #[cfg(test)]
// mod test {
//     use crate::address::TezosAddress;
//     use ikc_device::device_binding::bind_test;
//     use ikc_transport::hid_api::hid_connect;

//     #[test]
//     fn get_address_test() {
//         assert!(hid_connect("imKey Pro").is_ok());
//         bind_test();
//         let address = TezosAddress::get_address("m/44'/1729'/0'/0'").unwrap();
//         assert_eq!(address, "tz1d2TfcvWBwtPqo7f21DVv7HSSCoNAVp8gz".to_string());
//     }

//     #[test]
//     fn display_address_test() {
//         assert!(hid_connect("imKey Pro").is_ok());
//         bind_test();
//         let result = TezosAddress::display_address("m/44'/1729'/0'/0'").unwrap();
//         assert_eq!(result, "tz1d2TfcvWBwtPqo7f21DVv7HSSCoNAVp8gz".to_string());
//     }
// }
