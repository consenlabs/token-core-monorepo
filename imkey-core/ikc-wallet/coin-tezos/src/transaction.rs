use crate::tezosapi::{TezosTxInput, TezosTxOutput};
use crate::Result;
use anyhow::anyhow;
use bitcoin::util::base58;
use blake2b_simd::Params;
use ikc_common::apdu::{Apdu, ApduCheck, Ed25519Apdu};
use ikc_common::constants::{TEZOS_AID, TIMEOUT_LONG};
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{secp256k1_sign, secp256k1_sign_verify, sha256_hash};
use ikc_common::SignParam;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};

pub struct Transaction();

impl Transaction {
    pub fn sign_tx(tezos_tx_input: TezosTxInput, sign_param: &SignParam) -> Result<TezosTxOutput> {
        //check path
        check_path_validity(&sign_param.path).expect("check path error");
        let path_parts = sign_param.path.split('/').collect::<Vec<_>>();
        if path_parts[2] != "1729'" {
            return Err(anyhow!("invalid_sign_path"));
        }
        //check address
        Self::address_check(sign_param.receiver.as_str());

        let raw_data_bytes = if tezos_tx_input.raw_data.starts_with("0x") {
            tezos_tx_input.raw_data[2..].to_string()
        } else {
            tezos_tx_input.raw_data.clone()
        };

        //Blake2b hash
        let mut params = Params::new();
        params.hash_length(32);
        //add watermark https://gitlab.com/tezos/tezos/-/issues/199
        let mut hash_message: Vec<u8> = vec![0x03];
        hash_message.extend(hex::decode(&raw_data_bytes)?.as_slice());
        let hash_result = params.hash(hash_message.as_slice());

        let mut message_pack: Vec<u8> = vec![];
        //add hash
        message_pack.push(0x01 as u8);
        message_pack.push(hash_result.as_bytes().len() as u8);
        message_pack.extend(hash_result.as_bytes());
        //add path
        message_pack.push(0x02 as u8);
        message_pack.push(sign_param.path.as_bytes().len() as u8);
        message_pack.extend(sign_param.path.as_bytes());
        //add preview (payment + to + fee)
        message_pack.push(0x07 as u8);
        message_pack.push(sign_param.payment.as_bytes().len() as u8);
        message_pack.extend(sign_param.payment.as_bytes());
        message_pack.push(0x08 as u8);
        message_pack.push(sign_param.receiver.as_bytes().len() as u8);
        message_pack.extend(sign_param.receiver.as_bytes());
        message_pack.push(0x09 as u8);
        message_pack.push(sign_param.fee.as_bytes().len() as u8);
        message_pack.extend(sign_param.fee.as_bytes());
        //bind private key sign
        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &message_pack).unwrap();
        //add signature
        let mut data_pack: Vec<u8> = vec![];
        data_pack.push(0x00 as u8);
        data_pack.push(bind_signature.len() as u8);
        data_pack.extend(bind_signature.iter());
        data_pack.extend(message_pack.iter());
        //build sign apdu
        let sign_apdus = Ed25519Apdu::sign(data_pack.as_slice());
        //select applet
        let select_apdu = Apdu::select_applet(TEZOS_AID);
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;
        //sign
        let mut sign_response = "".to_string();
        for apdu in sign_apdus {
            sign_response = send_apdu_timeout(apdu, TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }
        // verify
        let sign_data_len: usize = usize::from_str_radix(&sign_response[..2], 16).unwrap() * 2 + 2;
        let sign_source_val = &sign_response[..sign_data_len];
        let sign_result = &sign_response[sign_data_len..sign_response.len() - 4];
        let sign_verify_result = secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        //tezos ed25519 signature prefix
        let edsig_prefix: [u8; 5] = [9, 245, 205, 134, 18];
        let mut edsig_source_data = vec![];
        edsig_source_data.extend(&edsig_prefix);
        edsig_source_data.extend(hex::decode(sign_source_val[2..].to_string())?.iter());
        let tx_out = TezosTxOutput {
            signature: sign_source_val[2..].to_string(),
            edsig: base58::check_encode_slice(edsig_source_data.as_slice()),
            sbytes: format!("{}{}", tezos_tx_input.raw_data, sign_source_val),
        };

        Ok(tx_out)
    }

    fn address_check(address: &str) -> bool {
        let decode_result = base58::from(address);
        if decode_result.is_err() {
            return false;
        };

        let decode_data = decode_result.unwrap();
        let hash_res = sha256_hash(&sha256_hash(&decode_data[..decode_data.len() - 4]));
        for number in 0..4 {
            if hash_res[number] != decode_data[decode_data.len() - 4 + number] {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod test {
    // use crate::tezosapi::TezosTxInput;
    // use crate::transaction::Transaction;
    // use ikc_common::SignParam;
    // use ikc_device::device_binding::bind_test;
    // use ikc_transport::hid_api::hid_connect;

    // #[test]
    // fn tx_sign_test() {
    //     assert!(hid_connect("imKey Pro").is_ok());
    //     bind_test();
    //     let tezos_tx_input = TezosTxInput{
    //         to: "tz1QSHaKpTFhgHLbqinyYRjxD5sLcbfbzhxy".to_string(),
    //         from: "tz1d2TfcvWBwtPqo7f21DVv7HSSCoNAVp8gz".to_string(),
    //         value: "".to_string(),
    //         raw_data: "d3bdafa2e36f872e24f1ccd68dbdca4356b193823d0a6a54886d7641e532a2a26c00dedf1a2f428e5e85edf105cb3600949f3d0e8837c70cacb4e803e8528102c0843d0000dcdcf88d0cfb769e33b1888d6bdc351ee3277ea700".to_string()
    //     };

    //     let sign_param = SignParam {
    //         chain_type: "TEZOS".to_string(),
    //         path: "m/44'/1729'/0'/0'".to_string(),
    //         network: "MAINNET".to_string(),
    //         input: None,
    //         payment: "1 XTZ".to_string(),
    //         receiver: "tz1QSHaKpTFhgHLbqinyYRjxD5sLcbfbzhxy".to_string(),
    //         sender: "tz1d2TfcvWBwtPqo7f21DVv7HSSCoNAVp8gz".to_string(),
    //         fee: "0.1 XTZ".to_string(),
    //     };
    //     let sign_result = Transaction::sign_tx(tezos_tx_input, sign_param);
    //     if sign_result.is_ok() {
    //         let tezosTxOutput = sign_result.unwrap();
    //         assert_eq!("0DF020458BDCFE24546488DD81E1BD7E2CB05379DC7C72AD626646AE22DF5D3A652FDC4FFD2383DD5823A98FE158780928DA07A3F0A234E23B759CE7B3A39A0C", tezosTxOutput.signature);
    //         assert_eq!("edsigtZdXPNY5QEakVWmib9RGM6nzkix5TM4GyKjez9uT9VtBV1xPLAV17YK6pQwFk2cvQXZrpE22AaUYhLkVbTjN5uvk3RXyKn", tezosTxOutput.edsig);
    //         assert_eq!("d3bdafa2e36f872e24f1ccd68dbdca4356b193823d0a6a54886d7641e532a2a26c00dedf1a2f428e5e85edf105cb3600949f3d0e8837c70cacb4e803e8528102c0843d0000dcdcf88d0cfb769e33b1888d6bdc351ee3277ea700400DF020458BDCFE24546488DD81E1BD7E2CB05379DC7C72AD626646AE22DF5D3A652FDC4FFD2383DD5823A98FE158780928DA07A3F0A234E23B759CE7B3A39A0C", tezosTxOutput.sbytes);
    //     } else {
    //         panic!("sign error");
    //     }
    // }
}
