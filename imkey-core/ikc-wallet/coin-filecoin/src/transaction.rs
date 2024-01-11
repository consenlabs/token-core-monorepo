use crate::address::FilecoinAddress;
use crate::filecoinapi::{FilecoinTxInput, FilecoinTxOutput, Signature};
use crate::utils::{digest, HashSize};
use crate::Result;

use ikc_common::apdu::{ApduCheck, Secp256k1Apdu};
use ikc_common::error::CoinError;
use ikc_common::utility::{hex_to_bytes, secp256k1_sign};
use ikc_common::{constants, path, utility, SignParam};
use ikc_device::device_binding::KEY_MANAGER;

use forest_address::Address;
use forest_cid::Cid;
use forest_encoding::Cbor;
use forest_message::UnsignedMessage as ForestUnsignedMessage;
use forest_vm::{Serialized, TokenAmount};
use ikc_transport::message::send_apdu_timeout;
use secp256k1::ecdsa::Signature as SecpSignature;
use std::str::FromStr;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {}

impl Transaction {
    fn convert_message(message: &FilecoinTxInput) -> Result<ForestUnsignedMessage> {
        let to = Address::from_str(&message.to).map_err(|_| CoinError::InvalidAddress)?;
        let from = Address::from_str(&message.from).map_err(|_| CoinError::InvalidAddress)?;
        let value = TokenAmount::from_str(&message.value).map_err(|_| CoinError::InvalidNumber)?;
        let gas_limit = message.gas_limit;
        let gas_fee_cap =
            TokenAmount::from_str(&message.gas_fee_cap).map_err(|_| CoinError::InvalidNumber)?;
        let gas_premium =
            TokenAmount::from_str(&message.gas_premium).map_err(|_| CoinError::InvalidNumber)?;

        let message_params_bytes =
            base64::decode(&message.params).map_err(|_| CoinError::InvalidParam)?;
        let params = Serialized::new(message_params_bytes);

        let tmp = ForestUnsignedMessage::builder()
            .to(to)
            .from(from)
            .sequence(message.nonce)
            .value(value)
            .method_num(message.method)
            .params(params)
            .gas_limit(gas_limit)
            .gas_premium(gas_premium)
            .gas_fee_cap(gas_fee_cap)
            .build()
            .map_err(|_| CoinError::InvalidFormat)?;

        Ok(tmp)
    }

    pub fn sign_tx(tx_input: FilecoinTxInput, sign_param: &SignParam) -> Result<FilecoinTxOutput> {
        path::check_path_validity(&sign_param.path)?;

        // let tx = tx_input.message.unwrap();
        let unsigned_message = Self::convert_message(&tx_input)?;

        //check address
        let address =
            FilecoinAddress::get_address(sign_param.path.as_str(), sign_param.network.as_str())?;

        //compare address
        if address != sign_param.sender {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }

        // get public key
        let res_msg_pubkey = FilecoinAddress::get_pub_key(sign_param.path.as_str())?;
        let pubkey_raw = hex_to_bytes(&res_msg_pubkey[..130]).unwrap();

        let mut cid: Cid = unsigned_message.cid()?;
        let data = &digest(&cid.to_bytes(), HashSize::Default);

        //organize data
        let mut data_pack: Vec<u8> = Vec::new();

        data_pack.extend([1, data.len() as u8].iter());
        data_pack.extend(data.iter());

        //path
        data_pack.extend([2, sign_param.path.as_bytes().len() as u8].iter());
        data_pack.extend(sign_param.path.as_bytes().iter());
        //payment info in TLV format
        data_pack.extend([7, sign_param.payment.as_bytes().len() as u8].iter());
        data_pack.extend(sign_param.payment.as_bytes().iter());
        //receiver info in TLV format
        data_pack.extend([8, sign_param.receiver.as_bytes().len() as u8].iter());
        data_pack.extend(sign_param.receiver.as_bytes().iter());
        //fee info in TLV format
        data_pack.extend([9, sign_param.fee.as_bytes().len() as u8].iter());
        data_pack.extend(sign_param.fee.as_bytes().iter());

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &data_pack).unwrap();

        let mut apdu_pack: Vec<u8> = Vec::new();
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.extend(data_pack.as_slice());

        //sign
        let mut sign_response = "".to_string();
        let sign_apdus = Secp256k1Apdu::sign(&apdu_pack);
        for apdu in sign_apdus {
            sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }

        // verify
        let sign_source_val = &sign_response[..132];
        let sign_result = &sign_response[132..sign_response.len() - 4];
        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;

        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let sign_compact = &sign_response[2..130];
        let sign_compact_vec = hex_to_bytes(sign_compact).unwrap();

        let mut signature_obj = SecpSignature::from_compact(sign_compact_vec.as_slice()).unwrap();
        signature_obj.normalize_s();
        let normalizes_sig_vec = signature_obj.serialize_compact();

        let rec_id = utility::retrieve_recid(&data, &normalizes_sig_vec, &pubkey_raw).unwrap();

        let mut data_arr = [0; 65];
        data_arr[0..64].copy_from_slice(&normalizes_sig_vec[0..64]);
        data_arr[64] = rec_id.to_i32() as u8;

        let forest_sig = forest_crypto::Signature::new_secp256k1(data_arr.to_vec());
        let forest_signed_msg = forest_message::SignedMessage {
            message: unsigned_message,
            signature: forest_sig,
        };
        cid = forest_signed_msg
            .cid()
            .map_err(|_e| format_err!("{}", "forest_message cid error"))?;

        let signature_type = 1;

        Ok(FilecoinTxOutput {
            cid: cid.to_string(),
            message: Some(tx_input.clone()),
            signature: Some(Signature {
                r#type: signature_type,
                data: base64::encode(&data_arr.to_vec()),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_sign_trans() {
        bind_test();
        let tx_input = FilecoinTxInput {
            to: "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
            from: "f1o2ph66tg7o7obyrqa7eiwiinrltauzxitkuk4ay".to_string(),
            nonce: 1,
            value: "100000".to_string(),
            gas_limit: 1,
            gas_fee_cap: "1".to_string(),
            gas_premium: "1".to_string(),
            method: 0,
            params: "".to_string(),
        };

        let sign_param = SignParam {
            chain_type: "FILECOIN".to_string(),
            path: "m/44'/461'/0/0/0".to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: "1 FILECOIN".to_string(),
            receiver: "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
            sender: "f1o2ph66tg7o7obyrqa7eiwiinrltauzxitkuk4ay".to_string(),
            fee: "0.1 FILECOIN".to_string(),
        };

        let tx_result = Transaction::sign_tx(tx_input, &sign_param).unwrap();
        let signature = tx_result.signature.unwrap();

        assert_eq!(
            "bafy2bzaceawarox6h5my5vk2gqe5v3qzzcsccoet4a5mrtg6xw7haeg7rd5ce",
            tx_result.cid
        );
        assert_eq!(signature.r#type, 1);
        assert_eq!(signature.data, "k/ODPDElcw/xCQ0WWO3r7H3GoKpJVX7j6x1lyNFZ4YNvoWx8/RVqn0/+GNUvFCj1EOEXKFNf2h5LsBmiHDllkgE=");
    }
}
