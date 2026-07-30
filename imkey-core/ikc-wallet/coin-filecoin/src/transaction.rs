use crate::address::FilecoinAddress;
use crate::filecoinapi::{FilecoinTxInput, FilecoinTxOutput, Signature};
use crate::utils::{digest, HashSize};
use crate::Result;

use ikc_common::apdu::{ApduCheck, Secp256k1Apdu};
use ikc_common::error::CoinError;
use ikc_common::utility::{hex_to_bytes, secp256k1_sign};
use ikc_common::{constants, path, utility, SignParam};
use ikc_device::async_device_manager::AsyncApduTransport;
use ikc_device::device_binding::KEY_MANAGER;

use anyhow::anyhow;
use forest_address::Address;
use forest_cid::{self, Cid, Code};
use forest_encoding::{ser, serde_bytes, to_vec};
use forest_vm::{Serialized, TokenAmount};
use ikc_transport::message::send_apdu_timeout;
use num_bigint_chainsafe::bigint_ser::BigIntSer;
use secp256k1::ecdsa::Signature as SecpSignature;
use std::str::FromStr;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {}

struct FilecoinUnsignedMessage {
    version: i64,
    from: Address,
    to: Address,
    sequence: u64,
    value: TokenAmount,
    method_num: u64,
    params: Serialized,
    gas_limit: i64,
    gas_fee_cap: TokenAmount,
    gas_premium: TokenAmount,
}

impl ser::Serialize for FilecoinUnsignedMessage {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ser::Serialize::serialize(
            &(
                &self.version,
                &self.to,
                &self.from,
                &self.sequence,
                BigIntSer(&self.value),
                &self.gas_limit,
                BigIntSer(&self.gas_fee_cap),
                BigIntSer(&self.gas_premium),
                &self.method_num,
                &self.params,
            ),
            serializer,
        )
    }
}

struct Secp256k1SignedMessage<'a> {
    message: &'a FilecoinUnsignedMessage,
    signature: Secp256k1Signature<'a>,
}

impl ser::Serialize for Secp256k1SignedMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ser::Serialize::serialize(&(&self.message, &self.signature), serializer)
    }
}

struct Secp256k1Signature<'a>(&'a [u8]);

impl ser::Serialize for Secp256k1Signature<'_> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut bytes = Vec::with_capacity(self.0.len() + 1);
        bytes.push(1);
        bytes.extend_from_slice(self.0);
        serde_bytes::Serialize::serialize(&bytes, serializer)
    }
}

fn secp256k1_signed_message_cid(
    message: &FilecoinUnsignedMessage,
    signature: &[u8],
) -> core::result::Result<Cid, forest_encoding::Error> {
    let signed_message = Secp256k1SignedMessage {
        message,
        signature: Secp256k1Signature(signature),
    };
    Ok(forest_cid::new_from_cbor(
        &to_vec(&signed_message)?,
        Code::Blake2b256,
    ))
}

fn unsigned_message_cid(
    message: &FilecoinUnsignedMessage,
) -> core::result::Result<Cid, forest_encoding::Error> {
    Ok(forest_cid::new_from_cbor(
        &to_vec(message)?,
        Code::Blake2b256,
    ))
}

impl Transaction {
    fn convert_message(message: &FilecoinTxInput) -> Result<FilecoinUnsignedMessage> {
        let to = Address::from_str(&message.to).map_err(|_| CoinError::InvalidAddress)?;
        let from = Address::from_str(&message.from).map_err(|_| CoinError::InvalidAddress)?;
        let value = TokenAmount::from_str(&message.value).map_err(|_| CoinError::InvalidNumber)?;
        let gas_limit = message.gas_limit;
        let gas_fee_cap =
            TokenAmount::from_str(&message.gas_fee_cap).map_err(|_| CoinError::InvalidNumber)?;
        let gas_premium =
            TokenAmount::from_str(&message.gas_premium).map_err(|_| CoinError::InvalidNumber)?;

        let message_params_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &message.params)
                .map_err(|_| CoinError::InvalidParam)?;
        let params = Serialized::new(message_params_bytes);

        Ok(FilecoinUnsignedMessage {
            version: 0,
            to,
            from,
            sequence: message.nonce,
            value,
            method_num: message.method,
            params,
            gas_limit,
            gas_premium,
            gas_fee_cap,
        })
    }

    fn prepare_signing_payload(
        message: &FilecoinUnsignedMessage,
        sign_param: &SignParam,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let cid = unsigned_message_cid(message)?;
        let data = digest(&cid.to_bytes(), HashSize::Default);
        let mut data_pack = Vec::new();
        data_pack.extend([1, data.len() as u8]);
        data_pack.extend(&data);
        data_pack.extend([2, sign_param.path.len() as u8]);
        data_pack.extend(sign_param.path.as_bytes());
        data_pack.extend([7, sign_param.payment.len() as u8]);
        data_pack.extend(sign_param.payment.as_bytes());
        data_pack.extend([8, sign_param.receiver.len() as u8]);
        data_pack.extend(sign_param.receiver.as_bytes());
        data_pack.extend([9, sign_param.fee.len() as u8]);
        data_pack.extend(sign_param.fee.as_bytes());

        let (bind_signature, se_pub_key) = {
            let key_manager = KEY_MANAGER.lock();
            (
                secp256k1_sign(&key_manager.pri_key, &data_pack)?,
                key_manager.se_pub_key.clone(),
            )
        };
        let mut apdu_pack = Vec::new();
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(&bind_signature);
        apdu_pack.extend(&data_pack);
        Ok((data, apdu_pack, se_pub_key))
    }

    fn finish_signing(
        tx_input: FilecoinTxInput,
        message: &FilecoinUnsignedMessage,
        data: &[u8],
        pubkey_raw: &[u8],
        se_pub_key: &[u8],
        sign_response: &str,
    ) -> Result<FilecoinTxOutput> {
        let payload_end = sign_response
            .len()
            .checked_sub(4)
            .ok_or_else(|| anyhow!("invalid_param"))?;
        let sign_source_val = sign_response
            .get(..132)
            .ok_or_else(|| anyhow!("invalid_param"))?;
        let sign_result = sign_response
            .get(132..payload_end)
            .ok_or_else(|| anyhow!("invalid_param"))?;
        if !utility::secp256k1_sign_verify(
            se_pub_key,
            &hex::decode(sign_result)?,
            &hex::decode(sign_source_val)?,
        )? {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let sign_compact = sign_response
            .get(2..130)
            .ok_or_else(|| anyhow!("invalid_param"))?;
        let mut signature_obj = SecpSignature::from_compact(&hex_to_bytes(sign_compact)?)?;
        signature_obj.normalize_s();
        let normalized_signature = signature_obj.serialize_compact();
        let rec_id = utility::retrieve_recid(data, &normalized_signature, pubkey_raw)?;
        let mut signature = [0; 65];
        signature[..64].copy_from_slice(&normalized_signature);
        signature[64] = i32::from(rec_id) as u8;
        let cid = secp256k1_signed_message_cid(message, &signature)
            .map_err(|_| anyhow!("forest_message cid error"))?;

        Ok(FilecoinTxOutput {
            cid: cid.to_string(),
            message: Some(tx_input),
            signature: Some(Signature {
                r#type: 1,
                data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature),
            }),
        })
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
        let pubkey_raw = hex_to_bytes(
            res_msg_pubkey
                .get(..130)
                .ok_or_else(|| anyhow!("invalid_param"))?,
        )?;

        let (data, apdu_pack, se_pub_key) =
            Self::prepare_signing_payload(&unsigned_message, sign_param)?;

        //sign
        let mut sign_response = "".to_string();
        let sign_apdus = Secp256k1Apdu::sign(&apdu_pack);
        for apdu in sign_apdus {
            sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }

        Self::finish_signing(
            tx_input,
            &unsigned_message,
            &data,
            &pubkey_raw,
            &se_pub_key,
            &sign_response,
        )
    }

    pub async fn sign_tx_async<T>(
        transport: &T,
        tx_input: FilecoinTxInput,
        sign_param: &SignParam,
    ) -> Result<FilecoinTxOutput>
    where
        T: AsyncApduTransport + ?Sized,
    {
        path::check_path_validity(&sign_param.path)?;

        let unsigned_message = Self::convert_message(&tx_input)?;
        let address = FilecoinAddress::get_address_async(
            transport,
            sign_param.path.as_str(),
            sign_param.network.as_str(),
        )
        .await?;
        if address != sign_param.sender {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }

        let res_msg_pubkey =
            FilecoinAddress::get_pub_key_async(transport, sign_param.path.as_str()).await?;
        let pubkey_raw = hex_to_bytes(
            res_msg_pubkey
                .get(..130)
                .ok_or_else(|| anyhow!("invalid_param"))?,
        )?;

        let (data, apdu_pack, se_pub_key) =
            Self::prepare_signing_payload(&unsigned_message, sign_param)?;

        let mut sign_response = String::new();
        for apdu in Secp256k1Apdu::sign(&apdu_pack) {
            sign_response = transport.send_apdu(&apdu, constants::TIMEOUT_LONG).await?;
            ApduCheck::check_response(&sign_response)?;
        }

        Self::finish_signing(
            tx_input,
            &unsigned_message,
            &data,
            &pubkey_raw,
            &se_pub_key,
            &sign_response,
        )
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
            seg_wit: "".to_string(),
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
