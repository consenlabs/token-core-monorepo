use crate::address::BtcForkAddress;
use crate::btcforkapi::Utxo;
use crate::Result;
use bitcoin::util::base58;
use bitcoin::util::bip32::{ChainCode, ChildNumber, ExtendedPubKey};
use bitcoin::Network;
use bitcoin::{Address, PublicKey};
use ikc_common::apdu::{ApduCheck, BtcApdu, CoinCommonApdu};
use ikc_common::error::CoinError;
use ikc_common::utility::{hex_to_bytes, sha256_hash};
use ikc_transport::message::send_apdu;
use secp256k1::{ecdsa::Signature, Message, PublicKey as Secp256k1PublicKey, Secp256k1};
use std::convert::TryFrom;
use std::str::FromStr;

/**
utxo address verify
*/
pub fn address_verify(
    utxos: &Vec<Utxo>,
    public_key: &str,
    chain_code: &[u8],
    network: Network,
    trans_type_flg: TransTypeFlg,
) -> Result<Vec<String>> {
    let mut utxo_pub_key_vec: Vec<String> = vec![];
    for utxo in utxos {
        let extend_public_key = if !utxo.derived_path.is_empty() {
            let xpub_data = get_xpub_data(&utxo.derived_path, true)?;
            let public_key = public_key_from_xpub_response(&xpub_data)?;
            let chain_code = chain_code_from_xpub_response(&xpub_data)?;
            ExtendedPubKey {
                network,
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: ChildNumber::from_normal_idx(0)?,
                public_key: Secp256k1PublicKey::from_str(public_key)?,
                chain_code: ChainCode::from(hex_to_bytes(chain_code)?.as_slice()),
            }
        } else {
            let public_key_obj = Secp256k1PublicKey::from_str(public_key)?;
            let chain_code_obj = ChainCode::try_from(chain_code)?;
            ExtendedPubKey {
                network,
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: ChildNumber::from_normal_idx(0)?,
                public_key: public_key_obj,
                chain_code: chain_code_obj,
            }
        };

        let se_gen_address = match trans_type_flg {
            TransTypeFlg::BTC => Address::p2pkh(
                &PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?,
                network,
            ),
            TransTypeFlg::SEGWIT => Address::p2shwpkh(
                &PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?,
                network,
            )?,
        };

        let se_script = se_gen_address.script_pubkey();
        let utxo_address = BtcForkAddress::from_str(&utxo.address)?;
        let utxo_script = utxo_address.payload.script_pubkey();

        if se_script != utxo_script {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }
        utxo_pub_key_vec.push(extend_public_key.public_key.to_string());
    }
    Ok(utxo_pub_key_vec)
}

/**
Transaction type identification
*/
pub enum TransTypeFlg {
    BTC,
    SEGWIT,
}

/**
get xpub
*/
pub fn get_xpub_data(path: &str, verify_flag: bool) -> Result<String> {
    let select_response = send_apdu(BtcApdu::select_applet())?;
    ApduCheck::check_response(&select_response)?;
    let xpub_data = send_apdu(BtcApdu::get_xpub(path, verify_flag))?;
    ApduCheck::check_response(&xpub_data)?;
    if verify_flag {
        let se_pubkey = ikc_device::device_binding::KEY_MANAGER
            .lock()
            .se_pub_key
            .clone();
        verify_xpub_response(&xpub_data, &se_pubkey)?;
    }
    Ok(xpub_data)
}

/**
sign verify
*/
pub fn secp256k1_sign_verify(public: &[u8], signed: &[u8], message: &[u8]) -> Result<bool> {
    let secp = Secp256k1::new();
    //build public
    let public_obj = Secp256k1PublicKey::from_slice(public)?;
    //build message
    let hash_result = sha256_hash(message);
    let message_obj = Message::from_slice(hash_result.as_ref())?;
    //build signature obj
    let mut sig_obj = Signature::from_der(signed)?;
    sig_obj.normalize_s();
    //verify
    Ok(secp
        .verify_ecdsa(&message_obj, &sig_obj, &public_obj)
        .is_ok())
}

/**
get address version
*/
pub fn get_address_version(_network: Network, address: &str) -> Result<u8> {
    let address_bytes = base58::from(address)?;
    Ok(address_bytes.as_slice()[0])
}

pub struct TxSignResult {
    pub signature: String,
    pub tx_hash: String,
    pub wtx_id: String,
}

pub fn public_key_from_xpub_response(xpub_data: &str) -> Result<&str> {
    xpub_data
        .get(..130)
        .ok_or_else(|| CoinError::GetXpubError.into())
}

pub fn chain_code_from_xpub_response(xpub_data: &str) -> Result<&str> {
    xpub_data
        .get(130..194)
        .ok_or_else(|| CoinError::GetXpubError.into())
}

pub(crate) fn verify_xpub_response(response: &str, se_pubkey: &[u8]) -> Result<()> {
    let checked = || -> Result<bool> {
        let end = response
            .len()
            .checked_sub(4)
            .ok_or(CoinError::GetXpubError)?;
        let source = response.get(..194).ok_or(CoinError::GetXpubError)?;
        let signature = response.get(194..end).ok_or(CoinError::GetXpubError)?;
        secp256k1_sign_verify(se_pubkey, &hex::decode(signature)?, &hex::decode(source)?)
    };
    if checked().unwrap_or(false) {
        Ok(())
    } else {
        Err(CoinError::ImkeySignatureVerifyFail.into())
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    #[test]
    fn security_xpub_requires_valid_se_signature() {
        let secp = Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[9; 32]).unwrap();
        let trusted = Secp256k1PublicKey::from_secret_key(&secp, &secret);
        let public = Secp256k1PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[1; 32]).unwrap(),
        );
        let mut source = public.serialize_uncompressed().to_vec();
        source.extend([0u8; 32]);
        let digest = sha256_hash(&source);
        let signature = secp
            .sign_ecdsa(&Message::from_slice(&digest).unwrap(), &secret)
            .serialize_der();
        let response = format!("{}{}9000", hex::encode(&source), hex::encode(signature));
        assert!(verify_xpub_response(&response, &trusted.serialize()).is_ok());
        assert!(verify_xpub_response(
            &format!("{}9000", hex::encode(&source)),
            &trusted.serialize()
        )
        .is_err());
        let mut forged = source.clone();
        forged[65] ^= 1;
        assert!(verify_xpub_response(
            &format!("{}{}9000", hex::encode(forged), hex::encode(signature)),
            &trusted.serialize()
        )
        .is_err());
        for short in ["", "9000", "049000", "invalid9000"] {
            assert!(verify_xpub_response(short, &trusted.serialize()).is_err());
        }
    }
}
