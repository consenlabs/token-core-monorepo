use crate::address::BtcForkAddress;
use crate::btcforkapi::Utxo;
use crate::Result;
use bitcoin::base58;
use bitcoin::bip32::{ChainCode, ChildNumber, Xpub};
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey as Secp256k1PublicKey, Secp256k1};
use bitcoin::Network;
use bitcoin::{Address, PublicKey, ScriptBuf};
use ikc_common::apdu::{ApduCheck, BtcApdu, CoinCommonApdu};
use ikc_common::error::CoinError;
use ikc_common::utility::{hex_to_bytes, sha256_hash};
use ikc_transport::message::send_apdu;
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
            let xpub_data = get_xpub_data(&utxo.derived_path, false)?;
            let public_key = &xpub_data[..130];
            let chain_code = &xpub_data[130..194];
            Xpub {
                network: network.into(),
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: ChildNumber::from_normal_idx(0)?,
                public_key: Secp256k1PublicKey::from_str(public_key)?,
                chain_code: ChainCode::try_from(hex_to_bytes(chain_code)?.as_slice())?,
            }
        } else {
            let public_key_obj = Secp256k1PublicKey::from_str(public_key)?;
            let chain_code_obj = ChainCode::try_from(chain_code)?;
            Xpub {
                network: network.into(),
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: ChildNumber::from_normal_idx(0)?,
                public_key: public_key_obj,
                chain_code: chain_code_obj,
            }
        };

        let public_key = PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?;
        let se_script = match trans_type_flg {
            TransTypeFlg::BTC => Address::p2pkh(&public_key, network).script_pubkey(),
            TransTypeFlg::SEGWIT => {
                let witness_script = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?);
                ScriptBuf::new_p2sh(&witness_script.script_hash())
            }
        };

        let utxo_address = BtcForkAddress::from_str(&utxo.address).unwrap();
        let utxo_script = utxo_address.script_pubkey();

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
    let message_obj = Message::from_digest_slice(hash_result.as_ref())?;
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
    let address_bytes = base58::decode(address)?;
    Ok(address_bytes.as_slice()[0])
}

pub struct TxSignResult {
    pub signature: String,
    pub tx_hash: String,
    pub wtx_id: String,
}
