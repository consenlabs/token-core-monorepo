use crate::address::BtcForkAddress;
use crate::btcforkapi::Utxo;
use crate::Result;
use bitcoin::secp256k1::Secp256k1 as BitcoinSecp256k1;
use bitcoin::util::base58;
use bitcoin::util::bip32::{ChainCode, ChildNumber, ExtendedPubKey};
use bitcoin::Network;
use bitcoin::{Address, PublicKey};
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::sha256d::Hash as Hash256;
use bitcoin_hashes::Hash;
use ikc_common::apdu::{ApduCheck, BtcApdu, CoinCommonApdu};
use ikc_common::error::CoinError;
use ikc_common::utility::sha256_hash;
use ikc_transport::message::send_apdu;
use secp256k1::{Message, PublicKey as Secp256k1PublicKey, Secp256k1, Signature};
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
        //get utxo public key
        let public_key_obj = Secp256k1PublicKey::from_str(public_key)?;

        //gen chain code obj
        let chain_code_obj = ChainCode::try_from(chain_code)?;
        //build extended public key
        let mut extend_public_key = ExtendedPubKey {
            network: network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            public_key: public_key_obj,
            chain_code: chain_code_obj,
        };

        let bitcoin_secp = BitcoinSecp256k1::new();
        if !utxo.derived_path.is_empty() {
            let index_number_vec: Vec<&str> = utxo.derived_path.as_str().split('/').collect();
            for index_number in index_number_vec {
                let test_chain_number =
                    ChildNumber::from_normal_idx(index_number.parse().unwrap())?;
                extend_public_key = extend_public_key.ckd_pub(&bitcoin_secp, test_chain_number)?;
            }
        }

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
        let utxo_address = BtcForkAddress::from_str(&utxo.address).unwrap();
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
    Ok(secp.verify(&message_obj, &sig_obj, &public_obj).is_ok())
}

/**
get address version
*/
pub fn get_address_version(network: Network, address: &str) -> Result<u8> {
    let address_bytes = base58::from(address)?;
    Ok(address_bytes.as_slice()[0])
}

pub struct TxSignResult {
    pub signature: String,
    pub tx_hash: String,
    pub wtx_id: String,
}
