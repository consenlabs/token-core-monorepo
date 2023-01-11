use crate::api::eos_wallet::PubKeyInfo;
use crate::api::{EosWallet, PubKeyParam, PubKeyResult};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_eos::pubkey::EosPubkey;
use prost::Message;

pub fn display_eos_pubkey(param: &PubKeyParam) -> Result<Vec<u8>> {
    let eos_pubkey = EosPubkey::display_pubkey(&param.path)?;
    let pub_key_info = PubKeyInfo {
        path: param.path.to_string(),
        derived_mode: "PATH_DIRECTLY".to_string(),
        public_key: eos_pubkey,
    };
    let eos_wallet = EosWallet {
        chain_type: param.chain_type.to_string(),
        address: "".to_string(),
        public_keys: vec![pub_key_info],
    };
    encode_message(eos_wallet)
}

pub fn get_eos_pubkey(param: &PubKeyParam) -> Result<Vec<u8>> {
    let eos_pubkey = EosPubkey::get_pubkey(&param.path)?;
    let pub_key_info = PubKeyInfo {
        path: param.path.to_string(),
        derived_mode: "PATH_DIRECTLY".to_string(),
        public_key: eos_pubkey,
    };
    let eos_wallet = EosWallet {
        chain_type: param.chain_type.to_string(),
        address: "".to_string(),
        public_keys: vec![pub_key_info],
    };
    encode_message(eos_wallet)
}
