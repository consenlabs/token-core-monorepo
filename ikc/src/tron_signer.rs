use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_tron::signer::TronSigner;
use coin_tron::tronapi::{TronMessageInput, TronTxInput};
use ikc_common::SignParam;
use prost::Message;

pub fn sign_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: TronTxInput = TronTxInput::decode(data).expect("decode proto error");
    let signed = TronSigner::sign_transaction(input, sign_param)?;
    encode_message(signed)
}

pub fn sign_message(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: TronMessageInput = TronMessageInput::decode(data).expect("decode proto error");
    let signed = TronSigner::sign_message(input, sign_param)?;
    encode_message(signed)
}
