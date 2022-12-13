use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_ckb::signer::CkbSigner;
use coin_ckb::CkbTxInput;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: CkbTxInput = CkbTxInput::decode(data).unwrap();
    let signed = CkbSigner::sign_transaction(&input, sign_param)?;
    encode_message(signed)
}
