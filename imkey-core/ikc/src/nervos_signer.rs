use crate::error_handling::Result;
use crate::message_handler::encode_message;
use anyhow::anyhow;
use coin_ckb::signer::CkbSigner;
use coin_ckb::CkbTxInput;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: CkbTxInput = CkbTxInput::decode(data).map_err(|_| anyhow!("imkey_illegal_param"))?;
    let signed = CkbSigner::sign_transaction(&input, sign_param)?;
    encode_message(signed)
}
