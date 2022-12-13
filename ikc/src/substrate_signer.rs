use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_substrate::substrateapi::SubstrateRawTxIn;
use coin_substrate::transaction::Transaction;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: SubstrateRawTxIn = SubstrateRawTxIn::decode(data).expect("decode proto error");
    let signed = Transaction::sign_transaction(&input, sign_param)?;
    encode_message(signed)
}
