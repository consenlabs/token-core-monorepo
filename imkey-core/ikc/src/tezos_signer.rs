use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_tezos::tezosapi::TezosTxInput;
use coin_tezos::transaction::Transaction;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_tezos_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input = TezosTxInput::decode(data).unwrap();
    let signed = Transaction::sign_tx(input, sign_param)?;
    encode_message(signed)
}
