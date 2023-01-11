use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_filecoin::filecoinapi::FilecoinTxInput;
use coin_filecoin::transaction::Transaction;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_filecoin_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: FilecoinTxInput = FilecoinTxInput::decode(data).unwrap();
    let signed = Transaction::sign_tx(input, sign_param)?;
    encode_message(signed)
}
