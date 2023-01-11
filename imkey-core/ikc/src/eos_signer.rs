use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_eos::eosapi::{EosMessageInput, EosMessageOutput, EosTxInput};
use coin_eos::transaction::EosTransaction;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_eos_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: EosTxInput = EosTxInput::decode(data).expect("imkey_illegal_param");

    let signed = EosTransaction::sign_tx(input, sign_param)?;
    encode_message(signed)
}

pub fn sign_eos_message(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: EosMessageInput =
        EosMessageInput::decode(data).expect("EosMessageInput unpack error");

    let signed = EosTransaction::sign_message(input, sign_param)?;
    let mes_sign_result = EosMessageOutput {
        signature: signed.signature,
    };
    encode_message(mes_sign_result)
}
