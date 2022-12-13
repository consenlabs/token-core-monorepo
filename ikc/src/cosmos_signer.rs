use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_cosmos::cosmosapi::CosmosTxInput;
use coin_cosmos::transaction::CosmosTransaction;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_cosmos_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: CosmosTxInput = CosmosTxInput::decode(data)?;

    let cosmos_input = CosmosTransaction {
        sign_data: input.data,
        path: sign_param.path.to_string(),
        payment_dis: sign_param.payment.to_string(),
        to_dis: sign_param.receiver.to_string(),
        fee_dis: sign_param.fee.to_string(),
    };
    let cosmos_tx_output = cosmos_input.sign()?;

    encode_message(cosmos_tx_output)
}
