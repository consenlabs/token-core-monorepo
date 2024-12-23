use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;
use coin_bitcoin::btcapi::{BtcMessageInput, BtcTxInput, BtcTxOutput};
use coin_bitcoin::message::MessageSinger;
use coin_bitcoin::transaction::{BtcTransaction, Utxo};
use ikc_common::path::get_account_path;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_btc_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: BtcTxInput = BtcTxInput::decode(data).expect("BtcTxInput");

    if input.protocol.to_uppercase() == "OMNI" {
        if input.seg_wit.to_uppercase() == "P2WPKH" {
            sign_usdt_segwit_transaction(&input, sign_param)
        } else {
            sign_usdt_transaction(&input, sign_param)
        }
    } else {
        btc_sign(&input, sign_param)
    }
}

pub fn btc_sign(param: &BtcTxInput, sign_param: &SignParam) -> Result<Vec<u8>> {
    let mut unspents = Vec::new();
    for utxo in &param.unspents {
        let new_utxo = Utxo {
            txhash: utxo.tx_hash.to_string(),
            vout: utxo.vout,
            amount: utxo.amount,
            address: utxo.address.to_string(),
            script_pubkey: utxo.script_pub_key.to_string(),
            derive_path: utxo.derived_path.to_uppercase(),
            sequence: utxo.sequence,
        };
        unspents.push(new_utxo);
    }

    let btc_tx = BtcTransaction {
        to: param.to.to_string(),
        amount: param.amount,
        unspents,
        fee: param.fee,
        chain_type: sign_param.chain_type.clone(),
    };

    let op_return = match &param.extra {
        Some(extra) => Some(extra.op_return.clone()),
        _ => None,
    };

    let signed = btc_tx.sign_transaction(
        &sign_param.network,
        &sign_param.path,
        param.change_address_index,
        op_return.as_deref(),
        &param.seg_wit,
    )?;
    let tx_sign_result = BtcTxOutput {
        signature: signed.signature,
        tx_hash: signed.tx_hash,
        wtx_hash: signed.wtx_id,
    };
    encode_message(tx_sign_result)
}

pub fn sign_usdt_transaction(input: &BtcTxInput, sign_param: &SignParam) -> Result<Vec<u8>> {
    let mut unspents = Vec::new();
    for utxo in &input.unspents {
        let new_utxo = Utxo {
            txhash: utxo.tx_hash.to_string(),
            vout: utxo.vout,
            amount: utxo.amount,
            address: utxo.address.to_string(),
            script_pubkey: utxo.script_pub_key.to_string(),
            derive_path: utxo.derived_path.to_string(),
            sequence: utxo.sequence,
        };
        unspents.push(new_utxo);
    }

    let btc_tx = BtcTransaction {
        to: input.to.to_string(),
        amount: input.amount,
        unspents: unspents,
        fee: input.fee,
        chain_type: sign_param.chain_type.clone(),
    };

    let network = if sign_param.network == "TESTNET".to_string() {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let extra = input
        .extra
        .clone()
        .expect("sign usdt tx must contains extra");

    let signed = btc_tx.sign_omni_transaction(network, &sign_param.path, extra.property_id)?;
    let tx_sign_result = BtcTxOutput {
        signature: signed.signature,
        tx_hash: signed.tx_hash,
        wtx_hash: "".to_string(),
    };
    encode_message(tx_sign_result)
}

pub fn sign_usdt_segwit_transaction(input: &BtcTxInput, sign_param: &SignParam) -> Result<Vec<u8>> {
    let mut unspents = Vec::new();
    for utxo in &input.unspents {
        let new_utxo = Utxo {
            txhash: utxo.tx_hash.to_string(),
            vout: utxo.vout,
            amount: utxo.amount,
            address: utxo.address.to_string(),
            script_pubkey: utxo.script_pub_key.to_string(),
            derive_path: utxo.derived_path.to_string(),
            sequence: utxo.sequence,
        };
        unspents.push(new_utxo);
    }

    let btc_tx = BtcTransaction {
        to: input.to.to_string(),
        amount: input.amount,
        unspents: unspents,
        fee: input.fee,
        chain_type: sign_param.chain_type.clone(),
    };

    let network = if sign_param.network == "TESTNET".to_string() {
        Network::Testnet
    } else {
        Network::Bitcoin
    };

    let extra = input
        .extra
        .clone()
        .expect("sign usdt tx must contains extra");

    let signed =
        btc_tx.sign_omni_segwit_transaction(network, &sign_param.path, extra.property_id as i32)?;
    let tx_sign_result = BtcTxOutput {
        signature: signed.signature,
        wtx_hash: signed.wtx_id,
        tx_hash: signed.tx_hash,
    };
    encode_message(tx_sign_result)
}

pub fn btc_sign_message(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: BtcMessageInput = BtcMessageInput::decode(data).expect("imkey_illegal_param");
    let derivation_path = get_account_path(&sign_param.path)?;
    let singer = MessageSinger {
        derivation_path,
        chain_type: sign_param.chain_type.clone(),
        network: sign_param.network.clone(),
        seg_wit: sign_param.seg_wit.clone(),
    };
    let signed = singer.sign_message(input)?;
    encode_message(signed)
}
