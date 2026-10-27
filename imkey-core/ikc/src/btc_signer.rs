use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;
use coin_bitcoin::btcapi::{BtcMessageInput, BtcTxInput, BtcTxOutput};
use coin_bitcoin::message::MessageSinger;
use coin_bitcoin::transaction::{BtcTransaction, Utxo};
use ikc_common::path::{get_account_path, resolve_derivation_path};
use ikc_common::SignParam;
use prost::Message;

pub fn sign_btc_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: BtcTxInput = BtcTxInput::decode(data)?;

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
            derive_path: resolve_derivation_path(&sign_param.path, &utxo.derived_path)?,
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
            derive_path: resolve_derivation_path(&sign_param.path, &utxo.derived_path)?,
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
            derive_path: resolve_derivation_path(&sign_param.path, &utxo.derived_path)?,
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

#[cfg(test)]
mod security_message_tests {
    use super::*;
    #[test]
    fn security_btc_message_wrapper_rejects_before_device_access() {
        let input = BtcMessageInput {
            message: "hello world".to_string(),
            signature_type: coin_bitcoin::btcapi::BtcSignatureType::Standard as i32,
        };
        let bytes = input.encode_to_vec();
        for path in [
            "",
            "m",
            "m/44'/60'/0'",
            "m/44/0'/0'",
            "m/44'/0/0'",
            "m/44'/0'/0",
        ] {
            let params = SignParam {
                chain_type: "BITCOIN".to_string(),
                path: path.to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                ..Default::default()
            };
            assert!(btc_sign_message(&bytes, &params).is_err());
        }
    }
}
