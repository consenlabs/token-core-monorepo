use crate::error_handling::Result;
use crate::message_handler::encode_message;
use anyhow::anyhow;
use coin_tron::signer::TronSigner;
use coin_tron::tronapi::{
    SignTxsInput, SignTxsItemOutput, SignTxsOutput, TronMessageInput, TronTxInput,
};
use ikc_common::path::check_path_validity;
use ikc_common::utility::sha256_hash;
use ikc_common::SignParam;
use prost::Message;

/// A hardware batch still performs one complete device signing flow per item.
pub const TRON_MAX_BATCH_SIZE: usize = 100;

fn transaction_hash(input: &TronTxInput) -> Result<String> {
    let raw_data =
        hex::decode(&input.raw_data).map_err(|err| anyhow!("invalid raw_data hex: {}", err))?;
    Ok(hex::encode(sha256_hash(&raw_data)))
}

pub fn sign_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: TronTxInput = TronTxInput::decode(data).expect("decode proto error");
    let signed = TronSigner::sign_transaction(input, sign_param)?;
    encode_message(signed)
}

pub fn sign_txs(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input = SignTxsInput::decode(data)
        .map_err(|err| anyhow!("invalid TRON batch protobuf: {}", err))?;

    if input.items.is_empty() {
        return Err(anyhow!("sign_txs batch is empty"));
    }
    if input.items.len() > TRON_MAX_BATCH_SIZE {
        return Err(anyhow!(
            "sign_txs batch exceeds max size of {}",
            TRON_MAX_BATCH_SIZE
        ));
    }

    // Resolve and validate every host-controlled field before selecting an
    // applet or sending an APDU. This guarantees a malformed later item
    // cannot trigger confirmations for earlier items.
    let mut preflight = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.iter().enumerate() {
        let tx = item
            .tx
            .as_ref()
            .ok_or_else(|| anyhow!("sign_txs failed at index {}: missing tx", index))?;
        if item.sender.is_empty() {
            return Err(anyhow!(
                "sign_txs failed at index {}: missing sender",
                index
            ));
        }

        let effective_path = if item.path.is_empty() {
            sign_param.path.clone()
        } else {
            item.path.clone()
        };
        if effective_path.is_empty() {
            return Err(anyhow!(
                "sign_txs failed at index {}: empty derivation path",
                index
            ));
        }
        check_path_validity(&effective_path)
            .map_err(|err| anyhow!("sign_txs failed at index {}: {}", index, err))?;
        let tx_hash = transaction_hash(tx)
            .map_err(|err| anyhow!("sign_txs failed at index {}: {}", index, err))?;
        preflight.push((effective_path, tx_hash));
    }

    let mut outputs = Vec::with_capacity(input.items.len());
    for (index, (item, (effective_path, tx_hash))) in
        input.items.iter().zip(preflight.into_iter()).enumerate()
    {
        let mut item_param = sign_param.clone();
        item_param.path = effective_path;
        item_param.payment = item.payment.clone();
        item_param.receiver = item.receiver.clone();
        item_param.sender = item.sender.clone();

        // Intentionally use the existing single-transaction signer. Applet
        // selection, xpub retrieval, sender verification, APDU signing and
        // physical confirmation therefore happen independently for each item.
        let signed = TronSigner::sign_transaction(item.tx.clone().unwrap(), &item_param)
            .map_err(|err| anyhow!("sign_txs failed at index {}: {}", index, err))?;
        outputs.push(SignTxsItemOutput {
            tx: Some(signed),
            from_address: item.sender.clone(),
            tx_hash,
        });
    }

    encode_message(SignTxsOutput { outputs })
}

pub fn sign_message(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: TronMessageInput = TronMessageInput::decode(data).expect("decode proto error");
    let signed = TronSigner::sign_message(input, sign_param)?;
    encode_message(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coin_tron::tronapi::SignTxsItem;

    const RAW_DATA: &str = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d";

    fn outer_param(path: &str) -> SignParam {
        SignParam {
            chain_type: "TRON".to_string(),
            path: path.to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: String::new(),
            receiver: String::new(),
            sender: String::new(),
            fee: String::new(),
            seg_wit: String::new(),
        }
    }

    fn item(raw_data: &str, sender: &str, path: &str) -> SignTxsItem {
        SignTxsItem {
            tx: Some(TronTxInput {
                raw_data: raw_data.to_string(),
            }),
            payment: "0.1 TRX".to_string(),
            receiver: "TDQqAkUUVYBuzaykLKCVwEeS3gFdM69jQo".to_string(),
            sender: sender.to_string(),
            path: path.to_string(),
        }
    }

    fn encode_batch(items: Vec<SignTxsItem>) -> Vec<u8> {
        SignTxsInput { items }.encode_to_vec()
    }

    #[test]
    fn rejects_empty_and_oversized_batches() {
        let param = outer_param("m/44'/195'/0'/0/0");
        let empty = sign_txs(&encode_batch(vec![]), &param).unwrap_err();
        assert_eq!(empty.to_string(), "sign_txs batch is empty");

        let oversized = vec![item(RAW_DATA, "sender", ""); TRON_MAX_BATCH_SIZE + 1];
        let error = sign_txs(&encode_batch(oversized), &param).unwrap_err();
        assert_eq!(error.to_string(), "sign_txs batch exceeds max size of 100");
    }

    #[test]
    fn rejects_all_static_errors_before_device_access() {
        let param = outer_param("m/44'/195'/0'/0/0");

        assert!(sign_txs(&[0xff], &param)
            .unwrap_err()
            .to_string()
            .contains("invalid TRON batch protobuf"));

        let missing_tx = SignTxsItem {
            tx: None,
            payment: String::new(),
            receiver: String::new(),
            sender: "sender".to_string(),
            path: String::new(),
        };
        assert!(sign_txs(&encode_batch(vec![missing_tx]), &param)
            .unwrap_err()
            .to_string()
            .contains("sign_txs failed at index 0: missing tx"));

        assert!(
            sign_txs(&encode_batch(vec![item(RAW_DATA, "", "")]), &param)
                .unwrap_err()
                .to_string()
                .contains("sign_txs failed at index 0: missing sender")
        );

        let indexed = sign_txs(
            &encode_batch(vec![
                item(RAW_DATA, "sender", ""),
                item("not-hex", "sender", ""),
            ]),
            &param,
        )
        .unwrap_err();
        assert!(indexed
            .to_string()
            .contains("sign_txs failed at index 1: invalid raw_data hex"));

        let empty_path_param = outer_param("");
        assert!(sign_txs(
            &encode_batch(vec![item(RAW_DATA, "sender", "")]),
            &empty_path_param
        )
        .unwrap_err()
        .to_string()
        .contains("sign_txs failed at index 0: empty derivation path"));

        assert!(sign_txs(
            &encode_batch(vec![item(RAW_DATA, "sender", "m/44'")]),
            &param
        )
        .unwrap_err()
        .to_string()
        .contains("sign_txs failed at index 0"));
    }
}
