use crate::Result;
use anyhow::anyhow;
use bitcoin::consensus::serialize;
use bitcoin::{OutPoint, Sequence, Transaction, TxOut, Witness};
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::constants::LC_MAX;
use ikc_common::utility::secp256k1_sign;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::send_apdu;

pub(crate) const TRANSACTION_CHUNK_BYTES: usize = 160;
const MAX_PREVIOUS_TRANSACTION_BYTES: usize = 1_000_000;
pub(crate) type InputReceipt = [u8; 32];

pub(crate) fn check_previous_output(
    previous_tx: &Transaction,
    outpoint: OutPoint,
    input_index: usize,
) -> Result<&TxOut> {
    if previous_tx.input.is_empty() || previous_tx.txid() != outpoint.txid {
        return Err(anyhow!(
            "btc_previous_transaction_txid_mismatch: input {}",
            input_index
        ));
    }
    let stripped_size = previous_tx.strippedsize();
    if stripped_size > MAX_PREVIOUS_TRANSACTION_BYTES {
        return Err(anyhow!(
            "btc_previous_transaction_exceeds_size_limit: input {}",
            input_index
        ));
    }
    previous_tx
        .output
        .get(outpoint.vout as usize)
        .ok_or_else(|| {
            anyhow!(
                "btc_previous_transaction_vout_not_found: input {}",
                input_index
            )
        })
}

pub(crate) fn authenticated_transaction_chunk(
    ins: u8,
    p1: u8,
    p2: u8,
    fragment: &[u8],
    key: &[u8],
) -> Result<String> {
    let mut raw_tlv = vec![0x01, (fragment.len() + 2) as u8, p1, p2];
    raw_tlv.extend_from_slice(fragment);
    let signature = secp256k1_sign(key, &raw_tlv)?;
    let mut data = vec![0x00, signature.len() as u8];
    data.extend(signature);
    data.extend(raw_tlv);
    BtcApdu::btc_authenticated_transaction_chunk(ins, p1, p2, &data)
}

pub(crate) fn send_input_proof(
    input_count: usize,
    input_index: usize,
    outpoint: OutPoint,
    sequence: Sequence,
    previous_tx: &Transaction,
) -> Result<InputReceipt> {
    let mut without_witness = previous_tx.clone();
    for input in &mut without_witness.input {
        input.witness = Witness::default();
    }
    let mut body = vec![input_count as u8, input_index as u8];
    body.extend(serialize(&outpoint));
    body.extend(serialize(&sequence));
    body.extend(serialize(&without_witness));

    let chunks = body.chunks(TRANSACTION_CHUNK_BYTES);
    let last = chunks.len() - 1;
    let key_manager = KEY_MANAGER.lock();
    let mut receipt = [0; 32];
    for (index, fragment) in chunks.enumerate() {
        let p1 = if index == 0 { 0 } else { 0x80 };
        let p2 = if index == last { 0x80 } else { 0 };
        let apdu = authenticated_transaction_chunk(0x53, p1, p2, fragment, &key_manager.pri_key)?;
        let response = send_apdu(apdu)?;
        if response.len() < 4 || !response.is_ascii() {
            return Err(anyhow!(
                "btc_input_proof_invalid_response: input {}",
                input_index
            ));
        }
        ApduCheck::check_response(&response)?;
        let payload = &response[..response.len() - 4];
        if index == last {
            if payload.is_empty() {
                return Err(anyhow!(
                    "btc_input_proof_receipt_missing: input {}",
                    input_index
                ));
            }
            hex::decode_to_slice(payload, &mut receipt)
                .map_err(|_| anyhow!("btc_input_proof_invalid_receipt: input {}", input_index))?;
        } else if !payload.is_empty() {
            return Err(anyhow!(
                "btc_input_proof_unexpected_response_data: input {}",
                input_index
            ));
        }
    }
    Ok(receipt)
}

pub(crate) fn segwit_sign_apdu(
    last_input: bool,
    mut data: Vec<u8>,
    receipt: Option<&InputReceipt>,
) -> Result<String> {
    if let Some(receipt) = receipt {
        data.extend_from_slice(receipt);
    }
    if data.len() > LC_MAX as usize {
        return Err(anyhow!("btc_segwit_signature_data_exceeds_apdu_limit"));
    }
    Ok(BtcApdu::btc_segwit_sign(last_input, 0x01, data))
}

#[cfg(test)]
mod tests {
    use crate::btcapi::BtcTxInput;
    use prost::Message;

    #[test]
    fn previous_transactions_use_repeated_bytes_field_nine() {
        let wire = [0x4a, 0x02, 0xab, 0xcd, 0x4a, 0x01, 0xef];
        let request = BtcTxInput::decode(wire.as_slice()).unwrap();
        assert_eq!(
            request.previous_transactions,
            vec![vec![0xab, 0xcd], vec![0xef]]
        );
        assert_eq!(request.encode_to_vec(), wire);
        assert!(BtcTxInput::decode([].as_slice())
            .unwrap()
            .previous_transactions
            .is_empty());
    }
}
