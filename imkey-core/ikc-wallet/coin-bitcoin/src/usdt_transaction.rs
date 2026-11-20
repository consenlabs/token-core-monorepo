use crate::change_candidates::{bitcoin_network_id, canonical_change_path};
use crate::common::{ensure_transaction_preview_version, get_utxo_pub_key, TxSignResult};
use crate::input_proof::{
    authenticated_transaction_chunk, send_input_proof, TRANSACTION_CHUNK_BYTES,
};
use crate::transaction::BtcTransaction;
use crate::Result;
use anyhow::anyhow;
use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::consensus::serialize;
use bitcoin::hashes::hex::ToHex;
use bitcoin::{Address, Network, PackedLockTime, PublicKey, Sequence, Transaction, TxOut};
use ikc_common::apdu::ApduCheck;
use ikc_common::constants::{MAX_UTXO_NUMBER, MIN_NONDUST_OUTPUT, TIMEOUT_LONG};
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_btc_apple_version;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use std::str::FromStr;

const OMNI_REVIEW_INS: u8 = 0x57;

impl BtcTransaction {
    /// Legacy callers must migrate to `sign_omni_transaction_with_previous_transactions`.
    pub fn sign_omni_transaction(
        &self,
        network: Network,
        path: &str,
        property_id: i32,
    ) -> Result<TxSignResult> {
        self.sign_omni_transaction_with_previous_transactions(
            network,
            path,
            property_id,
            false,
            &[],
        )
    }

    /// Legacy callers must migrate to `sign_omni_transaction_with_previous_transactions`.
    pub fn sign_omni_segwit_transaction(
        &self,
        network: Network,
        path: &str,
        property_id: i32,
    ) -> Result<TxSignResult> {
        self.sign_omni_transaction_with_previous_transactions(network, path, property_id, true, &[])
    }

    pub fn sign_omni_transaction_with_previous_transactions(
        &self,
        network: Network,
        path: &str,
        property_id: i32,
        segwit: bool,
        previous_transactions: &[Vec<u8>],
    ) -> Result<TxSignResult> {
        check_path_validity(path)?;
        let network_id = bitcoin_network_id(network)?;
        if self.unspents.len() > MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }
        if self.amount == 0 || self.amount > i64::MAX as u64 || property_id == 0 {
            return Err(CoinError::ImkeySdkIllegalArgument.into());
        }
        let inputs = self.validate_bitcoin_inputs(previous_transactions)?;
        let recipient = Address::from_str(&self.to)?;
        let recipient_script = recipient.script_pubkey();
        if recipient.network != network
            || !(recipient_script.is_p2pkh() || recipient_script.is_p2sh())
        {
            return Err(CoinError::InvalidAddress.into());
        }
        let minimum_fee_and_recipient = self
            .fee
            .checked_add(MIN_NONDUST_OUTPUT)
            .ok_or(CoinError::ImkeyInsufficientFunds)?;
        let input_total = self
            .unspents
            .iter()
            .try_fold(0u64, |sum, utxo| sum.checked_add(utxo.amount))
            .ok_or(CoinError::InvalidUtxo)?;
        let change_amount = input_total
            .checked_sub(minimum_fee_and_recipient)
            .ok_or(CoinError::ImkeyInsufficientFunds)?;

        ensure_transaction_preview_version(&get_btc_apple_version()?)?;
        let pub_keys = get_utxo_pub_key(&self.unspents)?;
        for ((outpoint, previous), public_key) in inputs.iter().zip(&pub_keys) {
            let public_key = PublicKey::from_str(public_key)?;
            let expected = if segwit {
                Address::p2shwpkh(&public_key, network)?
            } else {
                Address::p2pkh(&public_key, network)
            };
            if expected.script_pubkey() != previous.output[outpoint.vout as usize].script_pubkey {
                return Err(CoinError::InvalidUtxo.into());
            }
        }

        let mut output = Vec::with_capacity(3);
        let mut change = None;
        if change_amount >= MIN_NONDUST_OUTPUT {
            let (previous_output, previous) = &inputs[0];
            let script_pubkey = previous.output[previous_output.vout as usize]
                .script_pubkey
                .clone();
            change = self.unspents[0]
                .derive_path
                .to_ascii_lowercase()
                .parse()
                .ok()
                .and_then(|path| canonical_change_path(&path, &script_pubkey, network_id, true))
                .map(|path| (0, path));
            output.push(TxOut {
                value: change_amount,
                script_pubkey,
            });
        }
        output.push(TxOut {
            value: MIN_NONDUST_OUTPUT,
            script_pubkey: recipient_script,
        });
        output.push(self.build_omni_output(property_id, self.amount));
        let mut transaction = Transaction {
            version: if segwit { 2 } else { 1 },
            lock_time: PackedLockTime::ZERO,
            input: Vec::new(),
            output,
        };

        let receipts = inputs
            .iter()
            .enumerate()
            .map(|(index, (outpoint, previous))| {
                send_input_proof(inputs.len(), index, *outpoint, Sequence::MAX, previous)
            })
            .collect::<Result<Vec<_>>>()?;
        self.send_single_wallet_change(network, &inputs, &pub_keys, change)?;
        send_omni_preview(&transaction, network_id, inputs.len())?;
        for (index, (public_key, receipt)) in pub_keys.iter().zip(&receipts).enumerate() {
            if segwit {
                self.sign_p2sh_nested_p2wpkh_input(
                    index,
                    public_key,
                    &mut transaction,
                    Some(receipt),
                )?;
            } else {
                self.sign_p2pkh_input_after_preview(index, public_key, &mut transaction, 0x50)?;
            }
        }
        Ok(TxSignResult {
            signature: serialize(&transaction).to_hex(),
            tx_hash: transaction.txid().to_hex(),
            wtx_id: if segwit {
                transaction.wtxid().to_hex()
            } else {
                transaction.ntxid().to_hex()
            },
        })
    }

    pub fn build_omni_output(&self, property_id: i32, amount: u64) -> TxOut {
        let mut omni_data = b"omni\0\0\0\0".to_vec();
        omni_data.extend_from_slice(&property_id.to_be_bytes());
        omni_data.extend_from_slice(&amount.to_be_bytes());
        TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::all::OP_RETURN)
                .push_slice(&omni_data)
                .into_script(),
        }
    }
}

fn send_omni_preview(transaction: &Transaction, network: u8, input_count: usize) -> Result<()> {
    let mut body = vec![network];
    body.extend(transaction.version.to_le_bytes());
    body.push(input_count as u8);
    body.extend(serialize(&transaction.lock_time));
    body.extend(serialize(&transaction.output));
    let key_manager = KEY_MANAGER.lock();
    let chunks = body.chunks(TRANSACTION_CHUNK_BYTES);
    let last = chunks.len() - 1;
    for (index, fragment) in chunks.enumerate() {
        let phase = if index == last { 0x80 } else { 0 };
        let command = authenticated_transaction_chunk(
            OMNI_REVIEW_INS,
            index as u8,
            phase,
            fragment,
            &key_manager.pri_key,
        )?;
        let response = if index == last {
            send_apdu_timeout(command, TIMEOUT_LONG)?
        } else {
            send_apdu(command)?
        };
        ApduCheck::check_response(&response)?;
        if response.len() != 4 {
            return Err(anyhow!("btc_invalid_omni_review_response"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer() -> BtcTransaction {
        BtcTransaction {
            chain_type: "BITCOIN".to_owned(),
            to: "1BitcoinEaterAddressDontSendf59kuE".to_owned(),
            amount: 100,
            fee: 500,
            unspents: Vec::new(),
        }
    }

    #[test]
    fn omni_legacy_apis_require_verified_funding() {
        let transfer = transfer();
        for result in [
            transfer.sign_omni_transaction(Network::Bitcoin, "m/44'/0'/0'", 31),
            transfer.sign_omni_segwit_transaction(Network::Bitcoin, "m/49'/0'/0'", 31),
        ] {
            assert_eq!(
                result.err().unwrap().to_string(),
                "btc_requires_one_previous_transaction_per_input"
            );
        }
    }

    #[test]
    fn omni_simple_send_payload_uses_fixed_width_big_endian_fields() {
        let output = transfer().build_omni_output(0x9234_5678u32 as i32, 0x1122_3344_5566_7788);
        assert_eq!(output.value, 0);
        assert_eq!(
            hex::encode(output.script_pubkey.as_bytes()),
            "6a146f6d6e6900000000923456781122334455667788"
        );
    }
}
