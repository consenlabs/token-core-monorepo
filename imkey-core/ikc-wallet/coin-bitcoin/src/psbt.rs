use crate::btcapi::{PsbtInput, PsbtOutput};
use crate::common::{ensure_transaction_preview_version, get_xpub_data, select_btc_applet};
use crate::input_proof::{
    authenticated_transaction_chunk, check_previous_output, segwit_sign_apdu, send_input_proof,
    InputReceipt, TRANSACTION_CHUNK_BYTES,
};
use crate::Result;
use anyhow::anyhow;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::{serialize, Decodable, Encodable};
use bitcoin::psbt::Psbt;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::taproot::{TapLeafHash, TapTweakHash};
use bitcoin::{
    EcdsaSig, EcdsaSighashType, Network, PublicKey, SchnorrSig, SchnorrSighashType, Script, TxOut,
    WPubkeyHash, Witness,
};
use bitcoin_hashes::{hash160, Hash};
use hex::FromHex;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::constants::{MAX_UTXO_NUMBER, TIMEOUT_LONG};
use ikc_common::error::{ApduError, CoinError};
use ikc_common::path::check_path_validity;
use ikc_common::utility::hex_to_bytes;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_btc_apple_version;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::{
    ecdsa::Signature, schnorr::Signature as SchnorrSignature, PublicKey as Secp256k1PublicKey,
};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Mutex;

const PSBT_PREVIEW_MAX_BYTES: usize = 512;

enum PreviewState {
    Initial,
    InputsPrepared(Vec<InputReceipt>),
    Confirmed(Vec<InputReceipt>),
}

pub struct PsbtSigner<'a> {
    psbt: &'a mut Psbt,
    derivation_path: String,
    auto_finalize: bool,
    prevouts: Vec<TxOut>,
    network: Network,
    preview_state: Mutex<PreviewState>,
}

impl<'a> PsbtSigner<'a> {
    pub fn new(
        psbt: &'a mut Psbt,
        derivation_path: &str,
        auto_finalize: bool,
        network: Network,
        is_sign_message: bool,
    ) -> Result<Self> {
        if is_sign_message {
            return Err(anyhow!(
                "bip322_signing_requires_a_dedicated_device_protocol"
            ));
        }
        Ok(Self {
            psbt,
            derivation_path: derivation_path.to_string(),
            auto_finalize,
            prevouts: vec![],
            network,
            preview_state: Mutex::new(PreviewState::Initial),
        })
    }

    pub fn sign(&mut self, pub_keys: &Vec<String>) -> Result<()> {
        let state = self
            .preview_state
            .get_mut()
            .map_err(|_| ApduError::ImkeyUserNotConfirmed)?;
        let receipts = match std::mem::replace(state, PreviewState::Initial) {
            PreviewState::Confirmed(receipts) => receipts,
            _ => return Err(ApduError::ImkeyUserNotConfirmed.into()),
        };
        if pub_keys.len() != self.prevouts.len() {
            return Err(CoinError::InvalidUtxo.into());
        }
        for idx in 0..self.prevouts.len() {
            let prevout = &self.prevouts[idx];

            if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh(idx, &pub_keys[idx])?;

                if self.auto_finalize {
                    self.finalize_p2pkh(idx);
                }
            } else if prevout.script_pubkey.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh(idx, &pub_keys[idx], &receipts[idx])?;

                if self.auto_finalize {
                    self.finalize_p2sh_nested_p2wpkh(idx);
                }
            } else if prevout.script_pubkey.is_v0_p2wpkh() {
                self.sign_p2wpkh(idx, &pub_keys[idx], &receipts[idx])?;

                if self.auto_finalize {
                    self.finalize_p2wpkh(idx);
                }
            } else if !self.psbt.inputs.first().unwrap().tap_scripts.is_empty() {
                let input = self.psbt.inputs[idx].clone();
                let (_, script_leaf) = input.tap_scripts.first_key_value().unwrap();
                let (script, leaf_version) = script_leaf;
                self.sign_p2tr_script(
                    idx,
                    &pub_keys[idx],
                    Some((
                        TapLeafHash::from_script(script, leaf_version.clone()).into(),
                        0xFFFFFFFF,
                    )),
                )?;

                if self.auto_finalize {
                    self.finalize_p2tr(idx);
                }
            } else if prevout.script_pubkey.is_v1_p2tr() {
                self.sign_p2tr(idx, &pub_keys[idx])?;

                if self.auto_finalize {
                    self.finalize_p2tr(idx);
                }
            }

            if self.auto_finalize {
                self.clear_finalized_input(idx);
            }
        }

        Ok(())
    }

    pub fn prevouts(&mut self) -> Result<()> {
        self.prevouts.clear();
        let inputs = &self.psbt.unsigned_tx.input;
        if inputs.is_empty() || inputs.len() != self.psbt.inputs.len() {
            return Err(CoinError::InvalidUtxo.into());
        }
        if inputs.len() > MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }

        let mut prevouts = Vec::with_capacity(inputs.len());
        for (index, (txin, psbt_input)) in inputs.iter().zip(&self.psbt.inputs).enumerate() {
            let previous_tx = psbt_input
                .non_witness_utxo
                .as_ref()
                .ok_or_else(|| anyhow!("btc_missing_previous_transaction: input {}", index))?;
            let output = check_previous_output(previous_tx, txin.previous_output, index)?;
            if let Some(witness_utxo) = &psbt_input.witness_utxo {
                if witness_utxo != output {
                    return Err(anyhow!(
                        "btc_previous_transaction_output_mismatch: input {}",
                        index
                    ));
                }
            }
            prevouts.push(output.clone());
        }
        self.prevouts = prevouts;
        Ok(())
    }

    fn get_path(&self, index: usize, is_p2tr: bool) -> Result<String> {
        let input = &self.psbt.inputs[index];
        let mut path = if !self.derivation_path.is_empty() {
            format!("{}/0/0", self.derivation_path)
        } else {
            "".to_string()
        };

        if is_p2tr {
            let tap_bip32_derivation = input.tap_key_origins.first_key_value();

            if let Some((_, key_source)) = tap_bip32_derivation {
                path = key_source.1 .1.to_string();
            }
        } else {
            let bip32_derivations = input.bip32_derivation.first_key_value();

            if let Some((_, key_source)) = bip32_derivations {
                path = key_source.1.to_string();
            }
        }
        Ok(path)
    }

    pub fn get_pub_key(&self) -> Result<Vec<String>> {
        let mut pub_key_vec = vec![];
        for (idx, tx_out) in self.prevouts.iter().enumerate() {
            let path = if tx_out.script_pubkey.is_v1_p2tr() {
                self.get_path(idx, true)?
            } else {
                self.get_path(idx, false)?
            };

            let xpub_data = get_xpub_data(&path, false)?;
            let derive_pub_key = &xpub_data[..130];
            let public_key = Secp256k1PublicKey::from_str(derive_pub_key)?;
            pub_key_vec.push(public_key.to_string())
        }

        Ok(pub_key_vec)
    }

    fn sign_p2pkh(&mut self, idx: usize, pub_key: &str) -> Result<()> {
        let mut input_data_vec = vec![];
        for (x, prevout) in self.prevouts.iter().enumerate() {
            let mut temp_serialize_txin = self
                .psbt
                .unsigned_tx
                .input
                .get(x)
                .expect("get_input_error")
                .clone();
            if x == idx {
                temp_serialize_txin.script_sig = prevout.script_pubkey.clone();
            }
            input_data_vec.extend_from_slice(serialize(&temp_serialize_txin).as_slice());
        }
        let btc_perpare_apdu_list = BtcApdu::btc_single_utxo_sign_prepare(0x50, &input_data_vec);
        for apdu in btc_perpare_apdu_list {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }
        let path = self.get_path(idx, false)?;
        let btc_sign_apdu =
            BtcApdu::btc_single_utxo_sign(idx as u8, EcdsaSighashType::All.to_u32() as u8, &path);

        let btc_sign_apdu_return = send_apdu(btc_sign_apdu)?;
        ApduCheck::check_response(&btc_sign_apdu_return)?;
        let btc_sign_apdu_return =
            &btc_sign_apdu_return[..btc_sign_apdu_return.len() - 4].to_string();
        let sign_result_str = btc_sign_apdu_return[2..btc_sign_apdu_return.len() - 2].to_string();

        let mut signature_obj = Signature::from_compact(&hex::decode(&sign_result_str)?)?;
        signature_obj.normalize_s();
        let pub_key = PublicKey::from_str(pub_key)?;
        self.psbt.inputs[idx]
            .partial_sigs
            .insert(pub_key, EcdsaSig::sighash_all(signature_obj));

        Ok(())
    }

    fn sign_p2sh_nested_p2wpkh(
        &mut self,
        idx: usize,
        pub_key: &str,
        receipt: &InputReceipt,
    ) -> Result<()> {
        let temp_serialize_txin = self
            .psbt
            .unsigned_tx
            .input
            .get(idx)
            .expect("get_input_error")
            .clone();
        let prevout = &self.prevouts[idx];
        // let pub_key = &self.get_pub_key(idx, false)?;
        let mut data: Vec<u8> = vec![];
        //txhash and vout
        let txhash_data = serialize(&temp_serialize_txin.previous_output);
        data.extend(txhash_data.iter());
        //lock script
        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(hash160::Hash::hash(
            &hex_to_bytes(pub_key)?,
        )));
        let script = script.p2wpkh_script_code().expect("must be v0_p2wpkh");
        data.extend(serialize(&script).iter());
        //amount
        let mut utxo_amount = num_bigint::BigInt::from(prevout.value).to_signed_bytes_le();
        while utxo_amount.len() < 8 {
            utxo_amount.push(0x00);
        }
        data.extend(utxo_amount.iter());
        //set sequence
        let sequence = serialize(&temp_serialize_txin.sequence).to_vec();
        data.extend(sequence);
        //set length
        data.insert(0, data.len() as u8);
        //address
        let mut address_data: Vec<u8> = vec![];
        let sign_path = self.get_path(idx, false)?;
        address_data.push(sign_path.as_bytes().len() as u8);
        address_data.extend_from_slice(sign_path.as_bytes());
        data.extend(address_data.iter());

        let last_input = idx == self.psbt.unsigned_tx.input.len() - 1;
        let sign_apdu = segwit_sign_apdu(last_input, data, Some(receipt))?;
        let sign_apdu_return_data = send_apdu(sign_apdu)?;
        ApduCheck::check_response(&sign_apdu_return_data)?;

        //build signature obj
        let sign_result_vec =
            Vec::from_hex(&sign_apdu_return_data[2..sign_apdu_return_data.len() - 6]).unwrap();
        let mut signature_obj = Signature::from_compact(sign_result_vec.as_slice())?;
        signature_obj.normalize_s();
        //generator der sign data
        let mut sign_result_vec = signature_obj.serialize_der().to_vec();
        //add hash type
        sign_result_vec.push(EcdsaSighashType::All.to_u32() as u8);
        let pub_key = PublicKey::from_str(pub_key)?;
        self.psbt.inputs[idx]
            .partial_sigs
            .insert(pub_key, EcdsaSig::sighash_all(signature_obj));
        Ok(())
    }

    fn sign_p2wpkh(&mut self, idx: usize, pub_key: &str, receipt: &InputReceipt) -> Result<()> {
        let temp_serialize_txin = self
            .psbt
            .unsigned_tx
            .input
            .get(idx)
            .expect("get_input_error")
            .clone();
        let prevout = &self.prevouts[idx];
        let mut data: Vec<u8> = vec![];
        //txhash and vout
        let txhash_data = serialize(&temp_serialize_txin.previous_output);
        data.extend(txhash_data.iter());
        //lock script
        let script = prevout
            .script_pubkey
            .p2wpkh_script_code()
            .expect("must be v0_p2wpkh");
        data.extend(serialize(&script).iter());
        //amount
        let mut utxo_amount = num_bigint::BigInt::from(prevout.value).to_signed_bytes_le();
        while utxo_amount.len() < 8 {
            utxo_amount.push(0x00);
        }
        data.extend(utxo_amount.iter());
        //set sequence
        let sequence = serialize(&temp_serialize_txin.sequence).to_vec();
        data.extend(sequence);
        //set length
        data.insert(0, data.len() as u8);
        //address
        let mut address_data: Vec<u8> = vec![];
        let sign_path = self.get_path(idx, false)?;
        address_data.push(sign_path.as_bytes().len() as u8);
        address_data.extend_from_slice(sign_path.as_bytes());
        data.extend(address_data.iter());

        let last_input = idx == self.psbt.unsigned_tx.input.len() - 1;
        let sign_apdu = segwit_sign_apdu(last_input, data, Some(receipt))?;
        let sign_apdu_return_data = send_apdu(sign_apdu)?;
        ApduCheck::check_response(&sign_apdu_return_data)?;
        //build signature obj
        let sign_result_vec =
            Vec::from_hex(&sign_apdu_return_data[2..sign_apdu_return_data.len() - 6]).unwrap();
        let mut signature_obj = Signature::from_compact(sign_result_vec.as_slice())?;
        signature_obj.normalize_s();
        let pub_key = PublicKey::from_str(pub_key)?;
        self.psbt.inputs[idx]
            .partial_sigs
            .insert(pub_key, EcdsaSig::sighash_all(signature_obj));
        Ok(())
    }

    fn sign_p2tr(&mut self, idx: usize, pub_key: &str) -> Result<()> {
        let mut data: Vec<u8> = vec![];
        // epoch (1).
        data.push(0x00u8);
        // hash_type (1).
        data.push(SchnorrSighashType::Default as u8);
        //nVersion (4):
        //nLockTime (4)
        // data.extend(serialize(&PackedLockTime::ZERO));
        data.extend(serialize(&self.psbt.unsigned_tx.lock_time));
        //prevouts_hash + amounts_hash + script_pubkeys_hash + sequences_hash + sha_outputs (32)
        //spend_type (1)
        data.push(0x00u8);
        //input_index (4)
        data.extend(serialize(&(idx as u32)));

        let mut path_data: Vec<u8> = vec![];
        let sign_path = self.get_path(idx, true)?;
        path_data.push(sign_path.as_bytes().len() as u8);
        path_data.extend_from_slice(sign_path.as_bytes());
        data.extend(path_data.iter());

        let mut tweaked_pub_key_data: Vec<u8> = vec![];
        let untweaked_public_key = UntweakedPublicKey::from_str(&pub_key[2..66])?;
        let tweaked_pub_key = TapTweakHash::from_key_and_tweak(untweaked_public_key, None).to_vec();
        tweaked_pub_key_data.push(tweaked_pub_key.len() as u8);
        tweaked_pub_key_data.extend_from_slice(&tweaked_pub_key);
        data.extend(tweaked_pub_key_data.iter());

        let sign_apdu = if idx == (self.psbt.unsigned_tx.input.len() - 1) {
            BtcApdu::btc_taproot_sign(true, data)
        } else {
            BtcApdu::btc_taproot_sign(false, data)
        };
        let sign_result = send_apdu(sign_apdu)?;
        ApduCheck::check_response(&sign_result)?;

        let sign_bytes = hex_to_bytes(&sign_result[2..(sign_result.len() - 4)])?;
        let sig = SchnorrSignature::from_slice(&sign_bytes)?;
        self.psbt.inputs[idx].tap_key_sig = Some(SchnorrSig {
            hash_ty: SchnorrSighashType::Default,
            sig,
        });

        Ok(())
    }

    fn sign_p2tr_script(
        &mut self,
        idx: usize,
        pub_key: &str,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
    ) -> Result<()> {
        let mut data: Vec<u8> = vec![];
        // epoch (1).
        data.push(0x00u8);
        // hash_type (1).
        data.push(SchnorrSighashType::Default as u8);
        //nVersion (4):
        //nLockTime (4)
        // data.extend(serialize(&PackedLockTime::ZERO));
        data.extend(serialize(&self.psbt.unsigned_tx.lock_time));
        //prevouts_hash + amounts_hash + script_pubkeys_hash + sequences_hash + sha_outputs (32)
        //spend_type (1)
        let mut spend_type = 0u8;
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2u8;
        }
        data.push(spend_type);
        //input_index (4)
        data.extend(serialize(&(idx as u32)));
        //leaf hash code separator
        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            let mut temp_data = hash.into_inner().to_vec();
            temp_data.push(0x00u8); //key_version_0
            let code_separator_pos = code_separator_pos.to_be_bytes();
            temp_data.extend(code_separator_pos);
            data.push(temp_data.len() as u8);
            data.extend(temp_data);
        }
        let mut path_data: Vec<u8> = vec![];
        let sign_path = self.get_path(idx, true)?;
        path_data.push(sign_path.as_bytes().len() as u8);
        path_data.extend_from_slice(sign_path.as_bytes());
        data.extend(path_data.iter());
        let mut tweaked_pub_key_data: Vec<u8> = vec![];
        let untweaked_public_key = UntweakedPublicKey::from_str(&pub_key[2..66])?;
        let tweaked_pub_key = TapTweakHash::from_key_and_tweak(untweaked_public_key, None).to_vec();
        tweaked_pub_key_data.push(tweaked_pub_key.len() as u8);
        tweaked_pub_key_data.extend_from_slice(&tweaked_pub_key);
        data.extend(tweaked_pub_key_data.iter());

        let sign_apdu = if idx == (self.psbt.unsigned_tx.input.len() - 1) {
            BtcApdu::btc_taproot_script_sign(true, data)
        } else {
            BtcApdu::btc_taproot_script_sign(false, data)
        };

        let sign_result = send_apdu(sign_apdu)?;
        ApduCheck::check_response(&sign_result)?;

        let sign_bytes = hex_to_bytes(&sign_result[2..(sign_result.len() - 4)])?;
        let sig = SchnorrSignature::from_slice(&sign_bytes)?;
        self.psbt.inputs[idx].tap_key_sig = Some(SchnorrSig {
            hash_ty: SchnorrSighashType::Default,
            sig,
        });

        Ok(())
    }

    pub fn calc_tx_hash(&self) -> Result<()> {
        let mut state = self
            .preview_state
            .lock()
            .map_err(|_| ApduError::ImkeyUserNotConfirmed)?;
        *state = PreviewState::Initial;

        let inputs = &self.psbt.unsigned_tx.input;
        if inputs.is_empty() || inputs.len() != self.prevouts.len() {
            return Err(CoinError::InvalidUtxo.into());
        }
        if inputs.len() > MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }

        // The version query reselects the applet. Send proofs afterwards
        // so the proofs, preview, and signing share one device session.
        ensure_transaction_preview_version(&get_btc_apple_version()?)?;
        let mut receipts = Vec::with_capacity(inputs.len());
        for (index, (input, psbt_input)) in inputs.iter().zip(&self.psbt.inputs).enumerate() {
            let previous_tx = psbt_input
                .non_witness_utxo
                .as_ref()
                .ok_or_else(|| anyhow!("btc_missing_previous_transaction: input {}", index))?;
            receipts.push(send_input_proof(
                inputs.len(),
                index,
                input.previous_output,
                input.sequence,
                previous_tx,
            )?);
        }
        *state = PreviewState::InputsPrepared(receipts);
        Ok(())
    }

    pub fn tx_preview(&self, network: Network) -> Result<()> {
        let mut state = self
            .preview_state
            .lock()
            .map_err(|_| ApduError::ImkeyUserNotConfirmed)?;
        let receipts = match std::mem::replace(&mut *state, PreviewState::Initial) {
            PreviewState::InputsPrepared(receipts) => receipts,
            _ => return Err(ApduError::ImkeyUserNotConfirmed.into()),
        };
        if network != self.network {
            return Err(CoinError::ImkeySdkIllegalArgument.into());
        }

        let transaction = &self.psbt.unsigned_tx;
        let network_id = match network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            _ => return Err(CoinError::ImkeySdkIllegalArgument.into()),
        };
        if transaction.output.is_empty() {
            return Err(anyhow!("psbt_requires_at_least_one_output"));
        }
        self.output_totals()?;
        let mut body = vec![network_id];
        body.extend(transaction.version.to_le_bytes());
        body.push(transaction.input.len() as u8);
        body.extend(serialize(&transaction.lock_time));
        body.extend(serialize(&transaction.output));
        if body.len() > PSBT_PREVIEW_MAX_BYTES {
            return Err(anyhow!(
                "psbt_preview_exceeds_output_data_limit: {} bytes exceeds {}",
                body.len(),
                PSBT_PREVIEW_MAX_BYTES
            ));
        }

        let chunks = body.chunks(TRANSACTION_CHUNK_BYTES);
        let last_chunk = chunks.len() - 1;
        let key_manager = KEY_MANAGER.lock();
        for (index, fragment) in chunks.enumerate() {
            let final_chunk = index == last_chunk;
            let phase = if final_chunk { 0x80 } else { 0x00 };
            let index = index as u8;
            let apdu = authenticated_transaction_chunk(
                0x52,
                index,
                phase,
                fragment,
                &key_manager.pri_key,
            )?;
            let response = if final_chunk {
                send_apdu_timeout(apdu, TIMEOUT_LONG)?
            } else {
                send_apdu(apdu)?
            };
            ApduCheck::check_response(&response)?;
        }

        *state = PreviewState::Confirmed(receipts);
        Ok(())
    }

    fn finalize_p2pkh(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();

            input.final_script_sig = Some(
                Builder::new()
                    .push_slice(&sig.1.to_vec())
                    .push_slice(&sig.0.to_bytes())
                    .into_script(),
            );
        }
    }

    fn finalize_p2sh_nested_p2wpkh(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();

            let script =
                Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(Self::hash160(&sig.0.to_bytes())));
            let script = Builder::new().push_slice(&script.as_bytes()).into_script();
            input.final_script_sig = Some(script);

            let mut witness = Witness::new();
            witness.push(sig.1.to_vec());
            witness.push(sig.0.to_bytes());

            input.final_script_witness = Some(witness);
        }
    }

    fn finalize_p2wpkh(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();
            let mut witness = Witness::new();

            witness.push(sig.1.to_vec());
            witness.push(sig.0.to_bytes());

            input.final_script_witness = Some(witness)
        }
    }

    fn finalize_p2tr(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];

        if input.tap_key_sig.is_some() {
            let mut witness = Witness::new();
            witness.push(input.tap_key_sig.unwrap().to_vec());

            if !input.tap_scripts.is_empty() {
                let (control_block, script_leaf) = input.tap_scripts.first_key_value().unwrap();

                let (script, _) = script_leaf;
                witness.push(script.as_bytes().to_vec());
                witness.push(control_block.serialize())
            }

            input.final_script_witness = Some(witness);
        }
    }

    fn clear_finalized_input(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];
        input.tap_key_sig = None;
        input.tap_scripts = BTreeMap::new();
        input.tap_internal_key = None;
        input.tap_merkle_root = None;
        input.tap_script_sigs = BTreeMap::new();
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
        input.unknown = BTreeMap::new();
    }

    fn hash160(input: &[u8]) -> hash160::Hash {
        Hash::hash(input)
    }

    pub fn get_preview_info(&self) -> Result<(u64, u64, Vec<TxOut>)> {
        let (output_total, fee) = self.output_totals()?;
        Ok((output_total, fee, self.psbt.unsigned_tx.output.clone()))
    }

    fn output_totals(&self) -> Result<(u64, u64)> {
        let sum_outputs = |outputs: &[TxOut]| {
            outputs
                .iter()
                .try_fold(0u64, |sum, output| sum.checked_add(output.value))
                .ok_or_else(|| anyhow!("psbt_amount_overflow"))
        };
        let output_total = sum_outputs(&self.psbt.unsigned_tx.output)?;
        let input_total = sum_outputs(&self.prevouts)?;
        let fee = input_total
            .checked_sub(output_total)
            .ok_or(CoinError::ImkeyInsufficientFunds)?;
        Ok((output_total, fee))
    }
}

pub fn sign_psbt(
    derivation_path: &str,
    psbt_input: PsbtInput,
    network: Network,
) -> Result<PsbtOutput> {
    check_path_validity(derivation_path)?;

    select_btc_applet()?;

    let mut reader = Cursor::new(Vec::<u8>::from_hex(psbt_input.psbt)?);
    let mut psbt = Psbt::consensus_decode(&mut reader)?;
    let mut signer = PsbtSigner::new(
        &mut psbt,
        derivation_path,
        psbt_input.auto_finalize,
        network,
        false,
    )?;

    signer.prevouts()?;

    let pub_keys = signer.get_pub_key()?;

    signer.calc_tx_hash()?;

    signer.tx_preview(network)?;

    signer.sign(&pub_keys)?;

    let mut vec = Vec::<u8>::new();
    let mut writer = Cursor::new(&mut vec);
    psbt.consensus_encode(&mut writer)?;

    return Ok(PsbtOutput {
        psbt: hex::encode(vec),
    });
}

#[cfg(test)]
mod test {
    use crate::btcapi::PsbtInput;
    use crate::common::select_btc_applet;
    use crate::psbt::PsbtSigner;
    use bitcoin::consensus::Decodable;
    use bitcoin::psbt::serialize::{Deserialize, Serialize};
    use bitcoin::psbt::Psbt;
    use bitcoin::schnorr::TapTweak;
    use bitcoin::util::bip32::DerivationPath;
    use bitcoin::{schnorr, Address, Network, Transaction, TxOut};
    use bitcoin_hashes::hex::ToHex;
    use hex::FromHex;
    use ikc_device::device_binding::bind_test;
    use secp256k1::schnorr::Signature;
    use secp256k1::{Message, XOnlyPublicKey};
    use std::io::Cursor;
    use std::str::FromStr;

    #[test]
    fn test_sign_psbt_no_script() {
        bind_test();

        let psbt_input = PsbtInput {
            psbt: "70736274ff0100db0200000001fa4c8d58b9b6c56ed0b03f78115246c99eb70f99b837d7b4162911d1016cda340200000000fdffffff0350c30000000000002251202114eda66db694d87ff15ddd5d3c4e77306b6e6dd5720cbd90cd96e81016c2b30000000000000000496a47626274340066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229ec20acf33c17e5a6c92cced9f1d530cccab7aa3e53400456202f02fac95e9c481fa00d47b1700000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233d80f03000001012be3bf1d00000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c23301172066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e00000000".to_string(),
            auto_finalize: true,
        };

        let psbt_output = super::sign_psbt("m/86'/1'/0'", psbt_input, Network::Bitcoin).unwrap();
        let mut reader = Cursor::new(Vec::<u8>::from_hex(&psbt_output.psbt).unwrap());
        let psbt = Psbt::consensus_decode(&mut reader).unwrap();
        let tx = psbt.extract_tx();
        let sig = schnorr::SchnorrSig::from_slice(&tx.input[0].witness.to_vec()[0]).unwrap();

        let data =
            Vec::<u8>::from_hex("3a66cf6ec1a87b10b86fa358baf64484bba8c61c9828e5cbe2eb8a3d4bbf190c")
                .unwrap();
        let msg = Message::from_slice(&data).unwrap();
        let x_pub_key = XOnlyPublicKey::from_slice(
            Vec::<u8>::from_hex("66f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let SECP256K1_ENGINE: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
        let tweak_pub_key = x_pub_key.tap_tweak(&SECP256K1_ENGINE, None);

        // assert!(sig.sig.verify(&msg, &tweak_pub_key.0.to_inner()).is_ok());
    }

    #[test]
    fn test_sign_psbt_script() {
        bind_test();

        let psbt_input = PsbtInput {
            psbt: "70736274ff01005e02000000012bd2f6479f3eeaffe95c03b5fdd76a873d346459114dec99c59192a0cb6409e90000000000ffffffff01409c000000000000225120677cc88dc36a75707b370e27efff3e454d446ad55004dac1685c1725ee1a89ea000000000001012b50c3000000000000225120a9a3350206de400f09a73379ec1bcfa161fc11ac095e5f3d7354126f0ec8e87f6215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0d2956573f010fa1a3c135279c5eb465ec2250205dcdfe2122637677f639b1021356c963cd9c458508d6afb09f3fa2f9b48faec88e75698339a4bbb11d3fc9b0efd570120aff94eb65a2fe773a57c5bd54e62d8436a5467573565214028422b41bd43e29bad200aee0509b16db71c999238a4827db945526859b13c95487ab46725357c9a9f25ac20113c3a32a9d320b72190a04a020a0db3976ef36972673258e9a38a364f3dc3b0ba2017921cf156ccb4e73d428f996ed11b245313e37e27c978ac4d2cc21eca4672e4ba203bb93dfc8b61887d771f3630e9a63e97cbafcfcc78556a474df83a31a0ef899cba2040afaf47c4ffa56de86410d8e47baa2bb6f04b604f4ea24323737ddc3fe092dfba2079a71ffd71c503ef2e2f91bccfc8fcda7946f4653cef0d9f3dde20795ef3b9f0ba20d21faf78c6751a0d38e6bd8028b907ff07e9a869a43fc837d6b3f8dff6119a36ba20f5199efae3f28bb82476163a7e458c7ad445d9bffb0682d10d3bdb2cb41f8e8eba20fa9d882d45f4060bdb8042183828cd87544f1ea997380e586cab77d5fd698737ba569cc001172050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00000".to_string(),
            auto_finalize: true,
        };

        let psbt_output = super::sign_psbt("m/86'/1'/0'", psbt_input, Network::Bitcoin).unwrap();
        let mut reader = Cursor::new(Vec::<u8>::from_hex(&psbt_output.psbt).unwrap());
        let psbt = Psbt::consensus_decode(&mut reader).unwrap();
        let tx = psbt.extract_tx();
        let witness = tx.input[0].witness.to_vec();
        let sig = schnorr::SchnorrSig::from_slice(&witness[0]).unwrap();

        let data =
            Vec::<u8>::from_hex("56b6c5fd09753fbbbeb8f530308e4f7d2f404e02da767f033e926d27fcc2f37e")
                .unwrap();
        let msg = Message::from_slice(&data).unwrap();
        let x_pub_key = XOnlyPublicKey::from_slice(
            Vec::<u8>::from_hex("66f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let script = hex::encode(&witness[1]);
        let control_block = hex::encode(&witness[2]);
        assert_eq!(script, "20aff94eb65a2fe773a57c5bd54e62d8436a5467573565214028422b41bd43e29bad200aee0509b16db71c999238a4827db945526859b13c95487ab46725357c9a9f25ac20113c3a32a9d320b72190a04a020a0db3976ef36972673258e9a38a364f3dc3b0ba2017921cf156ccb4e73d428f996ed11b245313e37e27c978ac4d2cc21eca4672e4ba203bb93dfc8b61887d771f3630e9a63e97cbafcfcc78556a474df83a31a0ef899cba2040afaf47c4ffa56de86410d8e47baa2bb6f04b604f4ea24323737ddc3fe092dfba2079a71ffd71c503ef2e2f91bccfc8fcda7946f4653cef0d9f3dde20795ef3b9f0ba20d21faf78c6751a0d38e6bd8028b907ff07e9a869a43fc837d6b3f8dff6119a36ba20f5199efae3f28bb82476163a7e458c7ad445d9bffb0682d10d3bdb2cb41f8e8eba20fa9d882d45f4060bdb8042183828cd87544f1ea997380e586cab77d5fd698737ba569c");
        assert_eq!(control_block, "c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0d2956573f010fa1a3c135279c5eb465ec2250205dcdfe2122637677f639b1021356c963cd9c458508d6afb09f3fa2f9b48faec88e75698339a4bbb11d3fc9b0e");

        // assert!(sig.sig.verify(&msg, &x_pub_key).is_ok());
    }

    #[test]
    fn test_sign_psbt_multipayment() {
        bind_test();

        let raw_tx = "02000000054adc61444e5a4dd7021e52dc6f5adadd9a3286d346f5d9f023ebcde2af80a0ae0000000000ffffffff4adc61444e5a4dd7021e52dc6f5adadd9a3286d346f5d9f023ebcde2af80a0ae0100000000ffffffff12cc8049bf85b5e18cb2be8aa7aefc3afb8df4ec5c1f766750014cc95ca2dc130000000000ffffffff729e6570928cc65200f1d53def65a7934d2e9b543059d90598ed1d166af422010100000000ffffffffa126724475cd2f3252352b3543c8455c7999a8283883bd7a712a7d66609d92d80100000000ffffffff02409c00000000000022512036079c540758a51a86eeaf9e17668d4d8543d8b1b7e56fe2da0982c390c5655ef8fa0700000000002251209303a116174dd21ea473766659568ac24eb6b828c3ee998982d2ba070ea0615500000000";
        let mut tx = Transaction::deserialize(&Vec::from_hex(&raw_tx).unwrap()).unwrap();

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let fake_pub_key = secp256k1::PublicKey::from_slice(
            &Vec::<u8>::from_hex(
                "0266f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e",
            )
            .unwrap(),
        )
        .unwrap();
        let fake_xonly_pub_key = XOnlyPublicKey::from_slice(
            Vec::<u8>::from_hex("66f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        psbt.inputs[0].tap_key_origins.insert(
            fake_xonly_pub_key,
            (
                Default::default(),
                (
                    Default::default(),
                    DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap(),
                ),
            ),
        );
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 20000,
            script_pubkey: Address::from_str(
                "tb1p3ax2dfecfag2rlsqewje84dgxj6gp3jkj2nk4e3q9cwwgm93cgesa0zwj4",
            )
            .unwrap()
            .script_pubkey(),
        });

        psbt.inputs[1].tap_key_origins.insert(
            fake_xonly_pub_key,
            (
                Default::default(),
                (
                    Default::default(),
                    DerivationPath::from_str("m/86'/1'/0'/1/53").unwrap(),
                ),
            ),
        );
        psbt.inputs[1].witness_utxo = Some(TxOut {
            value: 283000,
            script_pubkey: Address::from_str(
                "tb1pjvp6z9shfhfpafrnwen9j452cf8tdwpgc0hfnzvz62aqwr4qv92sg7qj9r",
            )
            .unwrap()
            .script_pubkey(),
        });

        psbt.inputs[2].bip32_derivation.insert(
            fake_pub_key,
            (
                Default::default(),
                DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
            ),
        );
        psbt.inputs[2].witness_utxo = Some(TxOut {
            value: 100000,
            script_pubkey: Address::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95")
                .unwrap()
                .script_pubkey(),
        });

        psbt.inputs[3].bip32_derivation.insert(
            fake_pub_key,
            (
                Default::default(),
                DerivationPath::from_str("m/49'/1'/0'/0/0").unwrap(),
            ),
        );
        psbt.inputs[3].witness_utxo = Some(TxOut {
            value: 100000,
            script_pubkey: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB")
                .unwrap()
                .script_pubkey(),
        });

        psbt.inputs[4].bip32_derivation.insert(
            fake_pub_key,
            (
                Default::default(),
                DerivationPath::from_str("m/44'/1'/0'/0/0").unwrap(),
            ),
        );
        psbt.inputs[4].witness_utxo = Some(TxOut {
            value: 100000,
            script_pubkey: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
                .unwrap()
                .script_pubkey(),
        });

        select_btc_applet().unwrap();

        let mut signer = PsbtSigner::new(&mut psbt, "", true, Network::Testnet, false).unwrap();

        signer.prevouts().unwrap();

        let pub_keys = signer.get_pub_key().unwrap();

        signer.calc_tx_hash().unwrap();

        signer.get_preview_info().unwrap();

        signer.tx_preview(Network::Testnet).unwrap();

        signer.sign(&pub_keys).unwrap();

        let tx = psbt.extract_tx();

        let msg = Message::from_slice(
            &Vec::from_hex("f01ba76b329132e48188ad10d00791647ee6d2f7fee5ef397f3481993c898de3")
                .unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&tx.input[0].witness.to_vec()[0]).unwrap();
        let pub_key = XOnlyPublicKey::from_slice(
            &Vec::from_hex("8f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233")
                .unwrap(),
        )
        .unwrap();
        // assert!(sig.verify(&msg, &pub_key).is_ok());

        let msg = Message::from_slice(
            &Vec::from_hex("d0691b5ac1b338b9341790ea69417cb454cf346a718342fb4a846dbb8ae142e8")
                .unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&tx.input[1].witness.to_vec()[0]).unwrap();
        let pub_key = XOnlyPublicKey::from_slice(
            &Vec::from_hex("9303a116174dd21ea473766659568ac24eb6b828c3ee998982d2ba070ea06155")
                .unwrap(),
        )
        .unwrap();
        // assert!(sig.verify(&msg, &pub_key).is_ok());

        assert_eq!(tx.input[2].witness.to_vec()[0].to_hex(), "3044022022c2feaa4a225496fc6789c969fb776da7378f44c588ad812a7e1227ebe69b6302204fc7bf5107c6d02021fe4833629bc7ab71cefe354026ebd0d9c0da7d4f335f9401");
        assert_eq!(
            tx.input[2].witness.to_vec()[1].to_hex(),
            "02e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c0"
        );

        assert_eq!(tx.input[3].witness.to_vec()[0].to_hex(), "3045022100dec4d3fd189b532ef04f41f68319ff7dc6a7f2351a0a8f98cb7f1ec1f6d71c7a02205e507162669b642fdb480a6c496abbae5f798bce4fd42cc390aa58e3847a1b9101");
        assert_eq!(
            tx.input[3].witness.to_vec()[1].to_hex(),
            "031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc"
        );

        assert_eq!(tx.input[4].script_sig.to_hex(), "483045022100ca32abc7b180c84cf76907e4e1e0c3f4c0d6e64de23b0708647ac6fee1c04c5b02206e7412a712424eb9406f18e00a42e0dffbfb5901932d1ef97843d9273865550e0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4e");
    }

    #[test]
    fn test_sign_psbt_nested_segwit() {
        bind_test();
        let psbt_input = PsbtInput {
            psbt: "70736274ff0100730200000001fe21f2749ecc542a7fb8d6bc136b531e74967b9efeb84f46ad7469861a9cba2e0200000000ffffffff02e80300000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca587e72301000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca5870000000000010120932901000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca5870104160014472fe3b898332a7069dbad917f1fab64e1524e3a220603fd595ab49fa4c6ab779d7415c6234ec85d5cac9ebdaea59be913b997524047e718000000003100008000000080000000800000000000000000000000".to_string(),
            auto_finalize: true,
        };

        let psbt_output = super::sign_psbt("m/49'/0'/0'", psbt_input, Network::Bitcoin).unwrap();
        assert_eq!(psbt_output.psbt, "70736274ff0100730200000001fe21f2749ecc542a7fb8d6bc136b531e74967b9efeb84f46ad7469861a9cba2e0200000000ffffffff02e80300000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca587e72301000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca5870000000000010120932901000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca58701071716001456639e5fa57dad8a9888749051ffa28837f1a8dd01086c0248304502210088cf0dbfe31d38238cab22ae0fb572949cb4b35a96660e9b60c0e7d5f72c5f8e022030efd75b8789f6ed5895630246d97c68e3d9d5adbdeb9390e3f59d7fa86b15c7012103036695c5f3de2e2792b170f59679d4db88a8516728012eaa42a22ce6f8bf593b000000".to_string());
    }
}

#[cfg(test)]
mod p2wsh_preview_regression;
