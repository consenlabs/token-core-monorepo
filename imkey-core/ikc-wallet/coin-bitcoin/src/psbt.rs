use crate::address::BtcAddress;
use crate::btcapi::{PsbtInput, PsbtOutput};
use crate::common::{get_address_version, get_xpub_data, select_btc_applet};
use crate::Result;
use anyhow::anyhow;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::{serialize, Decodable, Encodable};
use bitcoin::psbt::Psbt;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::taproot::{TapLeafHash, TapTweakHash};
use bitcoin::{
    Address, EcdsaSig, EcdsaSighashType, Network, PublicKey, SchnorrSig, SchnorrSighashType,
    Script, TxOut, WPubkeyHash, Witness,
};
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::{hash160, Hash};
use hex::FromHex;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::coin_info::coin_info_from_param;
use ikc_common::constants;
use ikc_common::constants::TIMEOUT_LONG;
use ikc_common::error::CoinError;
use ikc_common::path::{check_path_validity, get_account_path};
use ikc_common::utility::{bigint_to_byte_vec, hex_to_bytes, secp256k1_sign, sha256_hash};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::{
    ecdsa::Signature, schnorr::Signature as SchnorrSignature, PublicKey as Secp256k1PublicKey,
};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::str::FromStr;
use std::usize;

pub struct PsbtSigner<'a> {
    psbt: &'a mut Psbt,
    derivation_path: String,
    auto_finalize: bool,
    prevouts: Vec<TxOut>,
    network: Network,
    preview_output: Vec<TxOut>,
    is_sign_message: bool,
}

impl<'a> PsbtSigner<'a> {
    pub fn new(
        psbt: &'a mut Psbt,
        derivation_path: &str,
        auto_finalize: bool,
        network: Network,
        is_sign_message: bool,
    ) -> Result<Self> {
        let mut psbt_signer = PsbtSigner {
            psbt,
            derivation_path: derivation_path.to_string(),
            prevouts: vec![],
            auto_finalize,
            network,
            preview_output: vec![],
            is_sign_message,
        };
        psbt_signer.get_preview_output()?;
        Ok(psbt_signer)
    }

    pub fn sign(&mut self, pub_keys: &Vec<String>) -> Result<()> {
        for idx in 0..self.prevouts.len() {
            let prevout = &self.prevouts[idx];

            if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh(idx, &pub_keys[idx])?;

                if self.auto_finalize {
                    self.finalize_p2pkh(idx);
                }
            } else if prevout.script_pubkey.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh(idx, &pub_keys[idx])?;

                if self.auto_finalize {
                    self.finalize_p2sh_nested_p2wpkh(idx);
                }
            } else if prevout.script_pubkey.is_v0_p2wpkh() {
                self.sign_p2wpkh(idx, &pub_keys[idx])?;

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
        let len = self.psbt.inputs.len();
        let mut utxos = Vec::with_capacity(len);

        for i in 0..len {
            let input = &self.psbt.inputs[i];
            let utxo = if let Some(witness_utxo) = &input.witness_utxo {
                witness_utxo
            } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
                let vout = self.psbt.unsigned_tx.input[i].previous_output.vout;
                &non_witness_utxo.output[vout as usize]
            } else {
                return Err(CoinError::InvalidUtxo.into());
            };
            utxos.push(utxo.clone());
        }
        self.prevouts = utxos;
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
        input_data_vec.extend(serialize(&self.psbt.unsigned_tx.output));
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

    fn sign_p2sh_nested_p2wpkh(&mut self, idx: usize, pub_key: &str) -> Result<()> {
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

        let sign_apdu = if idx == (self.psbt.unsigned_tx.input.len() - 1) {
            BtcApdu::btc_segwit_sign(true, 0x01, data)
        } else {
            BtcApdu::btc_segwit_sign(false, 0x01, data)
        };
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

    fn sign_p2wpkh(&mut self, idx: usize, pub_key: &str) -> Result<()> {
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

        let sign_apdu = if idx == (self.psbt.unsigned_tx.input.len() - 1) {
            BtcApdu::btc_segwit_sign(true, 0x01, data)
        } else {
            BtcApdu::btc_segwit_sign(false, 0x01, data)
        };
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
        let mut txhash_vout_vec = vec![];
        let mut sequence_vec = vec![];
        let mut amount_vec = vec![];
        let mut script_pubkeys_vec = vec![];
        for (idx, tx_in) in self.psbt.unsigned_tx.input.iter().enumerate() {
            let prevout = &self.prevouts[idx];
            txhash_vout_vec.extend(serialize(&tx_in.previous_output));
            sequence_vec.extend(serialize(&tx_in.sequence));
            amount_vec.extend(serialize(&prevout.value));
            script_pubkeys_vec.extend(serialize(&prevout.script_pubkey));
        }
        let mut calc_hash_apdu = vec![];
        calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x40, &txhash_vout_vec));
        calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x80, &sequence_vec));
        calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x20, &amount_vec));
        calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x21, &script_pubkeys_vec));
        for apdu in calc_hash_apdu {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }
        Ok(())
    }

    pub fn tx_preview(&self, network: Network) -> Result<()> {
        let (total_amount, fee, _outputs) = self.get_preview_info()?;
        let mut preview_data = vec![];
        preview_data.extend(&serialize(&self.psbt.unsigned_tx.version)); //version
        let input_number = self.psbt.unsigned_tx.input.len();
        preview_data.push(input_number as u8); //input number
        preview_data.extend(&serialize(&self.psbt.unsigned_tx.lock_time)); //lock time
        let mut sign_hash_type = Vec::new();
        let len = EcdsaSighashType::All
            .to_u32()
            .consensus_encode(&mut sign_hash_type)
            .unwrap();
        debug_assert_eq!(len, sign_hash_type.len());
        preview_data.extend(&sign_hash_type); //hash type
        preview_data.extend(bigint_to_byte_vec(total_amount)); //total payment amount
        preview_data.extend(bigint_to_byte_vec(fee)); //fee
        let mut output_serialize = vec![];
        for tx_out in self.psbt.unsigned_tx.output.iter() {
            output_serialize.extend(serialize(tx_out));
        }
        let hash = &sha256_hash(&output_serialize);
        preview_data.extend_from_slice(hash); //output hash
        let display_number = self.preview_output.len() as u16;
        preview_data.extend(display_number.to_be_bytes());

        //set 01 tag and length
        preview_data.insert(0, preview_data.len() as u8);
        preview_data.insert(0, 0x01);

        //use local private key sign data
        let key_manager_obj = KEY_MANAGER.lock();
        let mut output_pareper_data = secp256k1_sign(&key_manager_obj.pri_key, &preview_data)?;
        output_pareper_data.insert(0, output_pareper_data.len() as u8);
        output_pareper_data.insert(0, 0x00);
        output_pareper_data.extend(preview_data.iter());
        let btc_prepare_apdu_vec = BtcApdu::btc_prepare(0x4B, 0x00, &output_pareper_data);
        for temp_str in btc_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu(temp_str)?)?;
        }

        let mut page_number = 0;
        loop {
            let mut outputs_data = if self.is_sign_message {
                vec![0xFF, 0xFF]
            } else {
                self.serizalize_page_data(page_number, network)?
            };
            //set 01 tag and length
            outputs_data.insert(0, outputs_data.len() as u8);
            outputs_data.insert(0, 0x01);
            //use local private key sign data
            let mut output_pareper_data = secp256k1_sign(&key_manager_obj.pri_key, &outputs_data)?;
            output_pareper_data.insert(0, output_pareper_data.len() as u8);
            output_pareper_data.insert(0, 0x00);
            output_pareper_data.extend(outputs_data.iter());
            let sign_confirm = if self.is_sign_message {
                BtcApdu::btc_psbt_preview(&output_pareper_data, 0x80)
            } else {
                BtcApdu::btc_psbt_preview(&output_pareper_data, 0x00)
            };
            let response = &send_apdu_timeout(sign_confirm, TIMEOUT_LONG)?;
            ApduCheck::check_response(response)?;
            if response.len() > 4 {
                let page_index = &response[..response.len() - 4];
                page_number = u16::from_str_radix(page_index, 16)? as usize;
            } else {
                break;
            }
        }
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

    fn get_preview_output(&mut self) -> Result<()> {
        let mut preview_output: Vec<TxOut> = vec![];

        for tx_out in self.psbt.unsigned_tx.output.iter() {
            //remove empty and op_return TxOut
            if tx_out.script_pubkey.is_empty() || tx_out.script_pubkey.is_op_return() {
                continue;
            }
            //cale change index script
            let tx_out_script = &tx_out.script_pubkey;
            let address = if tx_out_script.is_p2pkh() {
                let change_path =
                    Self::get_change_index(self.network, constants::BTC_SEG_WIT_TYPE_LEGACY)?;
                let pub_key = BtcAddress::get_pub_key(&change_path)?;
                BtcAddress::from_public_key(
                    &pub_key,
                    self.network,
                    constants::BTC_SEG_WIT_TYPE_LEGACY,
                )?
            } else if tx_out_script.is_v0_p2wpkh() {
                let change_path =
                    Self::get_change_index(self.network, constants::BTC_SEG_WIT_TYPE_VERSION_0)?;
                let pub_key = BtcAddress::get_pub_key(&change_path)?;
                BtcAddress::from_public_key(
                    &pub_key,
                    self.network,
                    constants::BTC_SEG_WIT_TYPE_VERSION_0,
                )?
            } else if tx_out_script.is_p2sh() {
                let change_path =
                    Self::get_change_index(self.network, constants::BTC_SEG_WIT_TYPE_P2WPKH)?;
                let pub_key = BtcAddress::get_pub_key(&change_path)?;
                BtcAddress::from_public_key(
                    &pub_key,
                    self.network,
                    constants::BTC_SEG_WIT_TYPE_P2WPKH,
                )?
            } else if tx_out_script.is_v1_p2tr() {
                let change_path =
                    Self::get_change_index(self.network, constants::BTC_SEG_WIT_TYPE_VERSION_1)?;
                let pub_key = BtcAddress::get_pub_key(&change_path)?;
                BtcAddress::from_public_key(
                    &pub_key,
                    self.network,
                    constants::BTC_SEG_WIT_TYPE_VERSION_1,
                )?
            } else {
                continue;
            };
            //remove change TxOut
            let script_hex = Address::from_str(&address)?.script_pubkey().to_hex();
            if script_hex.eq(&tx_out.script_pubkey.to_hex()) {
                continue;
            }
            preview_output.push(tx_out.clone());
        }
        self.preview_output = preview_output;
        Ok(())
    }

    pub fn get_preview_info(&self) -> Result<(u64, u64, Vec<TxOut>)> {
        let outputs = &self.preview_output;
        let payment_total_amount = outputs.iter().map(|tx_out| tx_out.value).sum();
        let input_total_amount: u64 = self.prevouts.iter().map(|tx_out| tx_out.value).sum();
        let output_total_amount: u64 = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .map(|tx_out| tx_out.value)
            .sum();
        let fee = input_total_amount - output_total_amount;
        Ok((payment_total_amount, fee, outputs.clone()))
    }

    fn get_page_indices(total_number: usize, page_number: usize) -> Result<(usize, usize)> {
        let total_pages = (total_number + constants::BTC_PSBT_TRX_PER_PAGE_NUMBER - 1)
            / constants::BTC_PSBT_TRX_PER_PAGE_NUMBER;
        if page_number >= total_pages {
            return Err(anyhow!("page_number_out_of_range"));
        }
        let start_index = page_number * constants::BTC_PSBT_TRX_PER_PAGE_NUMBER;
        let end_index = usize::min(
            total_number,
            start_index + constants::BTC_PSBT_TRX_PER_PAGE_NUMBER,
        ) - 1;

        if start_index >= total_number {
            Ok((total_number, total_number - 1))
        } else if end_index >= total_number {
            Ok((start_index, total_number - 1))
        } else {
            Ok((start_index, end_index))
        }
    }

    fn serizalize_page_data(&self, page_number: usize, network: Network) -> Result<Vec<u8>> {
        let preview_output = &self.preview_output;
        let (start_index, end_index) = Self::get_page_indices(preview_output.len(), page_number)?;
        let mut data = vec![];
        data.extend((start_index as u16).to_be_bytes());
        data.extend((end_index as u16).to_be_bytes());
        for (index, output) in preview_output.iter().enumerate() {
            if start_index <= index && end_index >= index {
                let i_u16 = index as u16;
                data.extend(i_u16.to_be_bytes());
                data.extend(serialize(&output.value));
                let address = Address::from_script(&output.script_pubkey, network)?;
                let address_version = get_address_version(network, &address.to_string())?;
                let script_bytes = serialize(&output.script_pubkey);
                data.push((1 + script_bytes.len()) as u8);
                data.push(address_version);
                data.extend(script_bytes);
            }
        }

        Ok(data)
    }

    fn get_change_index(network: Network, segwit: &str) -> Result<String> {
        let network = match network {
            Network::Bitcoin => "MAINNET",
            _ => "TESTNET",
        };
        let coin_info = coin_info_from_param("BITCOIN", network, segwit, "secp256k1")?;
        let change_path = get_account_path(&coin_info.derivation_path)?;
        Ok(change_path)
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

    signer.get_preview_info()?;

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

        signer.tx_preview(Network::Bitcoin).unwrap();

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
