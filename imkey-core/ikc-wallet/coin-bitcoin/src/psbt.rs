use crate::btcapi::{PsbtInput, PsbtOutput};
use crate::change_candidates::{
    bitcoin_network_id, psbt_change_path, send_change_candidates, SingleWalletChange,
    MAX_CHANGE_CANDIDATES,
};
use crate::common::{ensure_transaction_preview_version, get_xpub_data, select_btc_applet};
use crate::input_proof::{
    authenticated_transaction_chunk, check_previous_output, segwit_sign_apdu, send_input_proof,
    InputReceipt, TRANSACTION_CHUNK_BYTES,
};
use crate::multisig::{is_multisig_script_input, MultisigChangePolicy, MultisigSpend};
use crate::Result;
use anyhow::anyhow;
use bitcoin::blockdata::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY, OP_CODESEPARATOR,
};
use bitcoin::blockdata::script::{Builder, Instruction};
use bitcoin::consensus::{serialize, Decodable, Encodable};
use bitcoin::psbt::{Input, Psbt};
use bitcoin::util::bip32::DerivationPath;
use bitcoin::util::sighash::{Prevouts, SighashCache};
use bitcoin::util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapTweakHash};
use bitcoin::{
    EcdsaSig, EcdsaSighashType, Network, PublicKey, SchnorrSig, SchnorrSighashType, Script, TxOut,
    WPubkeyHash, Witness,
};
use bitcoin_hashes::{hash160, Hash};
use hex::FromHex;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::constants::{LC_MAX, MAX_UTXO_NUMBER, TIMEOUT_LONG};
use ikc_common::error::{ApduError, CoinError};
use ikc_common::path::check_path_validity;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_btc_apple_version;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::{
    ecdsa::Signature, schnorr::Signature as SchnorrSignature, Message,
    PublicKey as Secp256k1PublicKey, Secp256k1, XOnlyPublicKey,
};
use std::convert::TryFrom;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Mutex;

const PSBT_PREVIEW_MAX_BYTES: usize = 512;

enum PreviewState {
    Initial,
    InputsPrepared(Vec<InputReceipt>, Option<SingleWalletChange>),
    Confirmed(Vec<InputReceipt>),
}

enum TaprootSpend<'a> {
    Key {
        output_key: XOnlyPublicKey,
        tweak: TapTweakHash,
    },
    Script {
        leaf: TapLeafHash,
        script: &'a Script,
        control: &'a ControlBlock,
    },
}

pub struct PsbtSigner<'a> {
    psbt: &'a mut Psbt,
    derivation_path: String,
    auto_finalize: bool,
    prevouts: Vec<TxOut>,
    network: Network,
    preview_state: Mutex<PreviewState>,
    multisig_account: Mutex<Option<DerivationPath>>,
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
            multisig_account: Mutex::new(None),
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
        let finalized: Vec<bool> = (0..self.prevouts.len())
            .map(|index| self.verify_final_multisig(index))
            .collect::<Result<_>>()?;
        let last_pending = finalized.iter().rposition(|finished| !finished);
        for (idx, already_final) in finalized.into_iter().enumerate() {
            if already_final {
                continue;
            }
            let last = Some(idx) == last_pending;
            let prevout = &self.prevouts[idx];

            let completed = if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh(idx, &pub_keys[idx])?;
                if self.auto_finalize {
                    self.finalize_p2pkh(idx);
                }
                self.auto_finalize
            } else if is_multisig_script_input(&prevout.script_pubkey, &self.psbt.inputs[idx]) {
                self.sign_p2wsh(idx, &pub_keys[idx], &receipts[idx], last)?;
                self.auto_finalize && self.finalize_p2wsh(idx)?
            } else if prevout.script_pubkey.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh(idx, &pub_keys[idx], &receipts[idx], last)?;
                if self.auto_finalize {
                    self.finalize_p2sh_nested_p2wpkh(idx);
                }
                self.auto_finalize
            } else if prevout.script_pubkey.is_v0_p2wpkh() {
                self.sign_p2wpkh(idx, &pub_keys[idx], &receipts[idx], last)?;
                if self.auto_finalize {
                    self.finalize_p2wpkh(idx);
                }
                self.auto_finalize
            } else if prevout.script_pubkey.is_v1_p2tr() {
                self.sign_p2tr(idx, &pub_keys[idx], last)?
            } else {
                return Err(anyhow!("psbt_unsupported_input_script: input {}", idx));
            };

            if completed {
                self.clear_finalized_input(idx);
            }
        }

        // The legacy signing command takes an ordinal instead of an end flag.
        // Reselect only if its last pending input preceded an already-final one.
        if last_pending.map_or(true, |idx| {
            idx + 1 < self.prevouts.len() && self.prevouts[idx].script_pubkey.is_p2pkh()
        }) {
            select_btc_applet()?;
        }
        Ok(())
    }

    pub fn prevouts(&mut self) -> Result<()> {
        self.prevouts.clear();
        *self
            .multisig_account
            .get_mut()
            .map_err(|_| CoinError::InvalidUtxo)? = None;
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
        let mut pub_key_vec = Vec::with_capacity(self.prevouts.len());
        let mut account = self
            .multisig_account
            .lock()
            .map_err(|_| CoinError::InvalidUtxo)?;
        *account = None;
        let mut common_multisig_account = None;
        let mut same_multisig_account = true;
        for (idx, tx_out) in self.prevouts.iter().enumerate() {
            let input = &self.psbt.inputs[idx];
            let script = &tx_out.script_pubkey;
            if self.verify_final_multisig(idx)? {
                pub_key_vec.push(String::new());
            } else if script.is_v1_p2tr() {
                Self::taproot_sighash(input)?;
                let paths = self.taproot_paths(idx)?;
                let mut owned = None;
                for path in paths {
                    let key = Self::device_pub_key(&path)?;
                    if self
                        .taproot_spend(idx, &path, key.x_only_public_key().0)
                        .is_some()
                    {
                        owned = Some(key);
                        break;
                    }
                }
                let key = owned
                    .ok_or_else(|| anyhow!("psbt_no_supported_taproot_spend: input {}", idx))?;
                pub_key_vec.push(key.to_string());
            } else if is_multisig_script_input(script, input) {
                let spend = Self::multisig_spend_for_signing(input, script, idx)?;
                let network = bitcoin_network_id(self.network)?;
                let requested_path = if self.derivation_path.is_empty() {
                    DerivationPath::master()
                } else {
                    self.derivation_path.parse()?
                };
                let mut paths = spend.signing_paths(input, network, &requested_path);
                paths.sort_unstable();
                paths.dedup();
                let mut owned = None;
                for path in paths {
                    let public_key = Self::device_pub_key(&path.to_string())?;
                    if spend.signing_path(input, network, &public_key).as_ref() == Some(&path) {
                        let origin = DerivationPath::from(path.as_ref()[..4].to_vec());
                        owned = Some((public_key, origin));
                        break;
                    }
                }
                let (public_key, origin) =
                    owned.ok_or_else(|| anyhow!("psbt_no_device_multisig_key: input {}", idx))?;
                same_multisig_account &= common_multisig_account
                    .as_ref()
                    .map_or(true, |previous| *previous == origin);
                common_multisig_account = Some(origin);
                pub_key_vec.push(public_key.to_string());
            } else {
                let path = self.get_path(idx, script.is_v1_p2tr())?;
                pub_key_vec.push(Self::device_pub_key(&path)?.to_string());
            }
        }
        if same_multisig_account {
            *account = common_multisig_account;
        }
        Ok(pub_key_vec)
    }

    fn device_pub_key(path: &str) -> Result<Secp256k1PublicKey> {
        let xpub_data = get_xpub_data(path, false)?;
        let pub_key = xpub_data
            .get(..130)
            .ok_or_else(|| anyhow!("btc_invalid_device_public_key"))?;
        Ok(Secp256k1PublicKey::from_str(pub_key)?)
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

        let signature_obj = Self::ecdsa_response(&send_apdu(btc_sign_apdu)?)?;
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
        last: bool,
    ) -> Result<()> {
        let pub_key = PublicKey::from_str(pub_key)?;
        let witness_program = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(hash160::Hash::hash(
            &pub_key.to_bytes(),
        )));
        let script = witness_program
            .p2wpkh_script_code()
            .expect("must be v0_p2wpkh");
        let path = self.get_path(idx, false)?;
        self.sign_segwit_v0(idx, pub_key, &script, &path, receipt, last, false)
    }

    fn sign_p2wpkh(
        &mut self,
        idx: usize,
        pub_key: &str,
        receipt: &InputReceipt,
        last: bool,
    ) -> Result<()> {
        let script = self.prevouts[idx]
            .script_pubkey
            .p2wpkh_script_code()
            .expect("must be v0_p2wpkh");
        let path = self.get_path(idx, false)?;
        self.sign_segwit_v0(
            idx,
            PublicKey::from_str(pub_key)?,
            &script,
            &path,
            receipt,
            last,
            false,
        )
    }

    fn multisig_spend_for_signing<'b>(
        input: &'b Input,
        script: &Script,
        index: usize,
    ) -> Result<MultisigSpend<'b>> {
        if input.ecdsa_hash_ty().ok() != Some(EcdsaSighashType::All) {
            return Err(anyhow!(
                "psbt_unsupported_multisig_sighash: input {}",
                index
            ));
        }
        if input.sighash_type.is_some()
            && input
                .partial_sigs
                .values()
                .any(|sig| sig.hash_ty != EcdsaSighashType::All)
        {
            return Err(anyhow!(
                "psbt_conflicting_multisig_sighash: input {}",
                index
            ));
        }
        MultisigSpend::from_input(input, script)
            .ok_or_else(|| anyhow!("psbt_unsupported_multisig_script: input {}", index))
    }

    fn sign_p2wsh(
        &mut self,
        idx: usize,
        pub_key: &str,
        receipt: &InputReceipt,
        last: bool,
    ) -> Result<()> {
        let input = &self.psbt.inputs[idx];
        let spend =
            Self::multisig_spend_for_signing(input, &self.prevouts[idx].script_pubkey, idx)?;
        let pub_key = PublicKey::from_str(pub_key)?;
        let path = spend
            .signing_path(input, bitcoin_network_id(self.network)?, &pub_key.inner)
            .ok_or_else(|| anyhow!("psbt_no_device_multisig_key: input {}", idx))?;
        let script_code = spend.witness_script.clone();
        self.sign_segwit_v0(
            idx,
            pub_key,
            &script_code,
            &path.to_string(),
            receipt,
            last,
            true,
        )
    }

    fn sign_segwit_v0(
        &mut self,
        idx: usize,
        pub_key: PublicKey,
        script_code: &Script,
        path: &str,
        receipt: &InputReceipt,
        last: bool,
        verify_multisig: bool,
    ) -> Result<()> {
        let tx_in = &self.psbt.unsigned_tx.input[idx];
        let mut data = vec![0];
        data.extend(serialize(&tx_in.previous_output));
        data.extend(serialize(script_code));
        data.extend(self.prevouts[idx].value.to_le_bytes());
        data.extend(serialize(&tx_in.sequence));
        data[0] = u8::try_from(data.len() - 1)?;
        data.push(u8::try_from(path.len())?);
        data.extend(path.as_bytes());

        let command = segwit_sign_apdu(last, data, Some(receipt))?;
        let signature = Self::ecdsa_response(&send_apdu(command)?)?;
        if verify_multisig {
            let message = self.multisig_digest(idx, script_code)?;
            Secp256k1::verification_only()
                .verify_ecdsa(&message, &signature, &pub_key.inner)
                .map_err(|_| anyhow!("psbt_invalid_device_multisig_signature: input {}", idx))?;
        }
        self.psbt.inputs[idx]
            .partial_sigs
            .insert(pub_key, EcdsaSig::sighash_all(signature));
        Ok(())
    }

    fn ecdsa_response(response: &str) -> Result<Signature> {
        ApduCheck::check_response(response)?;
        let payload = hex::decode(response)?;
        if payload.len() != 68 {
            return Err(anyhow!("btc_invalid_ecdsa_signature_response"));
        }
        let mut signature = Signature::from_compact(&payload[1..65])?;
        signature.normalize_s();
        Ok(signature)
    }

    fn taproot_sighash(input: &Input) -> Result<SchnorrSighashType> {
        match input.schnorr_hash_ty()? {
            sighash @ (SchnorrSighashType::Default | SchnorrSighashType::All) => Ok(sighash),
            _ => Err(anyhow!("psbt_unsupported_taproot_sighash")),
        }
    }

    fn taproot_paths(&self, index: usize) -> Result<Vec<String>> {
        let origins = &self.psbt.inputs[index].tap_key_origins;
        if origins.is_empty() {
            return Ok(vec![self.get_path(index, true)?]);
        }
        let mut paths: Vec<_> = origins
            .values()
            .map(|(_, (_, path))| path.to_string())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        Ok(paths)
    }

    fn taproot_spend(
        &self,
        index: usize,
        path: &str,
        key: XOnlyPublicKey,
    ) -> Option<TaprootSpend<'_>> {
        let input = &self.psbt.inputs[index];
        let output = &self.prevouts[index].script_pubkey;
        let output_key = XOnlyPublicKey::from_slice(output.as_bytes().get(2..)?).ok()?;
        let secp = Secp256k1::verification_only();
        let origin = input.tap_key_origins.get(&key);
        if origin.map_or(!input.tap_key_origins.is_empty(), |(_, (_, key_path))| {
            key_path.to_string() != path
        }) {
            return None;
        }
        for (control, (script, version)) in &input.tap_scripts {
            let leaf = TapLeafHash::from_script(script, *version);
            if *version == LeafVersion::TapScript
                && control.leaf_version == *version
                && origin.map_or(true, |(leaves, _)| leaves.contains(&leaf))
                && tapleaf_signs_for_key(script, key)
                && control.verify_taproot_commitment(&secp, output_key, script)
            {
                return Some(TaprootSpend::Script {
                    leaf,
                    script,
                    control,
                });
            }
        }

        if origin.map_or(false, |(leaves, _)| !leaves.is_empty())
            || input
                .tap_internal_key
                .map_or(false, |internal| internal != key)
            || *output != Script::new_v1_p2tr(&secp, key, input.tap_merkle_root)
        {
            return None;
        }
        Some(TaprootSpend::Key {
            output_key,
            tweak: TapTweakHash::from_key_and_tweak(key, input.tap_merkle_root),
        })
    }

    fn sign_p2tr(&mut self, index: usize, pub_key: &str, last: bool) -> Result<bool> {
        let key = Secp256k1PublicKey::from_str(pub_key)?.x_only_public_key().0;
        let (path, spend) = self
            .taproot_paths(index)?
            .into_iter()
            .find_map(|path| {
                self.taproot_spend(index, &path, key)
                    .map(|spend| (path, spend))
            })
            .ok_or_else(|| anyhow!("psbt_no_supported_taproot_spend: input {}", index))?;
        let sighash = Self::taproot_sighash(&self.psbt.inputs[index])?;
        let leaf = match spend {
            TaprootSpend::Key { .. } => None,
            TaprootSpend::Script { leaf, .. } => Some(leaf),
        };

        // The applet fills version, verified inputs and confirmed outputs.
        let mut data = vec![0, sighash as u8];
        data.extend(serialize(&self.psbt.unsigned_tx.lock_time));
        data.push(if leaf.is_some() { 2 } else { 0 });
        data.extend((index as u32).to_le_bytes());
        if let Some(leaf) = leaf {
            data.push(37);
            data.extend_from_slice(&leaf[..]);
            data.push(0);
            data.extend(u32::MAX.to_le_bytes());
        }
        if path.is_empty()
            || data.len() + 1 + path.len() + if leaf.is_some() { 0 } else { 33 } > LC_MAX as usize
        {
            return Err(anyhow!("psbt_taproot_signing_request_too_long"));
        }
        data.push(u8::try_from(path.len())?);
        data.extend(path.as_bytes());
        let command = match spend {
            TaprootSpend::Key { tweak, .. } => {
                data.push(32);
                data.extend_from_slice(&tweak[..]);
                BtcApdu::btc_taproot_sign(last, data)
            }
            TaprootSpend::Script { .. } => BtcApdu::btc_taproot_script_sign(last, data),
        };

        let response = send_apdu(command)?;
        ApduCheck::check_response(&response)?;
        let payload = hex::decode(response)?;
        if payload.len() != 67 || payload[0] != 64 {
            return Err(anyhow!("psbt_invalid_taproot_signature_response"));
        }
        let sig = SchnorrSignature::from_slice(&payload[1..65])?;
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        let prevouts = Prevouts::All(&self.prevouts);
        let (digest, signing_key) = match spend {
            TaprootSpend::Key { output_key, .. } => (
                cache.taproot_key_spend_signature_hash(index, &prevouts, sighash)?,
                output_key,
            ),
            TaprootSpend::Script { leaf, .. } => (
                cache.taproot_script_spend_signature_hash(index, &prevouts, leaf, sighash)?,
                key,
            ),
        };
        Secp256k1::verification_only()
            .verify_schnorr(&sig, &Message::from_slice(&digest[..])?, &signing_key)
            .map_err(|_| anyhow!("psbt_invalid_device_taproot_signature: input {}", index))?;

        let signature = SchnorrSig {
            hash_ty: sighash,
            sig,
        };
        let mut witness = Witness::new();
        witness.push(signature.to_vec());
        let completed = match spend {
            TaprootSpend::Key { .. } => self.auto_finalize,
            TaprootSpend::Script {
                script, control, ..
            } => {
                if self.auto_finalize && is_single_checksig_leaf(script, key) {
                    witness.push(script.as_bytes());
                    witness.push(control.serialize());
                    true
                } else {
                    false
                }
            }
        };
        let input = &mut self.psbt.inputs[index];
        if let Some(leaf) = leaf {
            input.tap_script_sigs.insert((key, leaf), signature);
        } else {
            input.tap_key_sig = Some(signature);
        }
        if completed {
            input.final_script_witness = Some(witness);
        }
        Ok(completed)
    }

    pub fn calc_tx_hash(&self) -> Result<()> {
        self.calc_tx_hash_with_keys(&self.get_pub_key()?)
    }

    fn calc_tx_hash_with_keys(&self, pub_keys: &[String]) -> Result<()> {
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

        let single_wallet = (pub_keys.len() == inputs.len())
            .then_some(pub_keys)
            .and_then(|keys| {
                let paths: Vec<_> = self
                    .prevouts
                    .iter()
                    .zip(keys)
                    .enumerate()
                    .map(|(index, (prevout, public_key))| {
                        if !prevout.script_pubkey.is_v1_p2tr() {
                            return self.get_path(index, false).ok();
                        }
                        // BIP371 may list other keys ahead of the device's own key.
                        let key = public_key
                            .parse::<Secp256k1PublicKey>()
                            .ok()?
                            .x_only_public_key()
                            .0;
                        self.taproot_paths(index).ok()?.into_iter().find(|path| {
                            matches!(
                                self.taproot_spend(index, path, key),
                                Some(TaprootSpend::Key { .. })
                            )
                        })
                    })
                    .collect::<Option<_>>()?;
                SingleWalletChange::from_inputs(
                    self.network,
                    paths.iter().zip(&self.prevouts).zip(keys).map(
                        |((path, prevout), public_key)| {
                            (path.as_str(), &prevout.script_pubkey, public_key.as_str())
                        },
                    ),
                )
            });

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
        *state = PreviewState::InputsPrepared(receipts, single_wallet);
        Ok(())
    }

    pub fn tx_preview(&self, network: Network) -> Result<()> {
        let mut state = self
            .preview_state
            .lock()
            .map_err(|_| ApduError::ImkeyUserNotConfirmed)?;
        let (receipts, single_wallet) = match std::mem::replace(&mut *state, PreviewState::Initial)
        {
            PreviewState::InputsPrepared(receipts, single_wallet) => (receipts, single_wallet),
            _ => return Err(ApduError::ImkeyUserNotConfirmed.into()),
        };
        if network != self.network {
            return Err(CoinError::ImkeySdkIllegalArgument.into());
        }

        let transaction = &self.psbt.unsigned_tx;
        let network_id = bitcoin_network_id(network)?;
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

        let candidates: Vec<_> = transaction
            .output
            .iter()
            .zip(&self.psbt.outputs)
            .enumerate()
            .filter_map(|(index, (output, metadata))| {
                psbt_change_path(metadata, &output.script_pubkey, network, network_id)
                    .filter(|path| {
                        single_wallet
                            .as_ref()
                            .map_or(false, |policy| policy.allows(path))
                    })
                    .map(|path| (index, path))
            })
            .take(MAX_CHANGE_CANDIDATES)
            .collect();
        let mut remaining = MAX_CHANGE_CANDIDATES;
        if let Some(account) = self
            .multisig_account
            .lock()
            .map_err(|_| CoinError::InvalidUtxo)?
            .as_ref()
        {
            if let Some(policy) =
                MultisigChangePolicy::from_psbt(self.psbt, &self.prevouts, network, network_id)
            {
                remaining -= policy.send(network, account)?;
            }
        }
        if let Some(policy) = single_wallet.as_ref().filter(|_| !candidates.is_empty()) {
            policy.send()?;
        }
        send_change_candidates(network_id, candidates, remaining)?;

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

    fn multisig_digest(&self, index: usize, witness_script: &Script) -> Result<Message> {
        let digest = SighashCache::new(&self.psbt.unsigned_tx).segwit_signature_hash(
            index,
            witness_script,
            self.prevouts[index].value,
            EcdsaSighashType::All,
        )?;
        Ok(Message::from_slice(&digest[..])?)
    }

    fn verify_final_multisig(&self, index: usize) -> Result<bool> {
        let input = &self.psbt.inputs[index];
        let output = &self.prevouts[index].script_pubkey;
        let witness_script = input
            .final_script_witness
            .as_ref()
            .and_then(|witness| witness.iter().last())
            .map(|bytes| Script::from(bytes.to_vec()));
        let is_nested = output.is_p2sh()
            && witness_script
                .as_ref()
                .map_or(false, |script| script.to_v0_p2wsh().to_p2sh() == *output);
        if !is_nested && !is_multisig_script_input(output, input) {
            return Ok(false);
        }
        if input.final_script_sig.is_none() && input.final_script_witness.is_none() {
            return Ok(false);
        }

        let invalid = || anyhow!("psbt_invalid_final_multisig_input: input {}", index);
        let script = witness_script.as_ref().ok_or_else(invalid)?;
        let witness = input.final_script_witness.as_ref().ok_or_else(invalid)?;
        let program = is_nested.then(|| script.to_v0_p2wsh());
        let expected_scriptsig = program
            .as_ref()
            .map(|program| Builder::new().push_slice(program.as_bytes()).into_script());
        if input.final_script_sig != expected_scriptsig
            || input
                .witness_script
                .as_ref()
                .map_or(false, |known| known != script)
            || input
                .redeem_script
                .as_ref()
                .map_or(false, |known| Some(known) != program.as_ref())
            || input.ecdsa_hash_ty().ok() != Some(EcdsaSighashType::All)
        {
            return Err(invalid());
        }
        let spend = MultisigSpend::parse(output, script, program.as_ref()).ok_or_else(invalid)?;
        let mut stack = witness.iter();
        if witness.len() != spend.threshold + 2 || stack.next() != Some(&[][..]) {
            return Err(invalid());
        }
        let secp = Secp256k1::verification_only();
        let message = self.multisig_digest(index, script)?;
        let mut keys = spend.keys.iter();
        for raw in stack.take(spend.threshold) {
            let signature = EcdsaSig::from_slice(raw).map_err(|_| invalid())?;
            if signature.hash_ty != EcdsaSighashType::All
                || !keys.any(|key| secp.verify_ecdsa(&message, &signature.sig, key).is_ok())
            {
                return Err(invalid());
            }
        }
        Ok(true)
    }

    fn finalize_p2wsh(&mut self, index: usize) -> Result<bool> {
        let input = &self.psbt.inputs[index];
        let spend =
            Self::multisig_spend_for_signing(input, &self.prevouts[index].script_pubkey, index)?;
        let message = self.multisig_digest(index, spend.witness_script)?;
        let secp = Secp256k1::verification_only();
        let signatures: Vec<_> = spend
            .keys
            .iter()
            .filter_map(|key| {
                let signature = input.partial_sigs.get(&PublicKey::new(*key))?;
                (signature.hash_ty == EcdsaSighashType::All
                    && secp.verify_ecdsa(&message, &signature.sig, key).is_ok())
                .then_some(signature)
            })
            .take(spend.threshold)
            .collect();
        if signatures.len() != spend.threshold {
            return Ok(false);
        }
        let mut witness = Witness::new();
        witness.push([]);
        for signature in signatures {
            witness.push(signature.to_vec());
        }
        witness.push(spend.witness_script.as_bytes());
        let redeem_sig = input
            .redeem_script
            .as_ref()
            .map(|script| Builder::new().push_slice(script.as_bytes()).into_script());
        let input = &mut self.psbt.inputs[index];
        input.final_script_sig = redeem_sig;
        input.final_script_witness = Some(witness);
        Ok(true)
    }

    fn clear_finalized_input(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];
        *input = Input {
            non_witness_utxo: input.non_witness_utxo.take(),
            witness_utxo: input.witness_utxo.take(),
            final_script_sig: input.final_script_sig.take(),
            final_script_witness: input.final_script_witness.take(),
            unknown: std::mem::take(&mut input.unknown),
            proprietary: std::mem::take(&mut input.proprietary),
            ..Input::default()
        };
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

fn tapleaf_signs_for_key(script: &Script, key: XOnlyPublicKey) -> bool {
    let key = key.serialize();
    let mut previous_key = false;
    let mut checks_key = false;
    for instruction in script.instructions() {
        match instruction {
            Err(_) | Ok(Instruction::Op(OP_CODESEPARATOR)) => return false,
            Ok(Instruction::PushBytes(data)) => previous_key = data == key,
            Ok(Instruction::Op(op)) => {
                checks_key |=
                    previous_key && matches!(op, OP_CHECKSIG | OP_CHECKSIGVERIFY | OP_CHECKSIGADD);
                previous_key = false;
            }
        }
    }
    checks_key
}

fn is_single_checksig_leaf(script: &Script, key: XOnlyPublicKey) -> bool {
    let bytes = script.as_bytes();
    bytes.len() == 34
        && bytes[0] == 32
        && bytes[1..33] == key.serialize()
        && bytes[33] == OP_CHECKSIG.to_u8()
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

    signer.calc_tx_hash_with_keys(&pub_keys)?;

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
