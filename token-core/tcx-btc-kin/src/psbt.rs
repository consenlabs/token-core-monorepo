use crate::bch_sighash::BitcoinCashSighash;
use crate::sighash::TxSignatureHasher;
use crate::transaction::{PsbtInput, PsbtOutput, PsbtsInput, PsbtsOutput};
use crate::{Error, Result, BITCOINCASH};
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::psbt::Prevouts;
use bitcoin::psbt::Psbt;
use bitcoin::schnorr::{TapTweak, UntweakedKeyPair};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::Message;
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::EcdsaSig;
use bitcoin::SchnorrSig;
use bitcoin::{EcdsaSighashType, SchnorrSighashType, Script, TxOut, WPubkeyHash, Witness};
use bitcoin_hashes::{hash160, Hash};
use std::collections::BTreeMap;
use std::io::Cursor;
use tcx_common::{FromHex, ToHex};
use tcx_constants::CurveType;
use tcx_keystore::Keystore;
use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, SECP256K1_ENGINE};

pub struct PsbtSigner<'a> {
    psbt: &'a mut Psbt,
    keystore: &'a mut Keystore,
    derivation_path: String,
    auto_finalize: bool,
    chain_type: String,

    prevouts: Vec<TxOut>,
    sighash_cache: Box<dyn TxSignatureHasher>,
}

impl<'a> PsbtSigner<'a> {
    pub fn new(
        psbt: &'a mut Psbt,
        keystore: &'a mut Keystore,
        chain_type: &str,
        derivation_path: &str,
        auto_finalize: bool,
    ) -> Self {
        let unsigned_tx = psbt.unsigned_tx.clone();

        let sighash_cache: Box<dyn TxSignatureHasher> = if chain_type == BITCOINCASH {
            Box::new(BitcoinCashSighash::new(unsigned_tx, 0x40))
        } else {
            Box::new(SighashCache::new(Box::new(unsigned_tx)))
        };

        PsbtSigner {
            psbt,
            keystore,
            derivation_path: derivation_path.to_string(),
            auto_finalize,
            chain_type: chain_type.to_owned(),

            sighash_cache,
            prevouts: Vec::new(),
        }
    }

    fn hash160(input: &[u8]) -> hash160::Hash {
        Hash::hash(input)
    }

    fn sign_ecdsa(data: &[u8], key: &Secp256k1PrivateKey) -> Result<Signature> {
        let msg = Message::from_slice(data)?;
        let sig = SECP256K1_ENGINE.sign_ecdsa(&msg, &key.0.inner);
        Ok(sig)
    }

    fn prevouts(&self) -> Result<Vec<TxOut>> {
        if self.psbt.inputs.is_empty()
            || self.psbt.inputs.len() != self.psbt.unsigned_tx.input.len()
        {
            return Err(Error::InvalidUtxo.into());
        }
        let mut utxos = Vec::with_capacity(self.psbt.inputs.len());
        for (input, tx_input) in self.psbt.inputs.iter().zip(&self.psbt.unsigned_tx.input) {
            let non_witness = if let Some(tx) = &input.non_witness_utxo {
                if tx.txid() != tx_input.previous_output.txid {
                    return Err(Error::InvalidUtxo.into());
                }
                Some(
                    tx.output
                        .get(tx_input.previous_output.vout as usize)
                        .ok_or(Error::InvalidUtxo)?,
                )
            } else {
                None
            };
            if let (Some(witness), Some(previous)) = (&input.witness_utxo, non_witness) {
                if witness != previous {
                    return Err(Error::InvalidUtxo.into());
                }
            }
            let utxo = input
                .witness_utxo
                .as_ref()
                .or(non_witness)
                .ok_or(Error::InvalidUtxo)?;
            // Legacy signatures do not commit to the input amount. Require the
            // complete previous transaction to authenticate that amount.
            if utxo.script_pubkey.is_p2pkh() && non_witness.is_none() {
                return Err(Error::InvalidUtxo.into());
            }
            utxos.push(utxo.clone());
        }
        let inputs = utxos.iter().try_fold(0u64, |sum, output| {
            sum.checked_add(output.value).ok_or(Error::InvalidUtxo)
        })?;
        let outputs = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .try_fold(0u64, |sum, output| {
                sum.checked_add(output.value).ok_or(Error::InvalidUtxo)
            })?;
        if outputs > inputs {
            return Err(Error::InvalidUtxo.into());
        }
        Ok(utxos)
    }

    fn validate_path(&self, path: &str) -> Result<()> {
        crate::signing_policy::validate_path(path, &self.chain_type, None)?;
        if !self.derivation_path.is_empty() {
            let account = format!("{}/0/0", self.derivation_path);
            crate::signing_policy::validate_path(&account, &self.chain_type, None)?;
            crate::signing_policy::same_account(path, &account)?;
        }
        Ok(())
    }

    fn get_private_key(&mut self, index: usize, is_p2tr: bool) -> Result<Secp256k1PrivateKey> {
        let input = &self.psbt.inputs[index];
        let origins: Vec<_> = if is_p2tr {
            input
                .tap_key_origins
                .iter()
                .map(|(key, (_, (_, path)))| (key.serialize().to_vec(), path.to_string()))
                .collect()
        } else {
            input
                .bip32_derivation
                .iter()
                .map(|(key, (_, path))| (key.serialize().to_vec(), path.to_string()))
                .collect()
        };
        for (claimed, path) in &origins {
            if self.keystore.derivable() {
                self.validate_path(path)?;
            }
            let key = self
                .keystore
                .get_private_key(CurveType::SECP256k1, path)?
                .as_secp256k1()?
                .clone();
            let public = key.public_key();
            let actual = if is_p2tr {
                public.0.inner.x_only_public_key().0.serialize().to_vec()
            } else {
                public.to_compressed()
            };
            if *claimed == actual {
                return Ok(key);
            }
        }
        if !origins.is_empty() {
            return Err(Error::InvalidUtxo.into());
        }
        let path = if self.keystore.derivable() {
            let path = format!("{}/0/0", self.derivation_path);
            self.validate_path(&path)?;
            path
        } else {
            String::new()
        };
        Ok(self
            .keystore
            .get_private_key(CurveType::SECP256k1, &path)?
            .as_secp256k1()?
            .clone())
    }

    fn validate_key(&self, index: usize, key: &Secp256k1PrivateKey) -> Result<()> {
        crate::signing_policy::validate_key(&self.prevouts[index].script_pubkey, key)
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
            let script = Builder::new().push_slice(&script.to_bytes()).into_script();
            input.final_script_sig = Some(script);

            let mut witness = Witness::new();
            witness.push(sig.1.to_vec());
            witness.push(sig.0.to_bytes());

            input.final_script_witness = Some(witness);
        }
    }

    fn finalize_p2tr(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];
        let mut witness = Witness::new();
        if input.tap_scripts.is_empty() {
            if let Some(signature) = input.tap_key_sig {
                witness.push(signature.to_vec());
                input.final_script_witness = Some(witness);
            }
        } else if let Some(((public_key, _), signature)) = input.tap_script_sigs.first_key_value() {
            let (control, (script, _)) = input.tap_scripts.first_key_value().unwrap();
            let bytes = script.as_bytes();
            if bytes.len() != 34
                || bytes[0] != 0x20
                || bytes[1..33] != public_key.serialize()
                || bytes[33] != 0xac
            {
                return;
            }
            witness.push(signature.to_vec());
            witness.push(script.as_bytes());
            witness.push(control.serialize());
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

    fn sign_p2pkh(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index, false)?;
        self.validate_key(index, &key)?;

        let prevout = &self.prevouts[index];

        let hash = self.sighash_cache.legacy_hash(
            index,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All.to_u32(),
        )?;

        let sig = Self::sign_ecdsa(&hash, &key)?;
        let mut public_key = key.public_key().0;
        if Script::new_p2pkh(&public_key.pubkey_hash()) != prevout.script_pubkey {
            public_key.compressed = false;
        }
        self.psbt.inputs[index].partial_sigs.clear();
        self.psbt.inputs[index]
            .partial_sigs
            .insert(public_key, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2sh_nested_p2wpkh(&mut self, index: usize) -> Result<()> {
        let prevout = &self.prevouts[index].clone();
        let key = self.get_private_key(index, false)?;
        self.validate_key(index, &key)?;
        let pub_key = key.public_key();

        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(Self::hash160(
            &pub_key.to_compressed(),
        )));

        let hash = self.sighash_cache.segwit_hash(
            index,
            &script.p2wpkh_script_code().expect("must be v0_p2wpkh"),
            prevout.value,
            EcdsaSighashType::All,
        )?;
        let sig = Self::sign_ecdsa(&hash, &key)?;

        self.psbt.inputs[index].partial_sigs.clear();
        self.psbt.inputs[index]
            .partial_sigs
            .insert(pub_key.0, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2wpkh(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index, false)?;
        self.validate_key(index, &key)?;
        let prevout = &self.prevouts[index];

        let hash = self.sighash_cache.segwit_hash(
            index,
            &prevout
                .script_pubkey
                .p2wpkh_script_code()
                .expect("must be v0_p2wpkh"),
            prevout.value,
            EcdsaSighashType::All,
        )?;
        let sig = Self::sign_ecdsa(&hash, &key)?;

        self.psbt.inputs[index].partial_sigs.clear();
        self.psbt.inputs[index]
            .partial_sigs
            .insert(key.public_key().0, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2tr(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index, true)?;
        let input = &self.psbt.inputs[index];
        let internal_key = key.public_key().0.inner.x_only_public_key().0;
        if input
            .tap_internal_key
            .map_or(false, |claimed| claimed != internal_key)
        {
            return Err(Error::InvalidUtxo.into());
        }
        let expected = Script::new_v1_p2tr(&SECP256K1_ENGINE, internal_key, input.tap_merkle_root);
        if expected != self.prevouts[index].script_pubkey {
            return Err(Error::InvalidUtxo.into());
        }
        let key_pair = UntweakedKeyPair::from_seckey_slice(&SECP256K1_ENGINE, &key.to_bytes())?
            .tap_tweak(&SECP256K1_ENGINE, input.tap_merkle_root);

        let hash = self.sighash_cache.taproot_hash(
            index,
            &Prevouts::All(self.prevouts.as_slice()),
            None,
            None,
            SchnorrSighashType::Default,
        )?;

        let msg = Message::from_slice(&hash[..])?;
        let sig = SECP256K1_ENGINE.sign_schnorr_no_aux_rand(&msg, &key_pair.to_inner());

        self.psbt.inputs[index].tap_key_sig = Some(SchnorrSig {
            hash_ty: SchnorrSighashType::Default,
            sig,
        });

        Ok(())
    }

    fn sign_p2tr_script(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index, true)?;

        let key_pair = UntweakedKeyPair::from_seckey_slice(&SECP256K1_ENGINE, &key.to_bytes())?;

        let input = self.psbt.inputs[index].clone();
        if input.tap_scripts.len() != 1 {
            return Err(Error::UnsupportedTaproot.into());
        }
        let (_, (script, leaf_version)) = input
            .tap_scripts
            .first_key_value()
            .ok_or(Error::InvalidUtxo)?;
        let (control_block, _) = input
            .tap_scripts
            .first_key_value()
            .ok_or(Error::InvalidUtxo)?;
        if *leaf_version != bitcoin::util::taproot::LeafVersion::TapScript
            || control_block.leaf_version != *leaf_version
        {
            return Err(Error::InvalidUtxo.into());
        }
        let output_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &self.prevouts[index].script_pubkey.as_bytes()[2..],
        )?;
        let signing_pubkey = key.public_key().0.inner.x_only_public_key().0.serialize();
        let contains_key = script.instructions().any(|instruction| {
            matches!(
                instruction, Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes))
                    if bytes == signing_pubkey
            )
        });
        if !control_block.verify_taproot_commitment(&SECP256K1_ENGINE, output_key, script)
            || !contains_key
        {
            return Err(Error::InvalidUtxo.into());
        }
        let hash = self.sighash_cache.taproot_script_spend_signature_hash(
            index,
            &Prevouts::All(&self.prevouts.clone()),
            TapLeafHash::from_script(script, *leaf_version),
            SchnorrSighashType::Default,
        )?;

        let msg = Message::from_slice(&hash[..])?;
        let sig = SECP256K1_ENGINE.sign_schnorr_no_aux_rand(&msg, &key_pair);
        let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
        let signing_key = key.public_key().0.inner.x_only_public_key().0;
        self.psbt.inputs[index].tap_script_sigs.clear();
        self.psbt.inputs[index].tap_script_sigs.insert(
            (signing_key, leaf_hash),
            SchnorrSig {
                hash_ty: SchnorrSighashType::Default,
                sig,
            },
        );

        Ok(())
    }

    pub fn sign(&mut self) -> Result<()> {
        self.prevouts = self.prevouts()?;

        for idx in 0..self.prevouts.len() {
            let prevout = &self.prevouts[idx];
            let input = &self.psbt.inputs[idx];
            if (prevout.script_pubkey.is_v1_p2tr()
                && input.schnorr_hash_ty()? != SchnorrSighashType::Default)
                || (!prevout.script_pubkey.is_v1_p2tr()
                    && input.ecdsa_hash_ty()? != EcdsaSighashType::All)
            {
                return Err(Error::InvalidUtxo.into());
            }

            if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh(idx)?;

                if self.auto_finalize {
                    self.finalize_p2pkh(idx);
                }
            } else if prevout.script_pubkey.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh(idx)?;

                if self.auto_finalize {
                    self.finalize_p2sh_nested_p2wpkh(idx);
                }
            } else if prevout.script_pubkey.is_v0_p2wpkh() {
                self.sign_p2wpkh(idx)?;

                if self.auto_finalize {
                    self.finalize_p2wpkh(idx);
                }
            } else if prevout.script_pubkey.is_v1_p2tr()
                && !self.psbt.inputs[idx].tap_scripts.is_empty()
            {
                self.sign_p2tr_script(idx)?;

                if self.auto_finalize {
                    self.finalize_p2tr(idx);
                }
            } else if prevout.script_pubkey.is_v1_p2tr() {
                self.sign_p2tr(idx)?;

                if self.auto_finalize {
                    self.finalize_p2tr(idx);
                }
            } else {
                return Err(Error::InvalidUtxo.into());
            }
            if self.auto_finalize
                && (self.psbt.inputs[idx].final_script_sig.is_some()
                    || self.psbt.inputs[idx].final_script_witness.is_some())
            {
                self.clear_finalized_input(idx);
            }
        }

        Ok(())
    }
}

pub fn sign_psbt(
    chain_type: &str,
    derivation_path: &str,
    keystore: &mut Keystore,
    psbt_input: PsbtInput,
) -> Result<PsbtOutput> {
    let mut psbt = Psbt::consensus_decode(&mut Cursor::new(Vec::<u8>::from_hex(psbt_input.psbt)?))?;

    let mut signer = PsbtSigner::new(
        &mut psbt,
        keystore,
        chain_type,
        derivation_path,
        psbt_input.auto_finalize,
    );
    signer.sign()?;

    let mut vec = Vec::new();
    psbt.consensus_encode(&mut vec)?;

    Ok(PsbtOutput { psbt: vec.to_hex() })
}

pub fn sign_psbts(
    chain_type: &str,
    derivation_path: &str,
    keystore: &mut Keystore,
    psbts_input: PsbtsInput,
) -> Result<PsbtsOutput> {
    let mut outputs = Vec::<String>::new();

    for item in psbts_input.psbts {
        let psbt_input = PsbtInput {
            psbt: item,
            auto_finalize: psbts_input.auto_finalize,
        };

        let output = sign_psbt(chain_type, derivation_path, keystore, psbt_input)?;
        outputs.push(output.psbt);
    }

    Ok(PsbtsOutput { psbts: outputs })
}

#[cfg(test)]
mod tests {
    use crate::psbt::PsbtSigner;
    use crate::tests::sample_hd_keystore;
    use crate::transaction::PsbtInput;
    use crate::BtcKinAddress;
    use bitcoin::consensus::Decodable;
    use bitcoin::psbt::Psbt;
    use bitcoin::schnorr::TapTweak;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::util::bip32::DerivationPath;
    use bitcoin::{Transaction, TxOut};
    use bitcoin_hashes::Hash;
    use std::io::Cursor;
    use std::str::FromStr;
    use tcx_common::FromHex;
    use tcx_constants::{CoinInfo, CurveType};

    #[test]
    fn test_sign_psbt_no_script() {
        let mut hd = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/86'/1'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "TESTNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
            contract_code: "".to_string(),
        };

        let _account = hd.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let psbt_input = PsbtInput {
            psbt: "70736274ff0100db0200000001fa4c8d58b9b6c56ed0b03f78115246c99eb70f99b837d7b4162911d1016cda340200000000fdffffff0350c30000000000002251202114eda66db694d87ff15ddd5d3c4e77306b6e6dd5720cbd90cd96e81016c2b30000000000000000496a47626274340066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229ec20acf33c17e5a6c92cced9f1d530cccab7aa3e53400456202f02fac95e9c481fa00d47b1700000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233d80f03000001012be3bf1d00000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c23301172066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e00000000".to_string(),
            auto_finalize: true,
        };

        let psbt_output = super::sign_psbt("BITCOIN", "m/86'/1'/0'", &mut hd, psbt_input).unwrap();
        let psbt = Psbt::consensus_decode(&mut Cursor::new(
            Vec::<u8>::from_hex(psbt_output.psbt).unwrap(),
        ))
        .unwrap();
        let tx = psbt.extract_tx();
        let sig = Signature::from_slice(&tx.input[0].witness.to_vec()[0]).unwrap();

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
        let secp = Secp256k1::verification_only();
        let tweak_pub_key = x_pub_key.tap_tweak(&secp, None);
        assert!(secp
            .verify_schnorr(&sig, &msg, &tweak_pub_key.0.to_inner())
            .is_ok());
    }

    #[test]
    fn rejects_nested_segwit_with_unbound_key_origin() {
        let mut hd = sample_hd_keystore();
        let psbt_input = PsbtInput {
            psbt: "70736274ff0100730200000001fe21f2749ecc542a7fb8d6bc136b531e74967b9efeb84f46ad7469861a9cba2e0200000000ffffffff02e80300000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca587e72301000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca5870000000000010120932901000000000017a914c38c28eed1988152d70c87163bbdcb41aad7cca5870104160014472fe3b898332a7069dbad917f1fab64e1524e3a220603fd595ab49fa4c6ab779d7415c6234ec85d5cac9ebdaea59be913b997524047e718000000003100008000000080000000800000000000000000000000".to_string(),
            auto_finalize: true,
        };
        assert_eq!(
            super::sign_psbt("BITCOIN", "m/49'/0'/0'", &mut hd, psbt_input)
                .unwrap_err()
                .to_string(),
            "invalid_utxo"
        );
    }

    fn make_psbt(script_pubkey: bitcoin::Script) -> Psbt {
        let previous = Transaction {
            version: 2,
            lock_time: bitcoin::PackedLockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: 10_000,
                script_pubkey,
            }],
        };
        let unsigned = Transaction {
            version: 2,
            lock_time: bitcoin::PackedLockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: previous.txid(),
                    vout: 0,
                },
                script_sig: bitcoin::Script::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: 9_000,
                script_pubkey: bitcoin::Script::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].witness_utxo = Some(previous.output[0].clone());
        psbt.inputs[0].non_witness_utxo = Some(previous);
        psbt
    }

    #[test]
    fn signs_bound_ecdsa_inputs_and_preserves_finalization() {
        use bitcoin::util::sighash::SighashCache;
        use bitcoin::{EcdsaSighashType, Script};
        for (purpose, kind) in [(44, 0), (49, 1), (84, 2)] {
            let mut hd = sample_hd_keystore();
            let path = format!("m/{purpose}'/1'/0'/0/0");
            let key = hd
                .get_public_key(CurveType::SECP256k1, &path)
                .unwrap()
                .as_secp256k1()
                .unwrap()
                .0;
            let witness_script = Script::new_v0_p2wpkh(&key.wpubkey_hash().unwrap());
            let script = match kind {
                0 => Script::new_p2pkh(&key.pubkey_hash()),
                1 => witness_script.to_p2sh(),
                _ => witness_script.clone(),
            };
            let mut psbt = make_psbt(script.clone());
            psbt.inputs[0].bip32_derivation.insert(
                key.inner,
                (Default::default(), DerivationPath::from_str(&path).unwrap()),
            );
            let unsigned = psbt.unsigned_tx.clone();
            let mut signer = PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", false);
            signer.sign().unwrap();
            let sig = psbt.inputs[0].partial_sigs.get(&key).unwrap();
            let mut cache = SighashCache::new(&unsigned);
            let digest = if kind == 0 {
                cache
                    .legacy_signature_hash(0, &script, EcdsaSighashType::All.to_u32())
                    .unwrap()
                    .into_inner()
            } else {
                cache
                    .segwit_signature_hash(
                        0,
                        &witness_script.p2wpkh_script_code().unwrap(),
                        10_000,
                        EcdsaSighashType::All,
                    )
                    .unwrap()
                    .into_inner()
            };
            Secp256k1::verification_only()
                .verify_ecdsa(&Message::from_slice(&digest).unwrap(), &sig.sig, &key.inner)
                .unwrap();
            let mut signer = PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", true);
            signer.sign().unwrap();
            assert!(psbt.inputs[0].partial_sigs.is_empty());
            assert!(
                psbt.inputs[0].final_script_sig.is_some()
                    || psbt.inputs[0].final_script_witness.is_some()
            );
        }
    }

    #[test]
    fn finalizes_uncompressed_p2pkh_with_the_committed_public_key() {
        use bitcoin::{util::sighash::SighashCache, EcdsaSighashType, Script};
        let mut hd = sample_hd_keystore();
        let path = "m/44'/1'/0'/0/0";
        let mut public = hd
            .get_public_key(CurveType::SECP256k1, path)
            .unwrap()
            .as_secp256k1()
            .unwrap()
            .0;
        public.compressed = false;
        let prevout_script = Script::new_p2pkh(&public.pubkey_hash());
        let mut psbt = make_psbt(prevout_script.clone());
        psbt.inputs[0].bip32_derivation.insert(
            public.inner,
            (Default::default(), DerivationPath::from_str(path).unwrap()),
        );
        let unsigned = psbt.unsigned_tx.clone();
        PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", true)
            .sign()
            .unwrap();
        let script_sig = psbt.inputs[0].final_script_sig.as_ref().unwrap();
        let pushes: Vec<_> = script_sig
            .instructions()
            .map(|instruction| match instruction.unwrap() {
                bitcoin::blockdata::script::Instruction::PushBytes(bytes) => bytes.to_vec(),
                _ => panic!("expected signature and public key pushes"),
            })
            .collect();
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[1].len(), 65);
        let final_public = bitcoin::PublicKey::from_slice(&pushes[1]).unwrap();
        assert_eq!(
            Script::new_p2pkh(&final_public.pubkey_hash()),
            prevout_script
        );
        let signature = bitcoin::EcdsaSig::from_slice(&pushes[0]).unwrap();
        let digest = SighashCache::new(&unsigned)
            .legacy_signature_hash(0, &prevout_script, EcdsaSighashType::All.to_u32())
            .unwrap()
            .into_inner();
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_slice(&digest).unwrap(),
                &signature.sig,
                &final_public.inner,
            )
            .unwrap();
    }

    #[test]
    fn rejects_forged_prevouts_and_key_origins_without_panicking() {
        use bitcoin::Script;
        let mut hd = sample_hd_keystore();
        let path = "m/84'/1'/0'/0/0";
        let key = hd
            .get_public_key(CurveType::SECP256k1, path)
            .unwrap()
            .as_secp256k1()
            .unwrap()
            .0;
        let mut valid = make_psbt(Script::new_v0_p2wpkh(&key.wpubkey_hash().unwrap()));
        valid.inputs[0].bip32_derivation.insert(
            key.inner,
            (Default::default(), DerivationPath::from_str(path).unwrap()),
        );
        for attack in 0..9 {
            let mut psbt = valid.clone();
            match attack {
                0 => psbt.unsigned_tx.input[0].previous_output.vout = u32::MAX,
                1 => psbt.inputs[0]
                    .non_witness_utxo
                    .as_mut()
                    .unwrap()
                    .output
                    .clear(),
                2 => psbt.inputs[0].witness_utxo.as_mut().unwrap().value = 20_000,
                3 => {
                    psbt.inputs[0]
                        .bip32_derivation
                        .values_mut()
                        .next()
                        .unwrap()
                        .1 = DerivationPath::from_str("m/84'/60'/0'/0/0").unwrap()
                }
                4 => {
                    psbt.inputs[0]
                        .bip32_derivation
                        .values_mut()
                        .next()
                        .unwrap()
                        .1 = DerivationPath::master()
                }
                5 => {
                    psbt.inputs[0]
                        .bip32_derivation
                        .values_mut()
                        .next()
                        .unwrap()
                        .1 = DerivationPath::from_str("m/84'/1'/0'/0/1").unwrap()
                }
                6 => {
                    psbt.inputs[0].bip32_derivation.clear();
                }
                7 => {
                    psbt.unsigned_tx.output[0].value = u64::MAX;
                }
                8 => {
                    let other = hd
                        .get_public_key(CurveType::SECP256k1, "m/84'/1'/0'/0/1")
                        .unwrap()
                        .as_secp256k1()
                        .unwrap()
                        .0;
                    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
                        Script::new_v0_p2wpkh(&other.wpubkey_hash().unwrap());
                    psbt.inputs[0].non_witness_utxo = None;
                }
                _ => unreachable!(),
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", false).sign()
            }));
            assert!(result.unwrap().is_err(), "attack {attack}");
            assert!(psbt.inputs[0].partial_sigs.is_empty());
        }
    }

    #[test]
    fn rejects_unauthenticated_legacy_prevout() {
        let mut hd = sample_hd_keystore();
        let path = "m/44'/1'/0'/0/0";
        let key = hd
            .get_public_key(CurveType::SECP256k1, path)
            .unwrap()
            .as_secp256k1()
            .unwrap()
            .0;
        let mut psbt = make_psbt(bitcoin::Script::new_p2pkh(&key.pubkey_hash()));
        psbt.inputs[0].non_witness_utxo = None;
        psbt.inputs[0].bip32_derivation.insert(
            key.inner,
            (Default::default(), DerivationPath::from_str(path).unwrap()),
        );
        assert!(PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", false)
            .sign()
            .is_err());
    }

    #[test]
    fn taproot_key_path_commits_to_supplied_merkle_root() {
        use bitcoin::{
            psbt::Prevouts, schnorr::TapTweak, util::sighash::SighashCache,
            util::taproot::TaprootBuilder, SchnorrSighashType,
        };
        let mut hd = sample_hd_keystore();
        let path = "m/86'/1'/0'/0/0";
        let key = hd
            .get_public_key(CurveType::SECP256k1, path)
            .unwrap()
            .as_secp256k1()
            .unwrap()
            .0
            .inner
            .x_only_public_key()
            .0;
        let script = bitcoin::blockdata::script::Builder::new()
            .push_x_only_key(&key)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script();
        let spend = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&Secp256k1::new(), key)
            .unwrap();
        let mut psbt = make_psbt(bitcoin::Script::new_v1_p2tr_tweaked(spend.output_key()));
        psbt.inputs[0].tap_internal_key = Some(key);
        psbt.inputs[0].tap_merkle_root = spend.merkle_root();
        psbt.inputs[0].tap_key_origins.insert(
            key,
            (
                vec![],
                (Default::default(), DerivationPath::from_str(path).unwrap()),
            ),
        );
        let mut invalid = psbt.clone();
        invalid.inputs[0].tap_merkle_root = None;
        assert!(PsbtSigner::new(&mut invalid, &mut hd, "BITCOIN", "", false)
            .sign()
            .is_err());
        let previous = psbt.inputs[0].witness_utxo.clone().unwrap();
        PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", false)
            .sign()
            .unwrap();
        let digest = SighashCache::new(&psbt.unsigned_tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[previous]),
                SchnorrSighashType::Default,
            )
            .unwrap()
            .into_inner();
        let output_key = key
            .tap_tweak(&Secp256k1::verification_only(), spend.merkle_root())
            .0;
        Secp256k1::verification_only()
            .verify_schnorr(
                &psbt.inputs[0].tap_key_sig.unwrap().sig,
                &Message::from_slice(&digest).unwrap(),
                &output_key.to_inner(),
            )
            .unwrap();
    }

    #[test]
    fn rejects_mismatched_and_future_taproot_leaf_versions() {
        use bitcoin::{
            util::taproot::{LeafVersion, TaprootBuilder},
            Script,
        };
        let mut hd = sample_hd_keystore();
        let path = "m/86'/1'/0'/0/0";
        let key = hd
            .get_public_key(CurveType::SECP256k1, path)
            .unwrap()
            .as_secp256k1()
            .unwrap()
            .0
            .inner
            .x_only_public_key()
            .0;
        let script = bitcoin::blockdata::script::Builder::new()
            .push_x_only_key(&key)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script();
        let future = LeafVersion::from_consensus(0xc2).unwrap();
        for (control_version, tuple_version, allowed) in [
            (LeafVersion::TapScript, LeafVersion::TapScript, true),
            (LeafVersion::TapScript, future, false),
            (future, future, false),
        ] {
            let spend = TaprootBuilder::new()
                .add_leaf_with_ver(0, script.clone(), control_version)
                .unwrap()
                .finalize(&Secp256k1::new(), key)
                .unwrap();
            let control = spend
                .control_block(&(script.clone(), control_version))
                .unwrap();
            assert!(control.verify_taproot_commitment(
                &Secp256k1::verification_only(),
                spend.output_key().to_inner(),
                &script
            ));
            let mut psbt = make_psbt(Script::new_v1_p2tr_tweaked(spend.output_key()));
            psbt.inputs[0]
                .tap_scripts
                .insert(control, (script.clone(), tuple_version));
            psbt.inputs[0].tap_key_origins.insert(
                key,
                (
                    vec![],
                    (Default::default(), DerivationPath::from_str(path).unwrap()),
                ),
            );
            let result = PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", true).sign();
            assert_eq!(result.is_ok(), allowed);
            if !allowed {
                assert!(psbt.inputs[0].tap_script_sigs.is_empty());
                assert!(psbt.inputs[0].final_script_witness.is_none());
            }
        }
    }

    #[test]
    fn signs_taproot_script_only_when_committed_and_key_is_present() {
        use bitcoin::{
            util::taproot::{LeafVersion, TaprootBuilder},
            Script,
        };
        let mut hd = sample_hd_keystore();
        let path = "m/86'/1'/0'/0/0";
        let key = hd
            .get_public_key(CurveType::SECP256k1, path)
            .unwrap()
            .as_secp256k1()
            .unwrap()
            .0
            .inner
            .x_only_public_key()
            .0;
        let script = bitcoin::blockdata::script::Builder::new()
            .push_x_only_key(&key)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script();
        let spend = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&Secp256k1::new(), key)
            .unwrap();
        let control = spend
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap();
        let mut valid = make_psbt(Script::new_v1_p2tr_tweaked(spend.output_key()));
        valid.inputs[0]
            .tap_scripts
            .insert(control, (script, LeafVersion::TapScript));
        valid.inputs[0].tap_key_origins.insert(
            key,
            (
                vec![],
                (Default::default(), DerivationPath::from_str(path).unwrap()),
            ),
        );
        for forged in [false, true] {
            let mut psbt = valid.clone();
            if forged {
                let entry = psbt.inputs[0].tap_scripts.first_entry().unwrap();
                let (script, _) = entry.into_mut();
                *script = Script::new();
            }
            let result = PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", true).sign();
            assert_eq!(result.is_ok(), !forged);
        }
    }
}
