use crate::Result;
use bitcoin::psbt::Prevouts;
use bitcoin::util::sighash::{Annex, SighashCache};
use bitcoin::util::taproot::{TapLeafHash, TapSighashHash};
use bitcoin::{EcdsaSighashType, SchnorrSighashType, Script, Sighash, Transaction, TxOut};
use tcx_common::Hash256;

pub trait TxSignatureHasher {
    fn consensus_sighash_type(&self, base_type: u32) -> u32;
    fn segwit_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<Sighash>;

    fn legacy_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: u32,
    ) -> Result<Sighash>;

    fn taproot_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<TxOut>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSighashType,
    ) -> Result<TapSighashHash>;
}

impl TxSignatureHasher for SighashCache<Box<Transaction>> {
    fn consensus_sighash_type(&self, base_type: u32) -> u32 {
        base_type
    }

    fn segwit_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<Sighash> {
        Ok(self.segwit_signature_hash(input_index, script_code, value, sighash_type)?)
    }

    fn legacy_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: u32,
    ) -> Result<Sighash> {
        Ok(self.legacy_signature_hash(input_index, script_code, sighash_type)?)
    }

    fn taproot_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<TxOut>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSighashType,
    ) -> Result<TapSighashHash> {
        Ok(self.taproot_signature_hash(
            input_index,
            prevouts,
            annex,
            leaf_hash_code_separator,
            sighash_type,
        )?)
    }
}
