use crate::Result;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Annex, Prevouts, SighashCache};
use bitcoin::{
    Amount, EcdsaSighashType, Script, SegwitV0Sighash, TapLeafHash, TapSighashType, Transaction,
    TxOut,
};

pub trait TxSignatureHasher {
    fn consensus_sighash_type(&self, base_type: u32) -> u32;
    fn segwit_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<[u8; 32]>;

    fn legacy_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: u32,
    ) -> Result<[u8; 32]>;

    fn taproot_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<TxOut>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: TapSighashType,
    ) -> Result<[u8; 32]>;

    fn taproot_script_spend_signature_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<TxOut>,
        tap_leaf_hash: TapLeafHash,
        sighash_type: TapSighashType,
    ) -> Result<[u8; 32]>;
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
    ) -> Result<[u8; 32]> {
        let mut enc = SegwitV0Sighash::engine();
        self.segwit_v0_encode_signing_data_to(
            &mut enc,
            input_index,
            script_code,
            Amount::from_sat(value),
            sighash_type,
        )?;
        Ok(SegwitV0Sighash::from_engine(enc).to_byte_array())
    }

    fn legacy_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        _: u64,
        sighash_type: u32,
    ) -> Result<[u8; 32]> {
        Ok(self
            .legacy_signature_hash(input_index, script_code, sighash_type)?
            .to_byte_array())
    }

    fn taproot_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<TxOut>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: TapSighashType,
    ) -> Result<[u8; 32]> {
        Ok(self
            .taproot_signature_hash(
                input_index,
                prevouts,
                annex,
                leaf_hash_code_separator,
                sighash_type,
            )?
            .to_byte_array())
    }

    fn taproot_script_spend_signature_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<TxOut>,
        tap_leaf_hash: TapLeafHash,
        sighash_type: TapSighashType,
    ) -> Result<[u8; 32]> {
        Ok(self
            .taproot_script_spend_signature_hash(
                input_index,
                &prevouts,
                tap_leaf_hash,
                sighash_type,
            )?
            .to_byte_array())
    }
}
