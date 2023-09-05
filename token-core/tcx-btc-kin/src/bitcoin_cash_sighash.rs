use crate::sighash::TxSignatureHasher;
use crate::{Error, Result};
use bitcoin::consensus::Encodable;
use bitcoin::psbt::Prevouts;
use bitcoin::util::sighash::Annex;
use bitcoin::util::taproot::{TapLeafHash, TapSighashHash};
use bitcoin::{EcdsaSighashType, SchnorrSighashType, Script, Sighash, Transaction, TxOut};
use bitcoin_hashes::{sha256d, Hash};
use std::io;
use std::io::Cursor;
use tcx_common::Hash256;

pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// Bitcoin Cash sighash flag for use on outputs after the fork

pub struct BitcoinCashSighash {
    tx: Transaction,
    fork_id: u32,
    segwit_cache: Option<SegwitCache>,
}

#[derive(Debug)]
struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,

    /// In theory `outputs` could be an `Option` since `SIGHASH_NONE` and `SIGHASH_SINGLE` do not
    /// need it, but since `SIGHASH_ALL` is by far the most used variant we don't bother.
    outputs: sha256d::Hash,
}
impl BitcoinCashSighash {
    fn segwit_cache(&mut self) -> &SegwitCache {
        self.segwit_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256d::Hash::engine();
            let mut enc_sequences = sha256d::Hash::engine();
            for txin in self.tx.input.iter() {
                txin.previous_output
                    .consensus_encode(&mut enc_prevouts)
                    .unwrap();
                txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
            }
            SegwitCache {
                prevouts: sha256d::Hash::from_engine(enc_prevouts),
                sequences: sha256d::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha256d::Hash::engine();
                    for txout in self.tx.output.iter() {
                        txout.consensus_encode(&mut enc).unwrap();
                    }
                    sha256d::Hash::from_engine(enc)
                },
            }
        })
    }

    pub fn new(tx: Transaction, fork_id: u32) -> Self {
        BitcoinCashSighash {
            tx,
            fork_id,
            segwit_cache: None,
        }
    }

    pub fn signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: u32,
    ) -> Result<Sighash> {
        let mut enc = Sighash::engine();
        self.encode_signing_data_to(&mut enc, input_index, script_code, value, sighash_type)?;
        Ok(Sighash::from_engine(enc))
    }

    pub fn encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: u32,
    ) -> Result<()> {
        let zero_hash = sha256d::Hash::all_zeros();

        let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;
        let base_type = EcdsaSighashType::from_consensus(sighash_type);

        self.tx.version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        if !anyone_can_pay
            && base_type != EcdsaSighashType::Single
            && base_type != EcdsaSighashType::None
        {
            self.segwit_cache()
                .sequences
                .consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        {
            let txin = &self.tx.input.get(input_index).ok_or(
                bitcoin::util::sighash::Error::IndexOutOfInputsBounds {
                    index: input_index,
                    inputs_size: self.tx.input.len(),
                },
            )?;

            txin.previous_output.consensus_encode(&mut writer)?;
            script_code.consensus_encode(&mut writer)?;
            value.consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        }

        if base_type != EcdsaSighashType::Single && base_type != EcdsaSighashType::None {
            self.segwit_cache().outputs.consensus_encode(&mut writer)?;
        } else if base_type == EcdsaSighashType::Single && input_index < self.tx.output.len() {
            let mut single_enc = Sighash::engine();
            self.tx.output[input_index].consensus_encode(&mut single_enc)?;
            Sighash::from_engine(single_enc).consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        self.tx.lock_time.consensus_encode(&mut writer)?;
        sighash_type.consensus_encode(&mut writer)?;

        Ok(())
    }
}

impl TxSignatureHasher for BitcoinCashSighash {
    fn consensus_sighash_type(&self, base_type: u32) -> u32 {
        base_type | self.fork_id
    }

    fn segwit_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<Sighash> {
        self.signature_hash(
            input_index,
            script_code,
            value,
            self.consensus_sighash_type(sighash_type.to_u32()),
        )
    }

    fn legacy_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: u32,
    ) -> Result<Sighash> {
        self.signature_hash(
            input_index,
            script_code,
            value,
            self.consensus_sighash_type(sighash_type),
        )
    }

    fn taproot_hash(
        &mut self,
        _: usize,
        _: &Prevouts<TxOut>,
        _: Option<Annex>,
        _: Option<(TapLeafHash, u32)>,
        _: SchnorrSighashType,
    ) -> Result<TapSighashHash> {
        Err(Error::UnsupportedTaproot.into())
    }
}
