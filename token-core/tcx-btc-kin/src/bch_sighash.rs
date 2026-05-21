use crate::sighash::TxSignatureHasher;
use crate::{Error, Result};
use bitcoin::consensus::Encodable;
use bitcoin::io;
use bitcoin::sighash::{Annex, Prevouts};
use bitcoin::{EcdsaSighashType, Script, TapLeafHash, TapSighashType, Transaction, TxOut};
use bitcoin_hashes::{sha256d, Hash};

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
            let mut enc_prevouts = Vec::new();
            let mut enc_sequences = Vec::new();
            for txin in self.tx.input.iter() {
                txin.previous_output
                    .consensus_encode(&mut enc_prevouts)
                    .unwrap();
                txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
            }
            SegwitCache {
                prevouts: sha256d::Hash::hash(&enc_prevouts),
                sequences: sha256d::Hash::hash(&enc_sequences),
                outputs: {
                    let mut enc = Vec::new();
                    for txout in self.tx.output.iter() {
                        txout.consensus_encode(&mut enc).unwrap();
                    }
                    sha256d::Hash::hash(&enc)
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
    ) -> Result<[u8; 32]> {
        let enc =
            self.encode_signing_data_to(Vec::new(), input_index, script_code, value, sighash_type)?;
        Ok(sha256d::Hash::hash(&enc).to_byte_array())
    }

    pub fn encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: u32,
    ) -> Result<Write> {
        let zero_hash = sha256d::Hash::from_byte_array([0u8; 32]);

        let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;
        let base_type = EcdsaSighashType::from_consensus(sighash_type);

        self.tx.version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            writer.write_all(self.segwit_cache().prevouts.as_ref())?;
        } else {
            writer.write_all(zero_hash.as_ref())?;
        }

        if !anyone_can_pay
            && base_type != EcdsaSighashType::Single
            && base_type != EcdsaSighashType::None
        {
            writer.write_all(self.segwit_cache().sequences.as_ref())?;
        } else {
            writer.write_all(zero_hash.as_ref())?;
        }

        {
            let txin = &self.tx.input.get(input_index).ok_or(Error::InvalidUtxo)?;

            txin.previous_output.consensus_encode(&mut writer)?;
            script_code.consensus_encode(&mut writer)?;
            value.consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        }

        if base_type != EcdsaSighashType::Single && base_type != EcdsaSighashType::None {
            writer.write_all(self.segwit_cache().outputs.as_ref())?;
        } else if base_type == EcdsaSighashType::Single && input_index < self.tx.output.len() {
            let mut single_enc = Vec::new();
            self.tx.output[input_index].consensus_encode(&mut single_enc)?;
            writer.write_all(sha256d::Hash::hash(&single_enc).as_ref())?;
            // padding zero hash, copy form bitcoin core
        } else {
            writer.write_all(zero_hash.as_ref())?;
        }

        self.tx.lock_time.consensus_encode(&mut writer)?;
        sighash_type.consensus_encode(&mut writer)?;

        Ok(writer)
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
    ) -> Result<[u8; 32]> {
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
    ) -> Result<[u8; 32]> {
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
        _: TapSighashType,
    ) -> Result<[u8; 32]> {
        Err(Error::UnsupportedTaproot.into())
    }

    fn taproot_script_spend_signature_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<TxOut>,
        tap_leaf_hash: TapLeafHash,
        sighash_type: TapSighashType,
    ) -> Result<[u8; 32]> {
        Err(Error::UnsupportedTaproot.into())
    }
}
