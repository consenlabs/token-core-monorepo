use crate::bch_sighash::BitcoinCashSighash;
use crate::sighash::TxSignatureHasher;
use crate::transaction::{PsbtInput, PsbtOutput};
use crate::{Error, Result, BITCOINCASH};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::psbt::{Prevouts, Psbt};
use bitcoin::schnorr::TapTweak;
use bitcoin::util::bip32::KeySource;
use bitcoin::util::sighash::SighashCache;
use bitcoin::{
    EcdsaSig, EcdsaSighashType, SchnorrSig, SchnorrSighashType, Script, TxOut, WPubkeyHash, Witness,
};
use bitcoin_hashes::{hash160, Hash};
use secp256k1::ecdsa::Signature;
use secp256k1::Message;
use std::collections::BTreeMap;
use std::io::Cursor;
use tcx_common::{FromHex, ToHex};
use tcx_constants::CurveType;
use tcx_keystore::Keystore;
use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, SECP256K1_ENGINE};

pub struct PsbtSigner<'a> {
    psbt: &'a mut Psbt,
    keystore: &'a mut Keystore,

    prevouts: Vec<TxOut>,
    sighash_cache: Box<dyn TxSignatureHasher>,
}

impl<'a> PsbtSigner<'a> {
    pub fn new(psbt: &'a mut Psbt, keystore: &'a mut Keystore, chain_type: &str) -> Self {
        let unsigned_tx = &psbt.unsigned_tx;

        let sighash_cache: Box<dyn TxSignatureHasher> = if chain_type == BITCOINCASH {
            Box::new(BitcoinCashSighash::new(unsigned_tx.clone(), 0x40))
        } else {
            Box::new(SighashCache::new(Box::new(unsigned_tx.clone())))
        };

        PsbtSigner {
            psbt,
            keystore,
            sighash_cache,
            prevouts: Vec::new(),
        }
    }

    fn hash160(&self, input: &[u8]) -> hash160::Hash {
        hash160::Hash::hash(input)
    }

    fn sign_ecdsa(data: &[u8], key: &Secp256k1PrivateKey) -> Result<Signature> {
        let msg = Message::from_slice(data)?;
        let sig = SECP256K1_ENGINE.sign_ecdsa(&msg, &key.0.inner);
        Ok(sig)
    }

    fn prevouts(&self) -> Result<Vec<TxOut>> {
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
                return Err(Error::InvalidUtxo.into());
            };
            utxos.push(utxo.clone());
        }

        Ok(utxos)
    }

    fn get_private_key(&mut self, index: usize) -> Result<Secp256k1PrivateKey> {
        let key_sources: Vec<&KeySource> =
            self.psbt.inputs[index].bip32_derivation.values().collect();
        let path = if key_sources.len() > 0 {
            key_sources[0].1.to_string()
        } else {
            "".to_string()
        };

        if self.keystore.derivable() {
            Ok(self
                .keystore
                .get_private_key(CurveType::SECP256k1, &path)?
                .as_secp256k1()?
                .clone())
        } else {
            Ok(self
                .keystore
                .get_private_key(CurveType::SECP256k1, &path)?
                .as_secp256k1()?
                .clone())
        }
    }

    fn sign_p2pkh(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index)?;

        let prevout = &self.prevouts[index];

        let hash = self.sighash_cache.legacy_hash(
            index,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All.to_u32(),
        )?;

        let sig = Self::sign_ecdsa(&hash, &key)?;
        self.psbt.inputs[index]
            .partial_sigs
            .insert(key.public_key().0, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2sh_nested_p2wpkh(&mut self, index: usize) -> Result<()> {
        let prevout = &self.prevouts[index].clone();
        let key = self.get_private_key(index)?;
        let pub_key = key.public_key();

        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(
            self.hash160(&pub_key.to_compressed()),
        ));

        let hash = self.sighash_cache.segwit_hash(
            index,
            &script.p2wpkh_script_code().expect("must be v0_p2wpkh"),
            prevout.value,
            EcdsaSighashType::All,
        )?;
        let sig = Self::sign_ecdsa(&hash, &key)?;

        self.psbt.inputs[index]
            .partial_sigs
            .insert(pub_key.0, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2wpkh(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index)?;
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
        self.psbt.inputs[index]
            .partial_sigs
            .insert(key.public_key().0, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2tr(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index)?;

        let key_pair = bitcoin::schnorr::UntweakedKeyPair::from_seckey_slice(
            &SECP256K1_ENGINE,
            &key.to_bytes(),
        )?
        .tap_tweak(&SECP256K1_ENGINE, None);

        let hash = self.sighash_cache.taproot_hash(
            index,
            &Prevouts::All(&self.prevouts.clone()),
            None,
            None,
            SchnorrSighashType::Default,
        )?;

        let msg = Message::from_slice(&hash[..])?;
        let sig = SECP256K1_ENGINE.sign_schnorr(&msg, &key_pair.to_inner());

        self.psbt.inputs[index].tap_key_sig = Some(SchnorrSig {
            hash_ty: SchnorrSighashType::Default,
            sig,
        });

        Ok(())
    }

    fn sign(&mut self) -> Result<()> {
        self.prevouts = self.prevouts()?;

        for idx in 0..self.prevouts.len() {
            let prevout = &self.prevouts[idx];

            if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh(idx)?;
            } else if prevout.script_pubkey.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh(idx)?;
            } else if prevout.script_pubkey.is_v0_p2wpkh() {
                self.sign_p2wpkh(idx)?;
            } else if prevout.script_pubkey.is_v1_p2tr() {
                self.sign_p2tr(idx)?;
            }
        }

        Ok(())
    }
}

pub fn sign_psbt(keystore: &mut Keystore, psbt_input: PsbtInput) -> Result<PsbtOutput> {
    let mut reader = Cursor::new(Vec::<u8>::from_hex(psbt_input.data)?);
    let mut psbt = Psbt::consensus_decode(&mut reader)?;

    let mut signer = PsbtSigner::new(&mut psbt, keystore, &psbt_input.chain_type);
    signer.sign()?;

    // FINALIZER
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();

        if input.tap_key_sig.is_some() {
            script_witness.push(input.tap_key_sig.unwrap().to_vec());
            input.final_script_witness = Some(script_witness);

            // Clear all the data fields as per the spec.
            input.partial_sigs = BTreeMap::new();
            input.sighash_type = None;
            input.redeem_script = None;
            input.witness_script = None;
            input.bip32_derivation = BTreeMap::new();
        }
    });

    println!("psbt: {:?}", psbt.inputs);

    let mut vec = Vec::<u8>::new();
    let mut writer = Cursor::new(&mut vec);
    psbt.consensus_encode(&mut writer)?;

    return Ok(PsbtOutput { data: vec.to_hex() });
}

#[cfg(test)]
mod tests {
    use crate::tests::sample_hd_keystore;
    use crate::transaction::PsbtInput;

    #[test]
    fn test_sign_psbt() {
        let mut hd = sample_hd_keystore();

        let psbt_input = PsbtInput {
            data: "70736274ff0100db02000000017e4e5ccaa5a84f4e2761816d948db0530283d2ddab9e2b0bf14432247177b67c0000000000fdffffff0350c30000000000002251202f03f11af54df4be96db1c8d6ee9ab2a29558479ff93ad019d182deed8f8c33d0000000000000000496a4762627434001fa696928d908ffd29c2ab9ebf8ad48946bf9d57b64c2e4f588988c830bd2571f4940b238dcd00535fde9730345bab6ff4ea6d413cc3602c4033c10f251c7e81fa0057620000000000002251206649a3708d5510aeb8140ffb6ed5866db64b817ea62902628ad7d04730484aab080803000001012bf4260100000000002251206649a3708d5510aeb8140ffb6ed5866db64b817ea62902628ad7d04730484aab0117201fa696928d908ffd29c2ab9ebf8ad48946bf9d57b64c2e4f588988c830bd257100000000".to_string(),
            chain_type: "BITCOIN".to_string(),
        };

        let result = super::sign_psbt(&mut hd, psbt_input).unwrap();
        assert_eq!(result.data, "70736274ff0100db02000000017e4e5ccaa5a84f4e2761816d948db0530283d2ddab9e2b0bf14432247177b67c0000000000fdffffff0350c30000000000002251202f03f11af54df4be96db1c8d6ee9ab2a29558479ff93ad019d182deed8f8c33d0000000000000000496a4762627434001fa696928d908ffd29c2ab9ebf8ad48946bf9d57b64c2e4f588988c830bd2571f4940b238dcd00535fde9730345bab6ff4ea6d413cc3602c4033c10f251c7e81fa0057620000000000002251206649a3708d5510aeb8140ffb6ed5866db64b817ea62902628ad7d04730484aab080803000001012bf4260100000000002251206649a3708d5510aeb8140ffb6ed5866db64b817ea62902628ad7d04730484aab0117201fa696928d908ffd29c2ab9ebf8ad48946bf9d57b64c2e4f588988c830bd257100000000");
    }
}
