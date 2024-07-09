use crate::Result;
use crate::btcapi::{PsbtInput, PsbtOutput};
use bitcoin::consensus::{Decodable, Encodable, serialize};
use bitcoin::psbt::{Prevouts, Psbt};
use bitcoin::schnorr::{TapTweak, UntweakedPublicKey};
use bitcoin::util::bip32::KeySource;
use bitcoin::util::sighash::SighashCache;
use bitcoin::{EcdsaSig, EcdsaSighashType, SchnorrSig, SchnorrSighashType, Script, TxOut, WPubkeyHash, Witness, Address, Transaction, TxIn, OutPoint, Sequence};
use bitcoin_hashes::{hash160, Hash};
use secp256k1::ecdsa::Signature;
use secp256k1::Message;
use std::collections::BTreeMap;
use std::io::Cursor;
use bitcoin::blockdata::script::Builder;
use bitcoin::util::taproot::TapTweakHash;
use hex::FromHex;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::error::CoinError;
use ikc_common::utility::hex_to_bytes;
use ikc_transport::message::send_apdu;
use crate::transaction::Utxo;


pub struct PsbtSigner<'a> {
    psbt: &'a mut Psbt,
    derivation_path: String,
    prevouts: Vec<TxOut>,
}

impl<'a> PsbtSigner<'a> {
    pub fn new(
        psbt: &'a mut Psbt,
        derivation_path: &str,
    ) -> Self {

        PsbtSigner {
            psbt,
            derivation_path: derivation_path.to_string(),
            prevouts: Vec::new(),
        }
    }

    fn prevouts(&mut self) -> Result<()> {
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

    fn sign(&mut self) -> Result<()> {
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

    fn get_path(&mut self, index: usize) -> Result<String> {
        let input = &self.psbt.inputs[index];
        let bip32_derivations: Vec<&KeySource> = input.bip32_derivation.values().collect();

        let path = if !bip32_derivations.is_empty() {
            bip32_derivations[0].1.to_string()
        } else if !self.derivation_path.is_empty() {
            self.derivation_path.clone() + "/0/0"
        } else {
            "".to_string()
        };
        Ok(path)
    }

    fn sign_p2pkh_input(
        &self,
        idx: usize,
        pub_key: &str,
        transaction: &mut Transaction,
    ) -> Result<()> {
        let mut input_data_vec = vec![];
        for (x, temp_utxo) in self.unspents.iter().enumerate() {
            let mut temp_serialize_txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(temp_utxo.txhash.as_str())?,
                    vout: temp_utxo.vout as u32,
                },
                script_sig: Script::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };
            if (x == idx) {
                temp_serialize_txin.script_sig =
                    Script::from(Vec::from_hex(temp_utxo.script_pubkey.as_str())?);
            }

            input_data_vec.extend_from_slice(serialize(&temp_serialize_txin).as_slice());
        }
        let btc_perpare_apdu_list = BtcApdu::btc_single_utxo_sign_prepare(0x46, &input_data_vec);
        for apdu in btc_perpare_apdu_list {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }

        let btc_sign_apdu = BtcApdu::btc_single_utxo_sign(
            idx as u8,
            EcdsaSighashType::All.to_u32() as u8,
            self.unspents.get(idx).unwrap().derive_path.as_str(),
        );

        let btc_sign_apdu_return = send_apdu(btc_sign_apdu)?;
        ApduCheck::check_response(&btc_sign_apdu_return)?;
        let btc_sign_apdu_return =
            &btc_sign_apdu_return[..btc_sign_apdu_return.len() - 4].to_string();
        let sign_result_str = btc_sign_apdu_return[2..btc_sign_apdu_return.len() - 2].to_string();

        let mut signature_obj = Signature::from_compact(&hex::decode(&sign_result_str)?)?;
        signature_obj.normalize_s();

        let script_sig = self.build_unlock_script(sign_result_str.as_str(), pub_key)?;
        let tx_in = TxIn {
            previous_output: OutPoint {
                txid: bitcoin::hash_types::Txid::from_hex(self.unspents[idx].txhash.as_str())?,
                vout: self.unspents[idx].vout,
            },
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        transaction.input.push(tx_in);

        Ok(())
    }

    fn sign_p2sh_nested_p2wpkh_input(
        &self,
        idx: usize,
        pub_key: &str,
        transaction: &mut Transaction,
    ) -> Result<()> {
        let unspent = self.unspents.get(idx).expect("get_utxo_fail ");
        let txin = TxIn {
            previous_output: OutPoint {
                txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                vout: unspent.vout,
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let mut data: Vec<u8> = vec![];
        //txhash and vout
        let txhash_data = serialize(&txin.previous_output);
        data.extend(txhash_data.iter());
        //lock script
        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(hash160::Hash::hash(
            &hex_to_bytes(pub_key)?,
        )));
        let script = script.p2wpkh_script_code().expect("must be v0_p2wpkh");
        data.extend(serialize(&script).iter());
        //amount
        let mut utxo_amount = num_bigint::BigInt::from(unspent.amount).to_signed_bytes_le();
        while utxo_amount.len() < 8 {
            utxo_amount.push(0x00);
        }
        data.extend(utxo_amount.iter());
        //set sequence
        data.extend(hex::decode("FFFFFFFF").unwrap());
        //set length
        data.insert(0, data.len() as u8);
        //address
        let mut address_data: Vec<u8> = vec![];
        let sign_path = unspent.derive_path.as_bytes();
        address_data.push(sign_path.len() as u8);
        address_data.extend_from_slice(sign_path);
        data.extend(address_data.iter());

        let sign_apdu = if idx == (self.unspents.len() - 1) {
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

        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(hash160::Hash::hash(
            &hex_to_bytes(pub_key)?,
        )));
        let script_sig = Builder::new().push_slice(&script.to_bytes()).into_script();
        let witness = Witness::from_vec(vec![sign_result_vec, hex::decode(pub_key)?]);

        transaction.input.push(TxIn {
            script_sig,
            witness,
            ..txin
        });
        Ok(())
    }

    fn sign_p2wpkh_input(
        &self,
        idx: usize,
        pub_key: &str,
        transaction: &mut Transaction,
    ) -> Result<()> {
        let unspent = self.unspents.get(idx).expect("get_utxo_fail");
        let txin = TxIn {
            previous_output: OutPoint {
                txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                vout: unspent.vout,
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let mut data: Vec<u8> = vec![];
        //txhash and vout
        let txhash_data = serialize(&txin.previous_output);
        data.extend(txhash_data.iter());
        //lock script
        let script = unspent
            .address
            .script_pubkey()
            .p2wpkh_script_code()
            .expect("must be v0_p2wpkh");
        data.extend(serialize(&script).iter());
        //amount
        let mut utxo_amount = num_bigint::BigInt::from(unspent.amount).to_signed_bytes_le();
        while utxo_amount.len() < 8 {
            utxo_amount.push(0x00);
        }
        data.extend(utxo_amount.iter());
        //set sequence
        data.extend(hex::decode("FFFFFFFF").unwrap());
        //set length
        data.insert(0, data.len() as u8);
        //address
        let mut address_data: Vec<u8> = vec![];
        let sign_path = unspent.derive_path.as_bytes();
        address_data.push(sign_path.len() as u8);
        address_data.extend_from_slice(sign_path);
        data.extend(address_data.iter());

        let sign_apdu = if idx == (self.unspents.len() - 1) {
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

        let witness = Witness::from_vec(vec![sign_result_vec, hex::decode(pub_key)?]);
        transaction.input.push(TxIn { witness, ..txin });
        Ok(())
    }

    fn sign_p2tr_input(
        &self,
        idx: usize,
        pub_key: &str,
        transaction: &mut Transaction,
        sighash_type: SchnorrSighashType,
    ) -> Result<()> {
        let unspent = self.unspents.get(idx).expect("get_utxo_fail");
        let mut data: Vec<u8> = vec![];
        // epoch (1).
        data.push(0x00u8);
        // hash_type (1).
        data.push(sighash_type as u8);
        //nVersion (4):
        //nLockTime (4)
        data.extend(serialize(&transaction.lock_time));
        //prevouts_hash + amounts_hash + script_pubkeys_hash + sequences_hash + sha_outputs (32)
        //spend_type (1)
        data.push(0x00u8);
        //input_index (4)
        data.extend(serialize(&(idx as u32)));

        let mut path_data: Vec<u8> = vec![];
        let sign_path = unspent.derive_path.as_bytes();
        path_data.push(sign_path.len() as u8);
        path_data.extend_from_slice(sign_path);
        data.extend(path_data.iter());

        let mut tweaked_pub_key_data: Vec<u8> = vec![];
        let untweaked_public_key = UntweakedPublicKey::from_str(&pub_key[2..66])?;
        let tweaked_pub_key = TapTweakHash::from_key_and_tweak(untweaked_public_key, None).to_vec();
        tweaked_pub_key_data.push(tweaked_pub_key.len() as u8);
        tweaked_pub_key_data.extend_from_slice(&tweaked_pub_key);
        data.extend(tweaked_pub_key_data.iter());

        let sign_apdu = if idx == (self.unspents.len() - 1) {
            BtcApdu::btc_taproot_sign(true, data)
        } else {
            BtcApdu::btc_taproot_sign(false, data)
        };
        let sign_result = send_apdu(sign_apdu)?;
        ApduCheck::check_response(&sign_result)?;

        let sign_bytes = hex_to_bytes(&sign_result[2..(sign_result.len() - 4)])?;
        let witness = Witness::from_vec(vec![sign_bytes]);
        transaction.input.push(TxIn {
            previous_output: OutPoint {
                txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                vout: unspent.vout,
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness,
        });
        Ok(())
    }
}

pub fn sign_psbt(
    chain_type: &str,
    derivation_path: &str,
    psbt_input: PsbtInput,
    amount: u64,
    fee: u64,
) -> Result<PsbtOutput> {
    let mut reader = Cursor::new(Vec::<u8>::from_hex(psbt_input.data)?);
    let mut psbt = Psbt::consensus_decode(&mut reader)?;
    let mut signer = PsbtSigner::new(&mut psbt, derivation_path);
    signer.prevouts()?;
    signer.sign()?;

    // FINALIZER
    //    if psbt_input.auto_finalize {
    psbt.inputs.iter_mut().for_each(|input| {
        input.finalize();
    });
    //   }

    let mut vec = Vec::<u8>::new();
    let mut writer = Cursor::new(&mut vec);
    psbt.consensus_encode(&mut writer)?;

    return Ok(PsbtOutput { data: hex::encode(vec) });
}


