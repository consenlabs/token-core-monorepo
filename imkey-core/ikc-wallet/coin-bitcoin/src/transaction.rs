use crate::address::BtcAddress;
use crate::common::{address_verify, get_address_version, TxSignResult};
use crate::Result;
use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::consensus::{serialize, Encodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::psbt::Prevouts;
use bitcoin::util::sighash::Annex;
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{
    Address, EcdsaSighashType, Network, OutPoint, PackedLockTime, SchnorrSighashType, Script,
    Sequence, Transaction, TxIn, TxOut, WPubkeyHash, Witness,
};
use bitcoin_hashes::hash160;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::Hash;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::constants::{
    DUST_THRESHOLD, EACH_ROUND_NUMBER, MAX_OPRETURN_SIZE, MAX_UTXO_NUMBER, TIMEOUT_LONG,
};
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{bigint_to_byte_vec, hex_to_bytes, secp256k1_sign};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::ecdsa::Signature;
use std::borrow::Borrow;
use std::str::FromStr;

#[derive(Clone)]
pub struct Utxo {
    pub txhash: String,
    pub vout: u32,
    pub amount: u64,
    pub address: Address,
    pub script_pubkey: String,
    pub derive_path: String,
    pub sequence: i64,
}

pub struct BtcTransaction {
    pub to: Address,
    pub amount: u64,
    pub unspents: Vec<Utxo>,
    pub fee: u64,
}

impl BtcTransaction {
    pub fn sign_transaction(
        &self,
        network: Network,
        path: &str,
        change_idx: i32,
        extra_data: &Vec<u8>,
    ) -> Result<TxSignResult> {
        //path check
        check_path_validity(path)?;
        let mut path_str = path.to_string();
        if !path.ends_with("/") {
            path_str = format!("{}{}", path_str, "/");
        }
        //check uxto number
        if &self.unspents.len() > &MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }

        //utxo address verify
        let utxo_pub_key_vec = address_verify(&self.unspents, network)?;

        //calc utxo total amount
        if self.get_total_amount() < self.amount {
            return Err(CoinError::ImkeyInsufficientFunds.into());
        }

        //add send to output
        let mut txouts: Vec<TxOut> = vec![];
        txouts.push(self.build_send_to_output());

        //add change output
        if self.get_change_amount() > DUST_THRESHOLD {
            let path_temp = format!("{}{}{}", path_str, "1/", change_idx);
            let address_str = BtcAddress::p2pkh(network, path_temp.as_str())?;
            let address_obj = Address::from_str(address_str.as_str())?;
            txouts.push(TxOut {
                value: self.get_change_amount() as u64,
                script_pubkey: address_obj.script_pubkey(),
            });
        }

        //add the op_return
        if !extra_data.is_empty() {
            if extra_data.len() > MAX_OPRETURN_SIZE {
                return Err(CoinError::ImkeySdkIllegalArgument.into());
            }
            txouts.push(self.build_op_return_output(&extra_data))
        }

        //output data serialize
        let mut tx_to_sign = Transaction {
            version: 1i32,
            lock_time: PackedLockTime::ZERO,
            input: vec![],
            output: txouts,
        };
        let mut output_serialize_data = serialize(&tx_to_sign);

        output_serialize_data.remove(5);
        output_serialize_data.remove(5);
        //add sign type
        let mut encoder_hash = Vec::new();
        let len = EcdsaSighashType::All
            .to_u32()
            .consensus_encode(&mut encoder_hash)
            .unwrap();
        debug_assert_eq!(len, encoder_hash.len());
        output_serialize_data.extend(encoder_hash);

        //set input number
        output_serialize_data.remove(4);
        output_serialize_data.insert(4, self.unspents.len() as u8);

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        let address_version = get_address_version(network, self.to.to_string().as_str())?;
        output_serialize_data.push(address_version);

        //set 01 tag and length
        output_serialize_data.insert(0, output_serialize_data.len() as u8);
        output_serialize_data.insert(0, 0x01);

        //use local private key sign data
        let key_manager_obj = KEY_MANAGER.lock();
        let mut output_pareper_data =
            secp256k1_sign(&key_manager_obj.pri_key, &output_serialize_data)?;
        output_pareper_data.insert(0, output_pareper_data.len() as u8);
        output_pareper_data.insert(0, 0x00);
        output_pareper_data.extend(output_serialize_data.iter());

        let btc_prepare_apdu_vec = BtcApdu::btc_prepare(0x41, 0x00, &output_pareper_data);
        for temp_str in btc_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu_timeout(temp_str, TIMEOUT_LONG)?)?;
        }

        let mut lock_script_ver: Vec<Script> = vec![];
        let count = (self.unspents.len() - 1) / EACH_ROUND_NUMBER + 1;
        for i in 0..count {
            for (x, temp_utxo) in self.unspents.iter().enumerate() {
                let mut input_data_vec = vec![];
                input_data_vec.push(x as u8);

                let mut temp_serialize_txin = TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::hash_types::Txid::from_hex(temp_utxo.txhash.as_str())?,
                        vout: temp_utxo.vout as u32,
                    },
                    script_sig: Script::default(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                };
                if (x >= i * EACH_ROUND_NUMBER) && (x < (i + 1) * EACH_ROUND_NUMBER) {
                    temp_serialize_txin.script_sig =
                        Script::from(Vec::from_hex(temp_utxo.script_pubkey.as_str())?);
                }
                input_data_vec.extend_from_slice(serialize(&temp_serialize_txin).as_slice());
                let btc_perpare_apdu = BtcApdu::btc_perpare_input(0x80, &input_data_vec);
                //send perpare apdu to device
                ApduCheck::check_response(&send_apdu(btc_perpare_apdu)?)?;
            }
            for y in i * EACH_ROUND_NUMBER..(i + 1) * EACH_ROUND_NUMBER {
                if y >= utxo_pub_key_vec.len() {
                    break;
                }
                let btc_sign_apdu = BtcApdu::btc_sign(
                    y as u8,
                    EcdsaSighashType::All.to_u32() as u8,
                    self.unspents.get(y).unwrap().derive_path.as_str(),
                );
                //sign data
                let btc_sign_apdu_return = send_apdu(btc_sign_apdu)?;
                ApduCheck::check_response(&btc_sign_apdu_return)?;
                let btc_sign_apdu_return =
                    &btc_sign_apdu_return[..btc_sign_apdu_return.len() - 4].to_string();
                let sign_result_str =
                    btc_sign_apdu_return[2..btc_sign_apdu_return.len() - 2].to_string();

                lock_script_ver.push(self.build_unlock_script(
                    sign_result_str.as_str(),
                    utxo_pub_key_vec.get(y).unwrap(),
                )?)
            }
        }
        let mut txinputs: Vec<TxIn> = Vec::new();
        for (index, unspent) in self.unspents.iter().enumerate() {
            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                    vout: unspent.vout as u32,
                },
                script_sig: lock_script_ver.get(index).unwrap().clone(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };
            txinputs.push(txin);
        }
        tx_to_sign.input = txinputs;
        let tx_bytes = serialize(&tx_to_sign);
        Ok(TxSignResult {
            signature: tx_bytes.to_hex(),
            tx_hash: tx_to_sign.txid().to_hex(),
            wtx_id: tx_to_sign.ntxid().to_hex(),
        })
    }

    pub fn sign_segwit_transaction(
        &self,
        network: Network,
        path: &str,
        change_idx: i32,
        extra_data: &Vec<u8>,
    ) -> Result<TxSignResult> {
        //path check
        check_path_validity(path)?;
        let mut path_str = path.to_string();
        if !path.ends_with("/") {
            path_str = format!("{}{}", path_str, "/");
        }
        //check utxo number
        if &self.unspents.len() > &MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }

        //utxo address verify
        let utxo_pub_key_vec = address_verify(&self.unspents, network)?;

        //calc utxo total amount
        if self.get_total_amount() < self.amount {
            return Err(CoinError::ImkeyInsufficientFunds.into());
        }

        //add send to output
        let mut txouts: Vec<TxOut> = Vec::new();
        txouts.push(self.build_send_to_output());

        //add change output
        if self.get_change_amount() > DUST_THRESHOLD {
            let path_temp = format!("{}{}{}", path_str, "1/", change_idx);
            let address_str = BtcAddress::p2shwpkh(network, path_temp.as_str())?;
            let address_obj = Address::from_str(address_str.as_str())?;
            txouts.push(TxOut {
                value: self.get_change_amount() as u64,
                script_pubkey: address_obj.script_pubkey(),
            });
        }
        //add the op_return
        if !extra_data.is_empty() {
            if extra_data.len() > MAX_OPRETURN_SIZE {
                return Err(CoinError::ImkeySdkIllegalArgument.into());
            }
            txouts.push(self.build_op_return_output(extra_data));
        }

        //8.output data serialize
        let mut tx_to_sign = Transaction {
            version: 2i32,
            lock_time: PackedLockTime::ZERO,
            input: vec![],
            output: txouts,
        };
        let mut output_serialize_data = serialize(&tx_to_sign);

        output_serialize_data.remove(5);
        output_serialize_data.remove(5);

        //add sign type
        let mut encoder_hash = Vec::new();
        let len = EcdsaSighashType::All
            .to_u32()
            .consensus_encode(&mut encoder_hash)
            .unwrap();
        debug_assert_eq!(len, encoder_hash.len());
        output_serialize_data.extend(encoder_hash);

        //set input number
        output_serialize_data.remove(4);
        output_serialize_data.insert(4, self.unspents.len() as u8);

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        let address_version = get_address_version(network, self.to.to_string().as_str())?;
        output_serialize_data.push(address_version);

        //set 01 tag and length
        output_serialize_data.insert(0, output_serialize_data.len() as u8);
        output_serialize_data.insert(0, 0x01);

        //use local private key sign data
        let key_manager_obj = KEY_MANAGER.lock();
        let mut output_pareper_data =
            secp256k1_sign(&key_manager_obj.pri_key, &output_serialize_data)?;
        output_pareper_data.insert(0, output_pareper_data.len() as u8);
        output_pareper_data.insert(0, 0x00);
        output_pareper_data.extend(output_serialize_data.iter());

        let btc_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x00, &output_pareper_data);
        //send output pareper command
        for temp_str in btc_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu_timeout(temp_str, TIMEOUT_LONG)?)?;
        }

        let mut txinputs: Vec<TxIn> = vec![];
        let mut txhash_vout_vec = vec![];
        let mut sequence_vec: Vec<u8> = vec![];
        let mut sign_apdu_vec: Vec<String> = vec![];
        for (index, unspent) in self.unspents.iter().enumerate() {
            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                    vout: unspent.vout as u32,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };

            txhash_vout_vec.extend(serialize(&txin.previous_output).iter());
            sequence_vec.extend(serialize(&txin.sequence).iter());

            let mut data: Vec<u8> = vec![];
            //txhash and vout
            let txhash_data = serialize(&txin.previous_output);
            data.extend(txhash_data.iter());

            //lock script
            let pub_key_bytes = hex::decode(utxo_pub_key_vec.get(index).unwrap())?;
            let pub_key_hash = hash160::Hash::hash(&pub_key_bytes).into_inner();
            let script_hex = format!("76a914{}88ac", hex::encode(pub_key_hash));
            let script = Script::from(hex::decode(script_hex)?);
            let script_data = serialize(&script);
            data.extend(script_data.iter());

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
            // let sign_path = format!("{}{}", path_str, unspent.derive_path);
            let sign_path = unspent.derive_path.as_bytes();
            address_data.push(sign_path.len() as u8);
            address_data.extend_from_slice(sign_path);

            data.extend(address_data.iter());
            if index == self.unspents.len() - 1 {
                sign_apdu_vec.push(BtcApdu::btc_segwit_sign(true, 0x01, data));
            } else {
                sign_apdu_vec.push(BtcApdu::btc_segwit_sign(false, 0x01, data));
            }

            txinputs.push(txin.clone());
        }
        tx_to_sign.input = txinputs;

        let mut txhash_vout_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x40, &txhash_vout_vec);
        let mut sequence_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x80, &sequence_vec);
        txhash_vout_prepare_apdu_vec.append(&mut sequence_prepare_apdu_vec);
        for apdu in txhash_vout_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }

        //send sign apdu
        let mut witnesses: Vec<(Vec<u8>, Vec<u8>)> = vec![];
        for (index, wegwit_sign_apdu) in sign_apdu_vec.iter().enumerate() {
            //send sign apdu
            let sign_apdu_return_data = send_apdu(wegwit_sign_apdu.clone())?;
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
            witnesses.push((
                sign_result_vec,
                hex::decode(utxo_pub_key_vec.get(index).unwrap())?,
            ));
        }

        let input_with_sigs: Result<Vec<TxIn>> = tx_to_sign
            .input
            .iter()
            .enumerate()
            .map(|(i, txin)| {
                let hash = hash160::Hash::hash(
                    hex_to_bytes(utxo_pub_key_vec.get(i).unwrap())
                        .unwrap()
                        .as_slice(),
                )
                .into_inner();
                let hex = format!("160014{}", hex::encode(&hash));
                Ok(TxIn {
                    script_sig: Script::from(hex::decode(hex).unwrap()),
                    witness: Witness::from_vec(vec![
                        witnesses[i].0.clone(),
                        witnesses[i].1.clone(),
                    ]),
                    ..*txin
                })
            })
            .collect();

        tx_to_sign.input = input_with_sigs?;
        let tx_bytes = serialize(&tx_to_sign);

        Ok(TxSignResult {
            signature: tx_bytes.to_hex(),
            tx_hash: tx_to_sign.txid().to_hex(),
            wtx_id: tx_to_sign.wtxid().to_hex(),
        })
    }

    pub fn get_total_amount(&self) -> u64 {
        let mut total_amount = 0;
        for unspent in &self.unspents {
            total_amount += unspent.amount;
        }
        total_amount
    }

    pub fn get_change_amount(&self) -> u64 {
        let total_amount = self.get_total_amount();
        let change_amout = total_amount - self.amount - self.fee;
        change_amout
    }

    pub fn build_send_to_output(&self) -> TxOut {
        TxOut {
            value: self.amount as u64,
            script_pubkey: self.to.script_pubkey(),
        }
    }

    pub fn build_op_return_output(&self, extra_data: &Vec<u8>) -> TxOut {
        let opreturn_script = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(&extra_data[..])
            .into_script();
        TxOut {
            value: 0u64,
            script_pubkey: opreturn_script,
        }
    }

    pub fn build_unlock_script(&self, signed: &str, utxo_public_key: &str) -> Result<Script> {
        let signed_vec = Vec::from_hex(&signed)?;
        let mut signature_obj = Signature::from_compact(signed_vec.as_slice())?;
        signature_obj.normalize_s();
        let mut signed_vec = signature_obj.serialize_der().to_vec();

        //add hash type
        signed_vec.push(EcdsaSighashType::All.to_u32() as u8);
        Ok(Builder::new()
            .push_slice(&signed_vec)
            .push_slice(Vec::from_hex(utxo_public_key)?.as_slice())
            .into_script())
    }

    pub fn sign(
        &self,
        network: Network,
        path: &str,
        change_idx: Option<u32>,
        extra_data: &Vec<u8>,
        seg_wit: &str,
    ) -> Result<TxSignResult> {
        //path check
        check_path_validity(path)?;
        let mut path_str = path.to_string();
        if !path.ends_with("/") {
            path_str = format!("{}{}", path_str, "/");
        }

        //check uxto number
        if &self.unspents.len() > &MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }

        //utxo address verify
        let utxo_pub_key_vec = address_verify(&self.unspents, network)?;

        //calc utxo total amount
        if self.get_total_amount() < self.amount {
            return Err(CoinError::ImkeyInsufficientFunds.into());
        }

        //add send to output
        let mut txouts: Vec<TxOut> = vec![];
        txouts.push(self.build_send_to_output());

        //add change output
        if self.get_change_amount() > DUST_THRESHOLD {
            //TODO
            let change_script = if let Some(change_address_index) = change_idx {
                let change_path = format!("{}{}{}", path_str, "1/", change_address_index);
                let pub_key = BtcAddress::get_pub_key(&change_path)?;
                let change_address = BtcAddress::from_public_key(&pub_key, network, seg_wit)?;
                let change_address = Address::from_str(&change_address)?;
                change_address.script_pubkey()
            } else {
                Address::from_str(&self.unspents[0].address.to_string())?.script_pubkey()
            };
            txouts.push(TxOut {
                value: self.get_change_amount(),
                script_pubkey: change_script,
            });
        }

        //add the op_return
        if !extra_data.is_empty() {
            if extra_data.len() > MAX_OPRETURN_SIZE {
                return Err(CoinError::ImkeySdkIllegalArgument.into());
            }
            txouts.push(self.build_op_return_output(&extra_data))
        }

        //output data serialize
        let mut tx_to_sign = Transaction {
            version: 2i32, // TODO legacy为1
            lock_time: PackedLockTime::ZERO,
            input: vec![],
            output: txouts,
        };
        let mut output_serialize_data = serialize(&tx_to_sign);

        output_serialize_data.remove(5);
        output_serialize_data.remove(5);
        //add sign type
        let mut encoder_hash = Vec::new();
        let len = EcdsaSighashType::All
            .to_u32()
            .consensus_encode(&mut encoder_hash)
            .unwrap();
        debug_assert_eq!(len, encoder_hash.len());
        output_serialize_data.extend(encoder_hash);

        //set input number
        output_serialize_data.remove(4);
        output_serialize_data.insert(4, self.unspents.len() as u8);

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        let address_version = get_address_version(network, self.to.to_string().as_str())?;
        output_serialize_data.push(address_version);

        //set 01 tag and length
        output_serialize_data.insert(0, output_serialize_data.len() as u8);
        output_serialize_data.insert(0, 0x01);

        //use local private key sign data
        let key_manager_obj = KEY_MANAGER.lock();
        let mut output_pareper_data =
            secp256k1_sign(&key_manager_obj.pri_key, &output_serialize_data)?;
        output_pareper_data.insert(0, output_pareper_data.len() as u8);
        output_pareper_data.insert(0, 0x00);
        output_pareper_data.extend(output_serialize_data.iter());

        // let btc_prepare_apdu_vec = BtcApdu::btc_prepare(0x41, 0x00, &output_pareper_data);//TODO legacy 是41 segwit是31
        let btc_prepare_apdu_vec = BtcApdu::btc_prepare(0x41, 0x00, &output_pareper_data);
        for temp_str in btc_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu_timeout(temp_str, TIMEOUT_LONG)?)?;
        }

        let input_with_sigs: Vec<TxIn> = vec![];
        for (idx, utxo) in self.unspents.iter().enumerate() {
            let script = Script::from_str(&utxo.script_pubkey)?;
            if script.is_p2pkh() {
                tx_to_sign.version = 1;
                self.sign_p2pkh_input(idx, &utxo_pub_key_vec[idx], &mut tx_to_sign)?;
            } else if script.is_p2sh() {
                tx_to_sign.version = 2;
                self.sign_p2sh_nested_p2wpkh_input(idx, &utxo_pub_key_vec[idx], &mut tx_to_sign)?;
            } else if script.is_v0_p2wpkh() {
                tx_to_sign.version = 2;
                self.sign_p2wpkh_input(idx, &utxo_pub_key_vec[idx], &mut tx_to_sign)?;
            } else {
                return Err(CoinError::InvalidUtxo.into());
            };
        }

        let tx_bytes = serialize(&tx_to_sign);

        Ok(TxSignResult {
            signature: tx_bytes.to_hex(),
            tx_hash: tx_to_sign.txid().to_hex(),
            wtx_id: tx_to_sign.wtxid().to_hex(),
        })
    }

    fn sign_p2pkh_input(
        &self,
        idx: usize,
        pub_key: &str,
        transaction: &mut Transaction,
    ) -> Result<()> {
        let mut input_data_vec = vec![];
        for (x, temp_utxo) in self.unspents.iter().enumerate() {
            // let mut input_data_vec = vec![];
            // input_data_vec.push(0 as u8);

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
            // let btc_perpare_apdu = BtcApdu::btc_perpare_input(0x80, &input_data_vec);
            // ApduCheck::check_response(&send_apdu(btc_perpare_apdu)?)?;
        }
        println!("序列化结果-->{}", hex::encode(&input_data_vec));
        let btc_perpare_apdu_list = BtcApdu::btc_single_utxo_sign_prepare(0x46, &input_data_vec);
        for apdu in btc_perpare_apdu_list {
            // println!("0000000000>{}", apdu.clone());
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }


        let btc_sign_apdu = BtcApdu::btc_single_utxo_sign(
            idx as u8,
            EcdsaSighashType::All.to_u32() as u8,
            self.unspents.get(idx).unwrap().derive_path.as_str(),
        );
        println!("btc_sign_apdu-->{}", btc_sign_apdu);
        //sign data
        let btc_sign_apdu_return = send_apdu(btc_sign_apdu)?;
        ApduCheck::check_response(&btc_sign_apdu_return)?;
        let btc_sign_apdu_return =
            &btc_sign_apdu_return[..btc_sign_apdu_return.len() - 4].to_string();
        let sign_result_str = btc_sign_apdu_return[2..btc_sign_apdu_return.len() - 2].to_string();

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
        let mut txinputs: Vec<TxIn> = vec![];
        let mut txhash_vout_vec = vec![];
        let mut sequence_vec: Vec<u8> = vec![];
        let mut sign_apdu_vec: Vec<String> = vec![];
        for (index, unspent) in self.unspents.iter().enumerate() {
            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                    vout: unspent.vout,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };

            txhash_vout_vec.extend(serialize(&txin.previous_output).iter());
            sequence_vec.extend(serialize(&txin.sequence).iter());

            let mut data: Vec<u8> = vec![];
            //txhash and vout
            let txhash_data = serialize(&txin.previous_output);
            data.extend(txhash_data.iter());

            //lock script
            // let pub_key_hash = hash160::Hash::hash(&hex_to_bytes(pub_key)?).into_inner();
            // let script_hex = format!("76a914{}88ac", hex::encode(pub_key_hash));
            // let script = Script::from(hex::decode(script_hex)?);
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
            if index == self.unspents.len() - 1 {
                sign_apdu_vec.push(BtcApdu::btc_segwit_sign(true, 0x01, data));
            } else {
                sign_apdu_vec.push(BtcApdu::btc_segwit_sign(false, 0x01, data));
            }

            txinputs.push(txin.clone());
        }

        let mut txhash_vout_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x40, &txhash_vout_vec);
        let mut sequence_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x80, &sequence_vec);
        txhash_vout_prepare_apdu_vec.append(&mut sequence_prepare_apdu_vec);
        for apdu in txhash_vout_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }

        let sign_apdu_return_data = send_apdu(sign_apdu_vec[idx].to_string())?;
        ApduCheck::check_response(&sign_apdu_return_data)?;
        //build signature obj
        let sign_result_vec =
            Vec::from_hex(&sign_apdu_return_data[2..sign_apdu_return_data.len() - 6]).unwrap();
        let mut signature_obj = Signature::from_compact(sign_result_vec.as_slice())?;
        signature_obj.normalize_s();
        //generator der sign data
        let mut sign_result_vec = signature_obj.serialize_der().to_vec();
        println!("sign result-->{}", hex::encode(&sign_result_vec));
        //add hash type
        sign_result_vec.push(EcdsaSighashType::All.to_u32() as u8);

        // let hash = hash160::Hash::hash(hex_to_bytes(pub_key).unwrap().as_slice()).into_inner();
        // let hex = format!("160014{}", hex::encode(&hash));
        // let script_sig = Script::from(hex::decode(hex).unwrap());
        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(hash160::Hash::hash(
            &hex_to_bytes(pub_key)?,
        )));
        let script_sig = Builder::new().push_slice(&script.to_bytes()).into_script();
        let witness = Witness::from_vec(vec![sign_result_vec, hex::decode(pub_key)?]);

        transaction.input.push(TxIn {
            script_sig,
            witness,
            ..txinputs[idx].clone()
        });
        Ok(())
    }

    fn sign_p2wpkh_input(
        &self,
        idx: usize,
        pub_key: &str,
        transaction: &mut Transaction,
    ) -> Result<()> {
        let mut txinputs: Vec<TxIn> = vec![];
        let mut txhash_vout_vec = vec![];
        let mut sequence_vec: Vec<u8> = vec![];
        let mut sign_apdu_vec: Vec<String> = vec![];
        for (index, unspent) in self.unspents.iter().enumerate() {
            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                    vout: unspent.vout,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };

            txhash_vout_vec.extend(serialize(&txin.previous_output).iter());
            sequence_vec.extend(serialize(&txin.sequence).iter());

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
            if index == self.unspents.len() - 1 {
                sign_apdu_vec.push(BtcApdu::btc_segwit_sign(true, 0x01, data));
            } else {
                sign_apdu_vec.push(BtcApdu::btc_segwit_sign(false, 0x01, data));
            }

            txinputs.push(txin.clone());
        }

        let mut txhash_vout_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x40, &txhash_vout_vec);
        let mut sequence_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x80, &sequence_vec);
        txhash_vout_prepare_apdu_vec.append(&mut sequence_prepare_apdu_vec);
        for apdu in txhash_vout_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }

        let sign_apdu_return_data = send_apdu(sign_apdu_vec[idx].to_string())?;
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

        // let hash = hash160::Hash::hash(hex_to_bytes(pub_key).unwrap().as_slice()).into_inner();
        // let hex = format!("160014{}", hex::encode(&hash));
        // let script_sig = Script::from(hex::decode(hex).unwrap());

        let witness = Witness::from_vec(vec![sign_result_vec, hex::decode(pub_key)?]);

        transaction.input.push(TxIn {
            witness,
            ..txinputs[idx].clone()
        });
        Ok(())
    }

    fn sign_p2tr_input<T: Borrow<TxOut>>(
        &self,
        idx: usize,
        pub_key: &str,
        transaction: &mut Transaction,
        prevouts: &Prevouts<T>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSighashType,
    ) -> Result<()> {
        let mut txinputs: Vec<TxIn> = vec![];
        let mut txhash_vout_vec = vec![];
        let mut sequence_vec: Vec<u8> = vec![];
        let mut sign_apdu_vec: Vec<String> = vec![];
        for (index, unspent) in self.unspents.iter().enumerate() {
            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                    vout: unspent.vout,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };

            txhash_vout_vec.extend(serialize(&txin.previous_output).iter());
            sequence_vec.extend(serialize(&txin.sequence).iter());

            let mut data: Vec<u8> = vec![];
            data.push(0u8);//epoch
            data.push(sighash_type as u8);//hash_type
            data.push(transaction.version as u8);//nVersion (4)
            data.extend(serialize(&transaction.lock_time));//nLockTime (4)
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
            if index == self.unspents.len() - 1 {
                sign_apdu_vec.push(BtcApdu::btc_segwit_sign(true, 0x01, data));
            } else {
                sign_apdu_vec.push(BtcApdu::btc_segwit_sign(false, 0x01, data));
            }

            txinputs.push(txin.clone());
        }

        let mut txhash_vout_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x40, &txhash_vout_vec);
        let mut sequence_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x80, &sequence_vec);
        txhash_vout_prepare_apdu_vec.append(&mut sequence_prepare_apdu_vec);
        for apdu in txhash_vout_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }

        let sign_apdu_return_data = send_apdu(sign_apdu_vec[idx].to_string())?;
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

        // let hash = hash160::Hash::hash(hex_to_bytes(pub_key).unwrap().as_slice()).into_inner();
        // let hex = format!("160014{}", hex::encode(&hash));
        // let script_sig = Script::from(hex::decode(hex).unwrap());

        let witness = Witness::from_vec(vec![sign_result_vec, hex::decode(pub_key)?]);

        transaction.input.push(TxIn {
            witness,
            ..txinputs[idx].clone()
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::{BtcTransaction, Utxo};
    use bitcoin::{Address, Network, Script, WPubkeyHash};
    use bitcoin_hashes::hex::ToHex;
    use bitcoin_hashes::{hash160, Hash};
    use hex::FromHex;
    use ikc_common::utility::hex_to_bytes;
    use ikc_device::device_binding::bind_test;
    use std::str::FromStr;

    #[test]
    fn test_sign_transaction() {
        //binding device
        bind_test();

        let extra_data = Vec::from_hex("0200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa99385").unwrap();
        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 200000000,
            address: Address::from_str("mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC").unwrap(),
            script_pubkey: "76a914118c3123196e030a8a607c22bafc1577af61497d88ac".to_string(),
            derive_path: "m/44'/1'/0'/0/22".to_string(),
            sequence: 4294967295,
        };
        let utxo2 = Utxo {
            txhash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531".to_string(),
            vout: 1,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 4294967295,
        };
        let utxo3 = Utxo {
            txhash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9".to_string(),
            vout: 0,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 4294967295,
        };
        let utxo4 = Utxo {
            txhash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9".to_string(),
            vout: 1,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 4294967295,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        utxos.push(utxo3);
        utxos.push(utxo4);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3").unwrap(),
            //            change_idx: 53,
            amount: 799988000,
            unspents: utxos,
            fee: 10000,
            //            extra_data: extra_data,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Testnet,
            &"m/44'/1'/0'".to_string(),
            53,
            &extra_data,
        );
        assert_eq!(
            "d40ceeecbb1ad07e7a19d4c807808ad7b5c78854cfebd7f25e2f79fcc43055f4",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "aad80fe8069e77559d3f99602a2f10cc9d459a591a04684bdfba9595029055e5",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_segwit_transaction() {
        //binding device
        bind_test();

        let extra_data = Vec::from_hex("1234").unwrap();
        let utxo = Utxo {
            txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf").unwrap(),
            script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
            derive_path: "m/49'/1'/0'/0/1".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp").unwrap(),
            amount: 88000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
        );
        assert_eq!(
            "3b2178aa4d52377226dd394776680a91a05781fe93ce42666e307dc16aeaae99",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "92fa20346dc6a97d852db332beffb7d60d57d82207b63c6484d886541a924041",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn sign_transaction_simple_test() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 10000112345678,
            address: Address::from_str("1Fj93kpLwM1KgTN6C75Z5Bokhays4MmJae").unwrap(),
            script_pubkey: "76a914a189f2f7836812aa7a0e36e28a20a10e64010bf688ac".to_string(),
            derive_path: "m/44'/0'/0'/0/22".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("18pMkq6HK5HR36jr7bSd39MpkVCfnP68VV").unwrap(),
            amount: 10000012345678,
            unspents: utxos,
            fee: 502130,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Bitcoin,
            &"m/44'/0'/0'/".to_string(),
            53,
            &extra_data,
        );
        assert_eq!(
            "a80aa368b10c8bdf0d2b1866462f2b4bb6b767e9b2b45abe2d05fa4c8efb40e0",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "9129a31332f509a9d03b25cf598d11cf4eaa0f6dbd27957d1f0d8f1b3d00a05d",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn insufficient_funds_test() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 10000112345678,
            address: Address::from_str("1Fj93kpLwM1KgTN6C75Z5Bokhays4MmJae").unwrap(),
            script_pubkey: "76a914a189f2f7836812aa7a0e36e28a20a10e64010bf688ac".to_string(),
            derive_path: "m/44'/0'/0'/0/22".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("18pMkq6HK5HR36jr7bSd39MpkVCfnP68VV").unwrap(),
            amount: 10000112345679,
            unspents: utxos,
            fee: 502130,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Bitcoin,
            &"m/44'/0'/0'/".to_string(),
            53,
            &extra_data,
        );

        assert!(sign_result.is_err());
        assert_eq!(
            format!("{}", sign_result.err().unwrap()),
            "imkey_insufficient_funds"
        );

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 10000000,
            address: Address::from_str("37E2J9ViM4QFiewo7aw5L3drF2QKB99F9e").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/0'/0'/0/22".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("18pMkq6HK5HR36jr7bSd39MpkVCfnP68VV").unwrap(),
            amount: 11000000,
            unspents: utxos,
            fee: 502130,
        };
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Bitcoin,
            &"m/49'/0'/0'".to_string(),
            53,
            &extra_data,
        );
        assert!(sign_result.is_err());
        assert_eq!(
            format!("{}", sign_result.err().unwrap()),
            "imkey_insufficient_funds"
        );
    }

    #[test]
    fn btc_extra_data_error() {
        //binding device
        bind_test();

        let extra_data = Vec::from_hex("0200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa9938500").unwrap();
        //        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 10000112345678,
            address: Address::from_str("1Fj93kpLwM1KgTN6C75Z5Bokhays4MmJae").unwrap(),
            script_pubkey: "76a914a189f2f7836812aa7a0e36e28a20a10e64010bf688ac".to_string(),
            derive_path: "m/44'/0'/0'/0/22".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("18pMkq6HK5HR36jr7bSd39MpkVCfnP68VV").unwrap(),
            amount: 10000012345678,
            unspents: utxos,
            fee: 502130,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Bitcoin,
            &"m/44'/0'/0'/".to_string(),
            53,
            &extra_data,
        );
        assert!(sign_result.is_err());
        assert_eq!(
            format!("{}", sign_result.err().unwrap()),
            "imkey_sdk_illegal_argument"
        );

        let utxo = Utxo {
            txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f".to_string(),
            vout: 0,
            amount: 500000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp").unwrap(),
            amount: 88000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
        );

        assert!(sign_result.is_err());
        assert_eq!(
            format!("{}", sign_result.err().unwrap()),
            "imkey_sdk_illegal_argument"
        );
    }

    #[test]
    fn sign_segwit_transaction_simple_test() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 1012345678,
            address: Address::from_str("37E2J9ViM4QFiewo7aw5L3drF2QKB99F9e").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/0'/0'/0/22".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("18pMkq6HK5HR36jr7bSd39MpkVCfnP68VV").unwrap(),
            amount: 112345678,
            unspents: utxos,
            fee: 502130,
        };
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Bitcoin,
            &"m/49'/0'/0'".to_string(),
            53,
            &extra_data,
        );
        assert_eq!(
            "bfa6137f3cdd4a9bc672380afc931bb89d4539d8c1a589316bedad30e4248a90",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "4694a01d72237fc066564fc807d9a2d7be9518151aabb32f3911526a4589109c",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn address_error_test() {
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 1012345678,
            address: Address::from_str("37E2J9ViM4QFiewo7aw5L3drF2QKB99F9e").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/0'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("18pMkq6HK5HR36jr7bSd39MpkVCfnP68VV").unwrap(),
            amount: 112345678,
            unspents: utxos,
            fee: 502130,
        };
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Bitcoin,
            &"m/49'/0'/0'".to_string(),
            53,
            &extra_data,
        );
        assert!(sign_result.is_err());
        assert_eq!(
            format!("{}", sign_result.err().unwrap()),
            "imkey_address_mismatch_with_path"
        );
    }

    #[test]
    fn test_sign_p2pkh() {
        bind_test();

        let extra_data = Vec::from_hex("0200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa99385").unwrap();
        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 200000000,
            address: Address::from_str("mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC").unwrap(),
            script_pubkey: "76a914118c3123196e030a8a607c22bafc1577af61497d88ac".to_string(),
            derive_path: "m/44'/1'/0'/0/22".to_string(),
            sequence: 4294967295,
        };
        let utxo2 = Utxo {
            txhash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531".to_string(),
            vout: 1,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 4294967295,
        };
        let utxo3 = Utxo {
            txhash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9".to_string(),
            vout: 0,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 4294967295,
        };
        let utxo4 = Utxo {
            txhash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9".to_string(),
            vout: 1,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 4294967295,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        utxos.push(utxo3);
        utxos.push(utxo4);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3").unwrap(),
            amount: 799988000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/44'/1'/0'".to_string(),
            Some(53),
            &extra_data,
            "DEFAULT",
        );
        assert_eq!(
            "d40ceeecbb1ad07e7a19d4c807808ad7b5c78854cfebd7f25e2f79fcc43055f4",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "d40ceeecbb1ad07e7a19d4c807808ad7b5c78854cfebd7f25e2f79fcc43055f4",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_p2wpkh() {
        //binding device
        bind_test();

        let extra_data = Vec::from_hex("1234").unwrap();
        let utxo = Utxo {
            txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf").unwrap(),
            script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
            derive_path: "m/49'/1'/0'/0/1".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp").unwrap(),
            amount: 88000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            Some(0),
            &extra_data,
            "P2WPKH",
        );
        assert_eq!(
            "3b2178aa4d52377226dd394776680a91a05781fe93ce42666e307dc16aeaae99",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "92fa20346dc6a97d852db332beffb7d60d57d82207b63c6484d886541a924041",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_version0_no_change() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "d7c2e585d5eaa185808addb3ef703f2a8fe09288b4f40b757a812d6d63b7c9c4".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            amount: 88000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            Some(0),
            &extra_data,
            "VERSION_0",
        );
        assert_eq!(
            "02000000000101c4c9b7636d2d817a750bf4b48892e08f2a3f70efb3dd8a8085a1ead585e5c2d70100000000ffffffff01c057010000000000160014654fbb08267f3d50d715a8f1abb55979b160dd5b0247304402200af2cffe06976e9f1f1bc0f036ceb3ff87e1c08cdb00ee2892df1e347f37529202203b70be4209103979f7b1a0a4a721af2dce34e0e3ca4426c50565902a5e7911d60121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "7c99f906e291d453b2c039939598eefd182dafb20d53bd0eebc2a1aa635ff60f",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "7f61bb392770b72bb13d090c371e220b69cd908792f16639494bcac5f89e7c16",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_version0_has_change() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "7c99f906e291d453b2c039939598eefd182dafb20d53bd0eebc2a1aa635ff60f".to_string(),
            vout: 0,
            amount: 88000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            amount: 50000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            Some(0),
            &extra_data,
            "VERSION_0",
        );
        assert_eq!(
            "020000000001010ff65f63aaa1c2eb0ebd530db2af2d18fdee98959339c0b253d491e206f9997c0000000000ffffffff0250c3000000000000160014654fbb08267f3d50d715a8f1abb55979b160dd5b606d000000000000160014622347653655d57ee8e8f25983f646bcdf9c50320248304502210099fc03a90559def6c8b8a9d6283f419189445200ae0218d5f9c53ea745d3c0ef0220590069313bac5f52f003dc7626148af6c85c479a93c0dd21c2a82c73f1576ed90121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "fcc622970fd80c14b111ee7950bcc309469b575194072209598176123fd06598",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "e0fc79f382d36229c650153904097795a4e1ae2763e366d5084ac5454e4383ad",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_version0_pay_to_p2pkh() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "64381306678c6a868e8778adee1ee9d1746e5e8dd3535fcbaa1a25baab49f015".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            amount: 30000,
            unspents: utxos,
            fee: 8000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            Some(0),
            &extra_data,
            "VERSION_0",
        );
        assert_eq!(
            "0200000000010115f049abba251aaacb5f53d38d5e6e74d1e91eeead78878e866a8c67061338640100000000ffffffff0230750000000000001976a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac30f2000000000000160014622347653655d57ee8e8f25983f646bcdf9c503202483045022100bc0e5f620554681ccd336cd9e12a244abd40d374a3a7668671a73edfb561a7900220534617da8eb8636f2db8bdb6191323bb766d534235d97ad08935a05ffb8b81010121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "eb3ea0d4b360a304849b90baf49197eb449ca746febd60f8f29cd279c966a3ea",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "0f538a5808dfc78124ad7de1ff81ededb94d0e8aabd057d46af46459582673e9",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_version0_pay_to_p2shp2wpkh() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "fcc622970fd80c14b111ee7950bcc309469b575194072209598176123fd06598".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            amount: 30000,
            unspents: utxos,
            fee: 7000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            Some(0),
            &extra_data,
            "VERSION_0",
        );
        assert_eq!(
            "020000000001019865d03f127681590922079451579b4609c3bc5079ee11b1140cd80f9722c6fc0000000000ffffffff02307500000000000017a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987c832000000000000160014622347653655d57ee8e8f25983f646bcdf9c503202483045022100f2d33b3a6f592f6f9ec9f2e560aaa2323e59cbc9e42cf9161b690ce26ef8371702203b2bebece7c8cfb9c24baf56bef8eecb9ec0be322889ac8053da1722a97c45160121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "e5add8950cb37b1d80ff18cb2ba775e185e1843b845e18b532dc4b5d8ffec7a9",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "8a52efead3765739a359ef50962cbde02737533a0a764b29fc3414b9c3ca6cd0",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_version0_pay_to_bech32() {
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "eb3ea0d4b360a304849b90baf49197eb449ca746febd60f8f29cd279c966a3ea".to_string(),
            vout: 0,
            amount: 30000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 4294967295,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            amount: 25000,
            unspents: utxos,
            fee: 5000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/44'/1'/0'".to_string(),
            Some(0),
            &extra_data,
            "DEFAULT",
        );
        assert_eq!(
            "0100000001eaa366c979d29cf2f860bdfe46a79c44eb9791f4ba909b8404a360b3d4a03eeb000000006b483045022100e8209a6692b87d0e743509e314894affefdb1f02ae0a210184c3d4c2c75394a70220144af4619d8b16dd3a7cb6f4a10552e766a7e9e16786c796cd9a162d8c0041880121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff01a861000000000000160014654fbb08267f3d50d715a8f1abb55979b160dd5b00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "63d3ee791a22fafc3708b57b2ba80909e5f0e41ce477c077146465aec3a9a11e",
            sign_result.as_ref().unwrap().tx_hash
        );
    }

    #[test]
    fn test_sign_segwit_p2sh_p2wpkh_pay_to_bech32() {
        bind_test();

        let extra_data = Vec::from_hex("1234").unwrap();
        let utxo = Utxo {
            txhash: "e5add8950cb37b1d80ff18cb2ba775e185e1843b845e18b532dc4b5d8ffec7a9".to_string(),
            vout: 0,
            amount: 30000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            amount: 26000,
            unspents: utxos,
            fee: 4000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            Some(0),
            &extra_data,
            "P2WPKH",
        );
        assert_eq!(
            "02000000000101a9c7fe8f5d4bdc32b5185e843b84e185e175a72bcb18ff801d7bb30c95d8ade50000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff029065000000000000160014654fbb08267f3d50d715a8f1abb55979b160dd5b0000000000000000046a02123402483045022100aca51e4f49ea1222a2a0ee92b4f76ab3cc4f81ee34fdabc51dfd5115fb4f472f022024c2c860b01e5314139c6a9442679e3a10ca5003f37eb727aa9b1af322a0ba8c0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "401959f94ad3c1c55a6d778f8446625a4b00a0a12a2cdb983fb4423ce93261cc",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "e5582aa8fed3c681516ba6348c59ef08983eb0e3121d81c03ad5225584445b41",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_version0_pay_to_bech32_multiutxo() {
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "401959f94ad3c1c55a6d778f8446625a4b00a0a12a2cdb983fb4423ce93261cc".to_string(),
            vout: 0,
            amount: 26000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "e5add8950cb37b1d80ff18cb2ba775e185e1843b845e18b532dc4b5d8ffec7a9".to_string(),
            vout: 1,
            amount: 13000,
            address: Address::from_str("tb1qvg35wefk2h2ha68g7fvc8ajxhn0ec5pjekus6j").unwrap(),
            script_pubkey: "0014622347653655d57ee8e8f25983f646bcdf9c5032".to_string(),
            derive_path: "m/49'/1'/0'/1/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            amount: 31000,
            unspents: utxos,
            fee: 5000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            Some(0),
            &extra_data,
            "VERSION_0",
        );
        assert_eq!(
            "02000000000102cc6132e93c42b43f98db2c2aa1a0004b5a6246848f776d5ac5c1d34af95919400000000000ffffffffa9c7fe8f5d4bdc32b5185e843b84e185e175a72bcb18ff801d7bb30c95d8ade50100000000ffffffff021879000000000000160014654fbb08267f3d50d715a8f1abb55979b160dd5bb80b000000000000160014622347653655d57ee8e8f25983f646bcdf9c50320248304502210098aea910af0731b676ec0b09f5e9b78be165808e7cda7f56fff535aab3ace1f5022062546d6894f0e6a0ae24e659fe37fb11c407739970a8aeb05b79c7bf8e012f4b0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc02483045022100bd8dc6ec13fb55900441ab8449675995bc9b046709c1bd1831b7bbc3066e2f8e02205f9dd402d1133ab92cbe46abcda11b332280955525fa4ff94832ecdf83803d89012103d83187d984c44ec073d4661d93fa306b613c0c91a1661d919dd43814da1a5f8900000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "b0d835f99c58870fc412d571f45779c4d5d7b8f975e47bf5d2fb6d92498e8702",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "ddb07af540008b352acbd6aa80c925ad2afcfc9354ac026c347fb7bc1a553167",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_version0_mixed_sign_pay_to_bech32_multiutxo() {
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "356d5e8628466f072c1de991e14320226ceef944cfebec251dd5c87ea925823c".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "b63ca3592561fd7c8b41017fbb0deff12ce6f7d351128c818dcf4ed1a0beae0e".to_string(),
            vout: 1,
            amount: 1418852,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2N5z4KZBCQNULTegkETDftMiNHWEFjrH3m2").unwrap(),
            amount: 1508852,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            Some(53),
            &extra_data,
            "P2WPKH",
        );
        assert_eq!(
            "020000000001023c8225a97ec8d51d25ecebcf44f9ee6c222043e191e91d2c076f4628865e6d35010000006b483045022100e3f1bffc773f0bd984f4d0cb727b4beb5c9833a701e2af3b26479a93eb764bc6022017b3269ade37bb70f84ed9576ac9bc96f262ac249b781bd5592069aceb01f4e80121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff0eaebea0d14ecf8d818c1251d3f7e62cf1ef0dbb7f01418b7cfd612559a33cb60100000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff01f40517000000000017a9148bbb53570df9656926ea0ef029cd2ee84dbc7d0f87000247304402206b159cc6edc019125ea87b4df39a566520e092371ddb030071f150476a1bbd8d022074c43c41557ab6be848d48ccc611225b3a36ea3b4163f0cfc970fc945dfa7acf0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );

        assert_eq!(
            "1f9d6ed247c27be02987e750de7d4289059eadbc220083fca80337beafea3079",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "069df21caebcc86674aa874a37276a5981a623a5c63452cfc8139d1451e74686",
            sign_result.as_ref().unwrap().wtx_id
        );
    }
}
