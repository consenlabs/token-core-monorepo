use crate::address::BtcAddress;
use crate::common::{
    address_verify, get_address_version, get_path_and_pubkeys, get_xpub_data,
    secp256k1_sign_verify, PathPubKey, TransTypeFlg, TxSignResult,
};
use crate::Result;
use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::consensus::{serialize, Encodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{
    Address, EcdsaSighashType, Network, OutPoint, PackedLockTime, Script, Sequence, SigHashType,
    Transaction, TxIn, TxOut, VarInt, Witness,
};
use bitcoin_hashes::hash160;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::Hash;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::constants::{
    BTC_NATIVE_SEGWIT_MAINNET_PATH, BTC_NATIVE_SEGWIT_TESTNET_PATH, DUST_THRESHOLD,
    EACH_ROUND_NUMBER, MAX_OPRETURN_SIZE, MAX_UTXO_NUMBER, TIMEOUT_LONG,
    UNCOMPRESSED_PUBKEY_STRING_LEN, XPUB_STRING_LEN,
};
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{bigint_to_byte_vec, hex_to_bytes, secp256k1_sign};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::Signature;
use std::str::FromStr;

#[derive(Clone)]
pub struct Utxo {
    pub txhash: String,
    pub vout: i32,
    pub amount: i64,
    pub address: Address,
    pub script_pubkey: String,
    pub derive_path: String,
    pub sequence: i64,
}

pub struct BtcTransaction {
    pub to: Address,
    pub amount: i64,
    pub unspents: Vec<Utxo>,
    pub fee: i64,
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

        //get xpub and sign data
        let xpub_data = get_xpub_data(path_str.as_str(), true)?;
        let xpub_data = &xpub_data[..xpub_data.len() - 4].to_string();

        //parsing xpub data
        let sign_source_val = &xpub_data[..XPUB_STRING_LEN];
        let sign_result = &xpub_data[XPUB_STRING_LEN..];
        let pub_key = &sign_source_val[..UNCOMPRESSED_PUBKEY_STRING_LEN];
        let chain_code = &sign_source_val[UNCOMPRESSED_PUBKEY_STRING_LEN..];

        //use se public key verify sign
        let key_manager_obj = KEY_MANAGER.lock();
        let sign_verify_result = secp256k1_sign_verify(
            &key_manager_obj.se_pub_key.as_slice(),
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        );
        if sign_verify_result.is_err() || !sign_verify_result.ok().unwrap() {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        //utxo address verify
        let utxo_pub_key_vec = address_verify(
            &self.unspents,
            pub_key,
            hex::decode(chain_code).unwrap().as_slice(),
            network,
            TransTypeFlg::BTC,
        )?;

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
            let address_str = BtcAddress::get_address(network, path_temp.as_str())?;
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
        let mut utxo_len = serialize(&VarInt(self.unspents.len() as u64));
        utxo_len.reverse();
        for temp_data in utxo_len {
            output_serialize_data.insert(4, temp_data);
        }

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        let address_version = get_address_version(network, self.to.to_string().as_str())?;
        output_serialize_data.push(address_version);

        //set 01 tag and length
        output_serialize_data.insert(0, output_serialize_data.len() as u8);
        output_serialize_data.insert(0, 0x01);

        //use local private key sign data
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
                input_data_vec.extend(hex::decode(format!("{:04X}", x)).unwrap());

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
                    y as u16,
                    EcdsaSighashType::All.to_u32() as u8,
                    format!("{}{}", path_str, self.unspents.get(y).unwrap().derive_path).as_str(),
                );
                //sign data
                let btc_sign_apdu_return = send_apdu(btc_sign_apdu)?;
                ApduCheck::check_response(&btc_sign_apdu_return)?;
                let btc_sign_apdu_return =
                    &btc_sign_apdu_return[..btc_sign_apdu_return.len() - 4].to_string();
                let sign_result_str =
                    btc_sign_apdu_return[2..btc_sign_apdu_return.len() - 2].to_string();

                lock_script_ver.push(self.build_lock_script(
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

        //get xpub and sign data
        let xpub_data = get_xpub_data(path_str.as_str(), true)?;
        let xpub_data = &xpub_data[..xpub_data.len() - 4].to_string();

        //parsing xpub data
        let sign_source_val = &xpub_data[..XPUB_STRING_LEN];
        let sign_result = &xpub_data[XPUB_STRING_LEN..];
        let pub_key = &sign_source_val[..UNCOMPRESSED_PUBKEY_STRING_LEN];
        let chain_code = &sign_source_val[UNCOMPRESSED_PUBKEY_STRING_LEN..];

        //use se public key verify sign
        let key_manager_obj = KEY_MANAGER.lock();
        let sign_verify_result = secp256k1_sign_verify(
            &key_manager_obj.se_pub_key.as_slice(),
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        );
        if sign_verify_result.is_err() || !sign_verify_result.ok().unwrap() {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }
        //utxo address verify
        let utxo_pub_key_vec = address_verify(
            &self.unspents,
            pub_key,
            hex::decode(chain_code).unwrap().as_slice(),
            network,
            TransTypeFlg::SEGWIT,
        )?;

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
            let address_str = BtcAddress::get_segwit_address(network, path_temp.as_str())?;
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
        let mut utxo_len = serialize(&VarInt(self.unspents.len() as u64));
        utxo_len.reverse();
        for temp_data in utxo_len {
            output_serialize_data.insert(4, temp_data);
        }

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        let address_version = get_address_version(network, self.to.to_string().as_str())?;
        output_serialize_data.push(address_version);

        //set 01 tag and length
        output_serialize_data.insert(0, output_serialize_data.len() as u8);
        output_serialize_data.insert(0, 0x01);

        //use local private key sign data
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
            let sign_path = format!("{}{}", path_str, unspent.derive_path);
            address_data.push(sign_path.as_bytes().len() as u8);
            address_data.extend_from_slice(sign_path.as_bytes());

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

    pub fn sign_native_segwit_transaction(
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

        //get xpub and sign data
        let xpub_data = get_xpub_data(path_str.as_str(), true)?;
        let xpub_data = &xpub_data[..xpub_data.len() - 4].to_string();

        //parsing xpub data
        let sign_source_val = &xpub_data[..XPUB_STRING_LEN];
        let sign_result = &xpub_data[XPUB_STRING_LEN..];
        let pub_key = &sign_source_val[..UNCOMPRESSED_PUBKEY_STRING_LEN];
        let chain_code = &sign_source_val[UNCOMPRESSED_PUBKEY_STRING_LEN..];

        //use se public key verify sign
        let key_manager_obj = KEY_MANAGER.lock();
        let sign_verify_result = secp256k1_sign_verify(
            &key_manager_obj.se_pub_key.as_slice(),
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        );
        if sign_verify_result.is_err() || !sign_verify_result.ok().unwrap() {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }
        //utxo address verify
        let utxo_pub_key_vec = address_verify(
            &self.unspents,
            pub_key,
            hex::decode(chain_code).unwrap().as_slice(),
            network,
            TransTypeFlg::NATIVE,
        )?;

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
            let address_str = BtcAddress::get_native_segwit_address(network, path_temp.as_str())?;
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
        let mut utxo_len = serialize(&VarInt(self.unspents.len() as u64));
        utxo_len.reverse();
        for temp_data in utxo_len {
            output_serialize_data.insert(4, temp_data);
        }

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        let address_version = get_address_version(network, self.to.to_string().as_str())?;
        output_serialize_data.push(address_version);

        //set 01 tag and length
        output_serialize_data.insert(0, output_serialize_data.len() as u8);
        output_serialize_data.insert(0, 0x01);

        //use local private key sign data
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
            let sign_path = format!("{}{}", path_str, unspent.derive_path);
            address_data.push(sign_path.as_bytes().len() as u8);
            address_data.extend_from_slice(sign_path.as_bytes());

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
                Ok(TxIn {
                    script_sig: Script::new(),
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

    pub fn sign_mixed_transaction(
        &self,
        network: Network,
        change_idx: i32,
        extra_data: &Vec<u8>,
    ) -> Result<TxSignResult> {
        let path_and_pubkeys = get_path_and_pubkeys(&self.unspents, network)?;

        //calc utxo total amount
        if self.get_total_amount() < self.amount {
            return Err(CoinError::ImkeyInsufficientFunds.into());
        }

        //add send to output
        let mut txouts: Vec<TxOut> = Vec::new();
        txouts.push(self.build_send_to_output());

        let parent_path = match network {
            Network::Testnet => BTC_NATIVE_SEGWIT_TESTNET_PATH,
            Network::Bitcoin => BTC_NATIVE_SEGWIT_MAINNET_PATH,
            _ => BTC_NATIVE_SEGWIT_MAINNET_PATH,
        };
        //add change output
        if self.get_change_amount() > DUST_THRESHOLD {
            let path_temp = format!("{}{}{}", parent_path, "/1/", change_idx);
            let address_str = BtcAddress::get_native_segwit_address(network, path_temp.as_str())?;
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

        //version, locktime and output data serialize
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
        let mut utxo_len = serialize(&VarInt(self.unspents.len() as u64));
        utxo_len.reverse();
        for temp_data in utxo_len {
            output_serialize_data.insert(4, temp_data);
        }

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        let address_version = get_address_version(network, self.to.to_string().as_str())?;
        output_serialize_data.push(address_version);

        //set 01 tag and length
        output_serialize_data.insert(0, output_serialize_data.len() as u8);
        output_serialize_data.insert(0, 0x01);

        let key_manager_obj = KEY_MANAGER.lock();
        //use local private key sign data
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

        // hash vout data and Sequnce data
        for unspent in self.unspents.iter() {
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
        }

        let mut txhash_vout_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x40, &txhash_vout_vec);
        let mut sequence_prepare_apdu_vec = BtcApdu::btc_prepare(0x31, 0x80, &sequence_vec);
        txhash_vout_prepare_apdu_vec.append(&mut sequence_prepare_apdu_vec);
        for apdu in txhash_vout_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }

        // sign
        let mut witnesses: Vec<(Vec<u8>, Vec<u8>)> = vec![];
        let mut lock_script_ver: Vec<Script> = vec![];

        for (index, unspent) in self.unspents.iter().enumerate() {
            let path_pubkey: &PathPubKey = path_and_pubkeys.get(index).unwrap();

            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                    vout: unspent.vout as u32,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };
            let mut data: Vec<u8> = vec![];

            // type legacy
            if unspent.script_pubkey.starts_with("76a914")
                || unspent.script_pubkey.starts_with("76A914")
            {
                for (x, temp_utxo) in self.unspents.iter().enumerate() {
                    let mut input_data_vec = vec![];
                    let mut temp_serialize_txin = TxIn {
                        previous_output: OutPoint {
                            txid: bitcoin::hash_types::Txid::from_hex(temp_utxo.txhash.as_str())?,
                            vout: temp_utxo.vout as u32,
                        },
                        script_sig: Script::default(),
                        sequence: Sequence::MAX,
                        witness: Witness::default(),
                    };
                    if x == index {
                        temp_serialize_txin.script_sig =
                            Script::from(Vec::from_hex(temp_utxo.script_pubkey.as_str())?);
                    }
                    input_data_vec.extend_from_slice(serialize(&temp_serialize_txin).as_slice());

                    let btc_perpare_apdu = if x == self.unspents.len() - 1 {
                        BtcApdu::btc_legacy_sign(0x00, 0x80, &input_data_vec)
                    } else if x == 0 {
                        BtcApdu::btc_legacy_sign(0x00, 0x40, &input_data_vec)
                    } else {
                        BtcApdu::btc_legacy_sign(0x00, 0x00, &input_data_vec)
                    };
                    //send perpare apdu to device
                    ApduCheck::check_response(&send_apdu(btc_perpare_apdu)?)?;
                }

                let btc_sign_apdu = BtcApdu::btc_legacy_sign(
                    0x80 as u8,
                    0x80 as u8,
                    &path_pubkey.path.as_bytes().to_vec(),
                );
                //sign data
                let btc_sign_apdu_return = send_apdu(btc_sign_apdu)?;
                ApduCheck::check_response(&btc_sign_apdu_return)?;
                let btc_sign_apdu_return =
                    &btc_sign_apdu_return[..btc_sign_apdu_return.len() - 4].to_string();
                let sign_result_str =
                    btc_sign_apdu_return[2..btc_sign_apdu_return.len() - 2].to_string();

                lock_script_ver
                    .push(self.build_lock_script(sign_result_str.as_str(), &path_pubkey.pub_key)?);
                // witnesses
                witnesses.push((
                    hex::decode(&sign_result_str)?,
                    hex::decode(&path_pubkey.pub_key)?,
                ));

                // segwit
            } else {
                //txhash and vout
                let txhash_data = serialize(&txin.previous_output);
                data.extend(txhash_data.iter());

                //lock script
                //                let path_pubkey: &PathPubKey = path_and_pubkeys.get(index).unwrap();
                let pub_key_bytes = hex::decode(&path_pubkey.pub_key)?;
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
                let sign_path = &path_pubkey.path;
                address_data.push(sign_path.as_bytes().len() as u8);
                address_data.extend_from_slice(sign_path.as_bytes());

                data.extend(address_data.iter());
                let segwit_sign_apdu = if index == self.unspents.len() - 1 {
                    BtcApdu::btc_segwit_sign(true, 0x01, data)
                } else {
                    BtcApdu::btc_segwit_sign(false, 0x01, data)
                };

                //send sign apdu
                let sign_apdu_return_data = send_apdu(segwit_sign_apdu.clone())?;
                ApduCheck::check_response(&sign_apdu_return_data)?;
                //build signature obj
                let sign_result_vec =
                    Vec::from_hex(&sign_apdu_return_data[2..sign_apdu_return_data.len() - 6])
                        .unwrap();

                let mut signature_obj = Signature::from_compact(sign_result_vec.as_slice())?;
                signature_obj.normalize_s();
                //generator der sign data
                let mut sign_result_vec = signature_obj.serialize_der().to_vec();
                //add hash type
                sign_result_vec.push(EcdsaSighashType::All.to_u32() as u8);

                witnesses.push((sign_result_vec, hex::decode(&path_pubkey.pub_key)?));

                lock_script_ver.push(Script::new());
            }

            txinputs.push(txin.clone());
        }
        tx_to_sign.input = txinputs;

        let input_with_sigs: Result<Vec<TxIn>> = tx_to_sign
            .input
            .iter()
            .enumerate()
            .map(|(i, txin)| {
                let script_pubkey = self.unspents.get(i).unwrap().script_pubkey.clone();
                if script_pubkey.starts_with("76a914") || script_pubkey.starts_with("76A914") {
                    Ok(TxIn {
                        script_sig: lock_script_ver.get(i).unwrap().clone(),
                        witness: Witness::default(),
                        ..*txin
                    })
                    // segwit
                } else if script_pubkey.starts_with("a914") || script_pubkey.starts_with("A914") {
                    let hash = hash160::Hash::hash(
                        hex_to_bytes(&path_and_pubkeys.get(i).unwrap().pub_key)
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
                } else if script_pubkey.starts_with("0014") {
                    Ok(TxIn {
                        script_sig: Script::new(),
                        witness: Witness::from_vec(vec![
                            witnesses[i].0.clone(),
                            witnesses[i].1.clone(),
                        ]),
                        ..*txin
                    })
                } else {
                    return Err(CoinError::UnsupportedScriptPubkey.into());
                }
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

    pub fn get_total_amount(&self) -> i64 {
        let mut total_amount: i64 = 0;
        for unspent in &self.unspents {
            total_amount += unspent.amount;
        }
        total_amount
    }

    pub fn get_change_amount(&self) -> i64 {
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

    pub fn build_lock_script(&self, signed: &str, utxo_public_key: &str) -> Result<Script> {
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
}

#[cfg(test)]
mod tests {
    use crate::transaction::{BtcTransaction, Utxo};
    use bitcoin::{Address, Network};
    use hex::FromHex;
    use std::str::FromStr;

    use ikc_common::error::CoinError;
    use ikc_device::device_binding::bind_test;
    use ikc_device::device_binding::DeviceManage;
    use ikc_transport::hid_api::hid_connect;

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
            derive_path: "0/22".to_string(),
            sequence: 4294967295,
        };
        let utxo2 = Utxo {
            txhash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531".to_string(),
            vout: 1,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 4294967295,
        };
        let utxo3 = Utxo {
            txhash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9".to_string(),
            vout: 0,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 4294967295,
        };
        let utxo4 = Utxo {
            txhash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9".to_string(),
            vout: 1,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
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
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf").unwrap(),
            script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
            derive_path: "0/1".to_string(),
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
            derive_path: "0/22".to_string(),
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
            derive_path: "0/22".to_string(),
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
            derive_path: "0/22".to_string(),
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
            derive_path: "0/22".to_string(),
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
            derive_path: "0/0".to_string(),
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
            derive_path: "0/22".to_string(),
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
            derive_path: "0/0".to_string(),
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
    fn test_native_segwit_bech32_to_bech32_no_change() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "d7c2e585d5eaa185808addb3ef703f2a8fe09288b4f40b757a812d6d63b7c9c4".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "0/0".to_string(),
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
        let sign_result = transaction_req_data.sign_native_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
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
    fn test_native_segwit_bech32_to_bech32_has_change() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "7c99f906e291d453b2c039939598eefd182dafb20d53bd0eebc2a1aa635ff60f".to_string(),
            vout: 0,
            amount: 88000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "0/0".to_string(),
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
        let sign_result = transaction_req_data.sign_native_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
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
    fn test_native_segwit_bech32_to_p2pkh() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "64381306678c6a868e8778adee1ee9d1746e5e8dd3535fcbaa1a25baab49f015".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "0/0".to_string(),
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
        let sign_result = transaction_req_data.sign_native_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
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
    fn test_native_segwit_bech32_to_p2shp2wpkh() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "fcc622970fd80c14b111ee7950bcc309469b575194072209598176123fd06598".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "0/0".to_string(),
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
        let sign_result = transaction_req_data.sign_native_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
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
    fn test_legacy_p2pkh_to_bech32() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "eb3ea0d4b360a304849b90baf49197eb449ca746febd60f8f29cd279c966a3ea".to_string(),
            vout: 0,
            amount: 30000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
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
        let sign_result = transaction_req_data.sign_transaction(
            Network::Testnet,
            &"m/44'/1'/0'".to_string(),
            0,
            &extra_data,
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
    fn test_segwit_p2sh_p2wpkh_to_bech32() {
        //binding device
        bind_test();

        let extra_data = Vec::from_hex("1234").unwrap();
        let utxo = Utxo {
            txhash: "e5add8950cb37b1d80ff18cb2ba775e185e1843b845e18b532dc4b5d8ffec7a9".to_string(),
            vout: 0,
            amount: 30000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
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
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
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
    fn test_native_segwit_bech32_to_bech32_multiutxo() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "401959f94ad3c1c55a6d778f8446625a4b00a0a12a2cdb983fb4423ce93261cc".to_string(),
            vout: 0,
            amount: 26000,
            address: Address::from_str("tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k").unwrap(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "e5add8950cb37b1d80ff18cb2ba775e185e1843b845e18b532dc4b5d8ffec7a9".to_string(),
            vout: 1,
            amount: 13000,
            address: Address::from_str("tb1qvg35wefk2h2ha68g7fvc8ajxhn0ec5pjekus6j").unwrap(),
            script_pubkey: "0014622347653655d57ee8e8f25983f646bcdf9c5032".to_string(),
            derive_path: "1/0".to_string(),
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
        let sign_result = transaction_req_data.sign_native_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
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
    fn test_sign_mixed_p2shp2wpkh_utxo_nochange() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "32f734241b2dee423ee736ddfd26ea341d56a0ded67f4e1c658d0119977c1b3a".to_string(),
            vout: 0,
            amount: 100000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2N5z4KZBCQNULTegkETDftMiNHWEFjrH3m2").unwrap(),
            amount: 90000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 0, &extra_data);

        assert_eq!(
            "020000000001013a1b7c9719018d651c4e7fd6dea0561d34ea26fddd36e73e42ee2d1b2434f7320000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff01905f01000000000017a9148bbb53570df9656926ea0ef029cd2ee84dbc7d0f870247304402202931423820466e0554d99eb93d6c9b6a1b7270c21e1ed7279f98152247103ab602201df7809aa81b66bace7131a260fb1de661c9da9d6ddbb82ceac3c6bbb043122f0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "7151e57d6380546e25778977b6aa298264d0b19de90ed420547681bccc7367a2",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "e6b15dce9a675fb6f503a03bcd216f032eedaf744155d9f84d83e636532f971f",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_mixed_p2shp2wpkh_utxo_haschange() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "8e7bb196a518413b80f08439b71cd7cfcf8b0c19e493f2f19aea1890fb834afe".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2N5z4KZBCQNULTegkETDftMiNHWEFjrH3m2").unwrap(),
            amount: 50000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 53, &extra_data);

        assert_eq!(
            "02000000000101fe4a83fb9018ea9af1f293e4190c8bcfcfd71cb73984f0803b4118a596b17b8e0100000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff0250c300000000000017a9148bbb53570df9656926ea0ef029cd2ee84dbc7d0f87409c0000000000001600147805a6361d2532deac1b62c93288aa159308dcc002483045022100c58e0b67aa08c760e96f22c9cede3ca8341449a0e46f1e092130d055f189cf36022003abd53fd0992088ea9769c1d62508153cd5c39aba9f7b21a20e89feff8ec91b0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );

        assert_eq!(
            "4cb26b6c65aeef1ceb01ecf319ff9b39f3dcb8e88631a9f7808537df204280d7",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "3df0e3129a84853a8b5eb2b0fda58551ffef8cbd7915e1848a3ba97c328e0d8f",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_mixed_single_legacy_and_segwit_utxo_has_change() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "356d5e8628466f072c1de991e14320226ceef944cfebec251dd5c87ea925823c".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "b63ca3592561fd7c8b41017fbb0deff12ce6f7d351128c818dcf4ed1a0beae0e".to_string(),
            vout: 1,
            amount: 1418852,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
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
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 53, &extra_data);
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

    #[test]
    fn test_sign_mixed_single_bech32_utxo_haschange() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "41eb7058313847d1f1b0cfee964a436d55eab5ca29fdbb42dbb5107a85afdda7".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95").unwrap(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99").unwrap(),
            amount: 30000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 53, &extra_data);

        assert_eq!(
            "02000000000101a7ddaf857a10b5db42bbfd29cab5ea556d434a96eecfb0f1d14738315870eb410100000000ffffffff0230750000000000001600140efbea077aa9cdb69569176ef5172de8c13a997360ea0000000000001600147805a6361d2532deac1b62c93288aa159308dcc002483045022100ae80f750fc99a9db1a017fd7021b102524edb7b708611aab83c4fe068c4a47110220743dd9c574956c736d38d3b072bd105b1b4e283ca9a0df2e95c7a6a4373cfe30012102e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c000000000",
            sign_result.as_ref().unwrap().signature
        );

        assert_eq!(
            "cf4c04e47121d05f9839f94c1461a17946627d91f661f8f02b18a7098bf8a1cf",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "f877d39fd8bb5b540881306d4e489d815908d6d1a5ad055955d87c737ee92901",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_mixed_multi_bech32_utxo_haschange() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "80f482aa891508c205a8b2fc52756b827d61aeda63ce909c51403d7bea3b040d".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95").unwrap(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let utxo2 = Utxo {
            txhash: "14b3966c886a64e85829a8ed01498495f5514851121048754cc39824b54aaf7f".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95").unwrap(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99").unwrap(),
            amount: 110000,
            unspents: utxos,
            fee: 20000,
        };
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 53, &extra_data);

        assert_eq!(
            "020000000001020d043bea7b3d40519c90ce63daae617d826b7552fcb2a805c2081589aa82f4800100000000ffffffff7faf4ab52498c34c75481012514851f595844901eda82958e8646a886c96b3140100000000ffffffff02b0ad0100000000001600140efbea077aa9cdb69569176ef5172de8c13a997370110100000000001600147805a6361d2532deac1b62c93288aa159308dcc002483045022100d0c50b5d3641db7417108217a2d686ae6d34f93a69b5856bf3a3bd33531e30ae02206d661be346d456ad9dad0a458169802b0b66df6d6fd7a22eb1586855dd891fe4012102e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c002483045022100be8664eb39f8f6cf5948e43c4a1cdd8cd5aedb6a0e6084709b322fc41a2380be02206831c1776daaad80d75440ac3b773970499c6e17821f434bb271aab0ee84e239012102e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c000000000",
            sign_result.as_ref().unwrap().signature
        );

        assert_eq!(
            "6d1d8f16f93fe99de489e20d5d08b59f0d98754e0a84824889d9a59cc640ffac",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "c7eee8142cace0c128bd512897a7cf51d0417570668aba289321ace5d3fcd111",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_mixed_p2shp2wpkh_and_bech32_utxo_haschange() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "0a7937fe1c6d03fb835aced9f3ca5fd3b2f1c78ed1f5f394ad742a01897157d7".to_string(),
            vout: 0,
            amount: 100000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let utxo2 = Utxo {
            txhash: "94fbcc624b34c6a1e7681312b490f0fbfaf3fb6efe90efb16a57815ea0c34edd".to_string(),
            vout: 0,
            amount: 100000,
            address: Address::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95").unwrap(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99").unwrap(),
            amount: 90000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 53, &extra_data);

        assert_eq!(
            "02000000000102d7577189012a74ad94f3f5d18ec7f1b2d35fcaf3d9ce5a83fb036d1cfe37790a0000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffffdd4ec3a05e81576ab1ef90fe6efbf3fafbf090b4121368e7a1c6344b62ccfb940000000000ffffffff02905f0100000000001600140efbea077aa9cdb69569176ef5172de8c13a9973a0860100000000001600147805a6361d2532deac1b62c93288aa159308dcc002483045022100e44a802d1a9f70e4087541808b39f4ba4b455f6371b471fa0cc122e2e8a163500220423a35e6c79cbe6287cde4b771b37966d6627defac5d0ed57b53e6c9ffa57c1f0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc02473044022018b55722a8c933fcb75309aedb4269d55d2e32549b431822f09019013785b8aa02205980d4f9233bae825cad9cf37b59aeac8fded55c450c59ce02f2bc4bb62352a3012102e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c000000000",
            sign_result.as_ref().unwrap().signature
        );

        assert_eq!(
            "541c4bf93d11bb80e4cf245a568700abdf3fabfeffac2d6231d1ec53d3d7c436",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "4fe029e36c611014de717c214461260574c33c2c6f2f000d083854441ec54128",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_mixed_transaction() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "b7b05e82cd4dad038d7f7545f02940ed959aa8f54b1701688927649f99021e60".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "36671b4b8f72542ae9b9708725119837b233177d28a710204b839343b8a811a0".to_string(),
            vout: 0,
            amount: 100000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo3 = Utxo {
            txhash: "6459945baee1c250c9099f2f23e24af5dbd73292f0d994bef076d3f65356563a".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95").unwrap(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo4 = Utxo {
            txhash: "6d1d8f16f93fe99de489e20d5d08b59f0d98754e0a84824889d9a59cc640ffac".to_string(),
            vout: 1,
            amount: 70000,
            address: Address::from_str("tb1q0qz6vdsay5edatqmvtyn9z92zkfs3hxqvk8k8k").unwrap(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "1/53".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        utxos.push(utxo3);
        utxos.push(utxo4);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99").unwrap(),
            amount: 310000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 53, &extra_data);

        assert_eq!(
            "02000000000104601e02999f6427896801174bf5a89a95ed4029f045757f8d03ad4dcd825eb0b7010000006a47304402205363ea34883d551c35c2338e1809566e424489167e69a404120c6684827443bf02200fbdcb4ff821c5aa28c1633e36406d3597f729b61dd631175d52964397138a7f0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa011a8b84393834b2010a7287d1733b2379811258770b9e92a54728f4b1b67360000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff3a565653f6d376f0be94d9f09232d7dbf54ae2232f9f09c950c2e1ae5b9459640100000000ffffffffacff40c69ca5d9894882840a4e75980d9fb5085d0de289e49de93ff9168f1d6d0100000000ffffffff02f0ba0400000000001600140efbea077aa9cdb69569176ef5172de8c13a997350c30000000000001600147805a6361d2532deac1b62c93288aa159308dcc00002473044022073a93e5bc5f739d9f54198f2d4da1dfc8f79f23a62a8fada6f5edd54f6a1f358022028b3c86a2683cfed9128b2bea71de30e2e3e29e48996a383ec030403c1b716360121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc02483045022100b4608108057f49a58ef4a9e49107232e140cb6729a69b0ac48c0bfeb237bf75e02206b6336c759ef83cb20b073545ca4227b280ebcb2aab932928a967e74bc6e4d42012102e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c00247304402205155631ba66e009c677cc7e4f67183922eaff389719e604d1ff72fe7fbd1b27d0220523baa8575da69b150da6ecf56814bc34820ed1950ec59943b36c0d5451b3ffe01210383f26c44bf1607224237a93e8735ff69a23655878ddb22c46fcdd850417097a400000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "6feccf5e50dbdc94e65cf2bbe89ed614096965aef45d97aa8f38a5c86af827e2",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "1012e522b417abc94f7eb6e07f8194321fa919744edf8760110dcc81846f8fec",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_mixed_single_legacy_utxotransaction() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "1cd9bfa2cabf071aca138e38e7ba281fa0aa26dd554d3518a2f3f74d33e9d3f5".to_string(),
            vout: 0,
            amount: 100000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo);

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2N5z4KZBCQNULTegkETDftMiNHWEFjrH3m2").unwrap(),
            amount: 30000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 53, &extra_data);

        assert_eq!(
            "0200000001f5d3e9334df7f3a218354d55dd26aaa01f28bae7388e13ca1a07bfcaa2bfd91c000000006a4730440220435b303f902c3df7a1d26fef8548eeb902ed7e2d3c8e94bed2afd1e2cfb7853802202d93753138a9464a7505d76489758e6aa5a88bfcf6e2ef7387e321739421d5150121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02307500000000000017a9148bbb53570df9656926ea0ef029cd2ee84dbc7d0f8760ea0000000000001600147805a6361d2532deac1b62c93288aa159308dcc000000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "db8c637e1b3f24a90e7bfcba130a2ce062a6681c00efdd6b996c9e8b18072ac3",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "db8c637e1b3f24a90e7bfcba130a2ce062a6681c00efdd6b996c9e8b18072ac3",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_legacy_transaction_max_utxo() {
        //binding device
        bind_test();

        let utxo = Utxo {
            txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a".to_string(),
            vout: 0,
            amount: 200000000,
            address: Address::from_str("mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC").unwrap(),
            script_pubkey: "76a914118c3123196e030a8a607c22bafc1577af61497d88ac".to_string(),
            derive_path: "0/22".to_string(),
            sequence: 4294967295,
        };
        let utxo2 = Utxo {
            txhash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531".to_string(),
            vout: 1,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 4294967295,
        };
        let utxo3 = Utxo {
            txhash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9".to_string(),
            vout: 0,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 4294967295,
        };
        let utxo4 = Utxo {
            txhash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9".to_string(),
            vout: 1,
            amount: 200000000,
            address: Address::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN").unwrap(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 4294967295,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        utxos.push(utxo3);
        utxos.push(utxo4.clone());
        for _index in (0..996) {
            utxos.push(utxo4.clone());
        }
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3").unwrap(),
            amount: 799988000,
            unspents: utxos.clone(),
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Testnet,
            &"m/44'/1'/0'".to_string(),
            53,
            &vec![],
        );
        println!("txhash-->{}", sign_result.as_ref().unwrap().tx_hash);
        println!("wtxid-->{}", sign_result.as_ref().unwrap().wtx_id);
        assert_eq!(
            "0dfc247c0b8ee8eaa3c29824c009d35e3aee682bae02554edc5975b7988e5550",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "8487e3008f911e9a974d913d86475f411c07622d348658cd617d23a40bcb865c",
            sign_result.as_ref().unwrap().wtx_id
        );
        let extra_data = Vec::from_hex("0200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa99385").unwrap();
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3").unwrap(),
            amount: 750000000,
            unspents: utxos,
            fee: 502130,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Testnet,
            &"m/44'/1'/0'".to_string(),
            53,
            &extra_data,
        );
        println!("txhash-->{}", sign_result.as_ref().unwrap().tx_hash);
        println!("wtxid-->{}", sign_result.as_ref().unwrap().wtx_id);
        assert_eq!(
            "97d57a48ed27e05461f8bb674403189ee8041c9446d1bf20a00ec30496dbd0a4",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "e0381d9f5940b76ebb3784bda762cb120dd685bea67d941874d91a6f02d43f58",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_segwit_transaction_max_utxo() {
        //binding device
        bind_test();

        let utxo = Utxo {
            txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf").unwrap(),
            script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
            derive_path: "0/1".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2.clone());
        for index in (0..998) {
            utxos.push(utxo2.clone());
        }
        let transaction_req_data = BtcTransaction {
            to: Address::from_str("2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp").unwrap(),
            amount: 88000,
            unspents: utxos.clone(),
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &vec![],
        );
        println!("txhash-->{}", sign_result.as_ref().unwrap().tx_hash);
        println!("wtxid-->{}", sign_result.as_ref().unwrap().wtx_id);
        assert_eq!(
            "83a87c473210fa5d2dabf4cd3157b46b2bb3097739388a92fb7b404203842c6a",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "4e49394a0a8dc1005864459189ac9f6174f1464a2d0d6b0f4afa8c3d1b187c51",
            sign_result.as_ref().unwrap().wtx_id
        );
        let extra_data = Vec::from_hex("1234").unwrap();
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Testnet,
            &"m/49'/1'/0'/".to_string(),
            0,
            &extra_data,
        );
        println!("txhash-->{}", sign_result.as_ref().unwrap().tx_hash);
        println!("wtxid-->{}", sign_result.as_ref().unwrap().wtx_id);
        assert_eq!(
            "5e2489a71e2395eb53166779d107042a95e65a57df0693b45ee917f054e05e68",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "e9bb76239849a6c6d4d5a831a9eaf78c721d2809d8c52d528e2a3d7d8f93c301",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_native_segwit_max_utxo() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "41eb7058313847d1f1b0cfee964a436d55eab5ca29fdbb42dbb5107a85afdda7".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95").unwrap(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo.clone());
        // utxos.push(utxo2.clone());
        for index in (0..250) {
            utxos.push(utxo.clone());
        }

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99").unwrap(),
            amount: 30000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result = transaction_req_data.sign_native_segwit_transaction(
            Network::Testnet,
            &"m/84'/1'/0'/".to_string(),
            53,
            &extra_data,
        );

        println!("{}", sign_result.as_ref().unwrap().signature);
        println!("{}", sign_result.as_ref().unwrap().tx_hash);
        println!("{}", sign_result.as_ref().unwrap().wtx_id);
        assert_eq!(
            "dec7cb804eca87af49259b8bddda94867913a8bc7236c6ef363c9370e06e424b",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "333360e695476ec06e40e1824f3c76f54a8e393958edc89d585f9e3f6ac62d9b",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_mixed_max_utxo() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "41eb7058313847d1f1b0cfee964a436d55eab5ca29fdbb42dbb5107a85afdda7".to_string(),
            vout: 1,
            amount: 100000,
            address: Address::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95").unwrap(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f".to_string(),
            vout: 0,
            amount: 50000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };
        let utxo3 = Utxo {
            txhash: "0a7937fe1c6d03fb835aced9f3ca5fd3b2f1c78ed1f5f394ad742a01897157d7".to_string(),
            vout: 0,
            amount: 100000,
            address: Address::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "0/0".to_string(),
            sequence: 0,
        };

        let mut utxos = Vec::new();
        utxos.push(utxo.clone());
        utxos.push(utxo2.clone());
        utxos.push(utxo3.clone());
        for index in (0..100) {
            utxos.push(utxo.clone());
            utxos.push(utxo2.clone());
            utxos.push(utxo3.clone());
        }

        let transaction_req_data = BtcTransaction {
            to: Address::from_str("tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99").unwrap(),
            amount: 30000,
            unspents: utxos,
            fee: 10000,
        };
        let sign_result =
            transaction_req_data.sign_mixed_transaction(Network::Testnet, 53, &extra_data);

        assert_eq!(
            "5db9fa2c5e606997ca5005e032f4351034d45df4f032b3d717e520d37d321678",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "6831921a9b602c9cab7e8163c821a4f0b26c94a1a307d6808916a1dde8084977",
            sign_result.as_ref().unwrap().wtx_id
        );
    }
}
