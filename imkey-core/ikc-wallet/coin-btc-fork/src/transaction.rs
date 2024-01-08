use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::consensus::{serialize, Encodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::{
    EcdsaSighashType, Network, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use bitcoin_hashes::hash160;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::Hash;
use ikc_common::apdu::{ApduCheck, BtcForkApdu};
use ikc_common::coin_info::CoinInfo;
use ikc_common::constants::{
    BTC_FORK_DUST, EACH_ROUND_NUMBER, MAX_OPRETURN_SIZE, MAX_UTXO_NUMBER, TIMEOUT_LONG,
};
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{bigint_to_byte_vec, hex_to_bytes, secp256k1_sign};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::ecdsa::Signature;
use std::str::FromStr;

use crate::address::BtcForkAddress;
use crate::btc_fork_network::network_from_param;
use crate::btcforkapi::BtcForkTxInput;
use crate::common::{
    address_verify, get_address_version, get_xpub_data, secp256k1_sign_verify, TransTypeFlg,
    TxSignResult,
};
use crate::Result;

pub struct BtcForkTransaction {
    pub tx_input: BtcForkTxInput,
    pub coin_info: CoinInfo,
}

impl BtcForkTransaction {
    pub fn sign_transaction(
        &self,
        network: Network,
        path: &str,
        extra_data: &Vec<u8>,
    ) -> Result<TxSignResult> {
        //path check
        check_path_validity(path)?;
        let bip44_segments: Vec<&str> = path.split("/").collect();
        let is_full_path = bip44_segments.len() == 6;
        let mut path_str: String = path.to_string();
        if !path.ends_with("/") && !is_full_path {
            path_str = format!("{}{}", path_str, "/");
        }
        //check uxto number
        if &self.tx_input.unspents.len() > &MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }

        //get xpub and sign data
        let xpub_data = get_xpub_data(path_str.as_str(), true)?;
        let xpub_data = &xpub_data[..xpub_data.len() - 4].to_string();

        //parsing xpub data
        let sign_source_val = &xpub_data[..194];
        let sign_result = &xpub_data[194..];
        let pub_key = &sign_source_val[..130];
        let chain_code = &sign_source_val[130..];

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
            &self.tx_input.unspents,
            pub_key,
            hex::decode(chain_code).unwrap().as_slice(),
            network,
            TransTypeFlg::BTC,
        )?;

        //calc utxo total amount
        if self.get_total_amount() < self.tx_input.amount {
            return Err(CoinError::ImkeyInsufficientFunds.into());
        }

        //add send to output
        let mut txouts: Vec<TxOut> = vec![];
        txouts.push(self.build_send_to_output());

        //add change output
        if self.get_change_amount() > BTC_FORK_DUST {
            //add change output
            let change_addr = self.get_change_address(
                path,
                self.tx_input.change_address_index as i32,
                &self.tx_input.change_address,
            )?;
            txouts.push(TxOut {
                value: self.get_change_amount() as u64,
                script_pubkey: change_addr.payload.script_pubkey(),
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
        // output_serialize_data.extend(SigHashType::All.serialize().iter());
        let mut encoder_hash = Vec::new();
        let len = EcdsaSighashType::All
            .to_u32()
            .consensus_encode(&mut encoder_hash)
            .unwrap();
        debug_assert_eq!(len, encoder_hash.len());
        output_serialize_data.extend(encoder_hash);
        //set input number
        output_serialize_data.remove(4);
        output_serialize_data.insert(4, self.tx_input.unspents.len() as u8);

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.tx_input.fee));

        //add address version
        let address_version = get_address_version(network, self.tx_input.to.to_string().as_str())?;
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

        let btc_prepare_apdu_vec = BtcForkApdu::btc_fork_prepare(0x49, 0x00, &output_pareper_data);
        for temp_str in btc_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu_timeout(temp_str, TIMEOUT_LONG)?)?;
        }

        let mut lock_script_ver: Vec<Script> = vec![];
        let count = (self.tx_input.unspents.len() - 1) / EACH_ROUND_NUMBER + 1;
        for i in 0..count {
            for (x, temp_utxo) in self.tx_input.unspents.iter().enumerate() {
                let mut input_data_vec = vec![];
                input_data_vec.push(x as u8);

                let mut temp_serialize_txin = TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::hash_types::Txid::from_hex(temp_utxo.tx_hash.as_str())?,
                        vout: temp_utxo.vout as u32,
                    },
                    script_sig: Script::default(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                };
                if (x >= i * EACH_ROUND_NUMBER) && (x < (i + 1) * EACH_ROUND_NUMBER) {
                    // temp_serialize_txin.script_sig =
                    //     Script::from(Vec::from_hex(temp_utxo.script_pub_key.as_str())?);
                    temp_serialize_txin.script_sig =
                        Script::from_hex(temp_utxo.script_pub_key.as_str())?;
                }
                input_data_vec.extend_from_slice(serialize(&temp_serialize_txin).as_slice());
                let btc_perpare_apdu =
                    BtcForkApdu::btc_fork_perpare_input(0x49, 0x80, &input_data_vec);
                //send perpare apdu to device
                ApduCheck::check_response(&send_apdu(btc_perpare_apdu)?)?;
            }
            for y in i * EACH_ROUND_NUMBER..(i + 1) * EACH_ROUND_NUMBER {
                if y >= utxo_pub_key_vec.len() {
                    break;
                }
                let btc_sign_apdu = BtcForkApdu::btc_fork_sign(
                    0x4A,
                    y as u8,
                    EcdsaSighashType::All.to_u32() as u8,
                    format!(
                        "{}{}",
                        path_str,
                        self.tx_input.unspents.get(y).unwrap().derived_path
                    )
                    .as_str(),
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
        for (index, unspent) in self.tx_input.unspents.iter().enumerate() {
            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.tx_hash)?,
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
        extra_data: &Vec<u8>,
    ) -> Result<TxSignResult> {
        //path check
        check_path_validity(path)?;
        let bip44_segments: Vec<&str> = path.split("/").collect();
        let is_full_path = bip44_segments.len() == 6;
        let mut path_str: String = path.to_string();
        if !path.ends_with("/") && !is_full_path {
            path_str = format!("{}{}", path_str, "/");
        }
        //check utxo number
        if &self.tx_input.unspents.len() > &MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }

        //get xpub and sign data
        let xpub_data = get_xpub_data(path_str.as_str(), true)?;
        let xpub_data = &xpub_data[..xpub_data.len() - 4].to_string();

        //parsing xpub data
        let sign_source_val = &xpub_data[..194];
        let sign_result = &xpub_data[194..];
        let pub_key = &sign_source_val[..130];
        let chain_code = &sign_source_val[130..];

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
            &self.tx_input.unspents,
            pub_key,
            hex::decode(chain_code).unwrap().as_slice(),
            network,
            TransTypeFlg::SEGWIT,
        )?;

        //calc utxo total amount
        if self.get_total_amount() < self.tx_input.amount {
            return Err(CoinError::ImkeyInsufficientFunds.into());
        }

        //add send to output
        let mut txouts: Vec<TxOut> = Vec::new();
        txouts.push(self.build_send_to_output());

        //add change output
        if self.get_change_amount() > BTC_FORK_DUST {
            //add change output
            let change_addr = self.get_change_address(
                path,
                self.tx_input.change_address_index as i32,
                &self.tx_input.change_address,
            )?;
            txouts.push(TxOut {
                value: self.get_change_amount() as u64,
                script_pubkey: change_addr.payload.script_pubkey(),
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
        // output_serialize_data.extend(SigHashType::All.serialize().iter());
        let mut encoder_hash = Vec::new();
        let len = EcdsaSighashType::All
            .to_u32()
            .consensus_encode(&mut encoder_hash)
            .unwrap();
        debug_assert_eq!(len, encoder_hash.len());
        output_serialize_data.extend(encoder_hash);

        //set input number
        output_serialize_data.remove(4);
        output_serialize_data.insert(4, self.tx_input.unspents.len() as u8);

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.tx_input.fee));

        //add address version
        let address_version = get_address_version(network, self.tx_input.to.to_string().as_str())?;
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

        let btc_prepare_apdu_vec = BtcForkApdu::btc_fork_prepare(0x39, 0x00, &output_pareper_data);
        //send output pareper command
        for temp_str in btc_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu_timeout(temp_str, TIMEOUT_LONG)?)?;
        }

        let mut txinputs: Vec<TxIn> = vec![];
        let mut txhash_vout_vec = vec![];
        let mut sequence_vec: Vec<u8> = vec![];
        let mut sign_apdu_vec: Vec<String> = vec![];
        for (index, unspent) in self.tx_input.unspents.iter().enumerate() {
            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.tx_hash)?,
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
            // let script = Script::from(hex::decode(script_hex)?);
            let script = Script::from_hex(script_hex.as_str())?;
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
            let sign_path = format!("{}{}", path_str, unspent.derived_path);
            address_data.push(sign_path.as_bytes().len() as u8);
            address_data.extend_from_slice(sign_path.as_bytes());

            data.extend(address_data.iter());
            if index == self.tx_input.unspents.len() - 1 {
                sign_apdu_vec.push(BtcForkApdu::btc_fork_segwit_sign(0x3A, true, 0x01, data));
            } else {
                sign_apdu_vec.push(BtcForkApdu::btc_fork_segwit_sign(0x3A, false, 0x01, data));
            }

            txinputs.push(txin.clone());
        }
        tx_to_sign.input = txinputs;

        let mut txhash_vout_prepare_apdu_vec =
            BtcForkApdu::btc_fork_prepare(0x39, 0x40, &txhash_vout_vec);
        let mut sequence_prepare_apdu_vec =
            BtcForkApdu::btc_fork_prepare(0x39, 0x80, &sequence_vec);
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
                    script_sig: Script::from_hex(hex.as_str())?,
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

    pub fn get_total_amount(&self) -> i64 {
        let mut total_amount: i64 = 0;
        for unspent in &self.tx_input.unspents {
            total_amount += unspent.amount;
        }
        total_amount
    }

    pub fn get_change_amount(&self) -> i64 {
        let total_amount = self.get_total_amount();
        let change_amout = total_amount - self.tx_input.amount - self.tx_input.fee;
        change_amout
    }

    pub fn build_send_to_output(&self) -> TxOut {
        let legacy_addr = BtcForkAddress::from_str(&self.tx_input.to).unwrap();
        TxOut {
            value: self.tx_input.amount as u64,
            script_pubkey: legacy_addr.payload.script_pubkey(),
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

    fn get_change_address(
        &self,
        path: &str,
        change_idx: i32,
        change_address: &str,
    ) -> Result<BtcForkAddress> {
        let addr = if !change_address.is_empty() {
            if !BtcForkAddress::is_valid(change_address, &self.coin_info) {
                return Err(CoinError::InvalidAddress.into());
            }
            change_address.to_string()
        } else {
            let path_temp = format!("{}{}{}", path, "1/", change_idx);

            if &self.tx_input.seg_wit.to_uppercase() == "P2WPKH" {
                let network = network_from_param(
                    &self.coin_info.coin,
                    &self.coin_info.network,
                    &self.coin_info.seg_wit,
                )
                .unwrap();
                BtcForkAddress::p2shwpkh(&network, &path_temp)?
            } else {
                let network =
                    network_from_param(&self.coin_info.coin, &self.coin_info.network, "NONE")
                        .unwrap();
                BtcForkAddress::p2pkh(&network, &path_temp)?
            }
        };
        BtcForkAddress::from_str(&addr)
    }
}

#[cfg(test)]
mod tests {
    use crate::btcforkapi::BtcForkTxInput;
    use crate::btcforkapi::Utxo;
    use crate::transaction::BtcForkTransaction;
    use bitcoin::Network;
    use ikc_common::coin_info::coin_info_from_param;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_sign_simple_ltc() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458".to_string(),
            vout: 0,
            amount: 1000000,
            address: "myxdgXjCRgAskD2g1b6WJttJbuv67hq6sQ".to_string(),
            script_pub_key: "76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac".to_string(),
            derived_path: "0/0".to_string(),
            sequence: 0,
        };
        let mut unspents = Vec::new();
        unspents.push(utxo);

        let tx_input = BtcForkTxInput {
            to: "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc".to_string(),
            amount: 500000,
            unspents,
            fee: 100000,
            change_address_index: 1u32,
            change_address: "".to_string(),
            seg_wit: "NONE".to_string(),
        };

        let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap();
        let transaction_req_data = BtcForkTransaction {
            tx_input,
            coin_info,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Testnet,
            &"m/44'/2'/0'/".to_string(),
            &extra_data,
        );

        assert_eq!(
            "01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000006b483045022100b73ecae568a16b17c556d86afab4e71131848f02e888439a978cb9c1b32df95702201a4d63b36cc5a623114443a6fe9d3ee8dc95611488f49bcdfbcb89df9c89dd3b01210289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7bffffffff0220a10700000000001976a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac801a0600000000001976a914cee8ec4d3d43bfe9150e0e66c781bf1d84e6ad3288ac00000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_change_address_ltc() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458".to_string(),
            vout: 0,
            amount: 1000000,
            address: "myxdgXjCRgAskD2g1b6WJttJbuv67hq6sQ".to_string(),
            script_pub_key: "76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac".to_string(),
            derived_path: "0/0".to_string(),
            sequence: 0,
        };
        let mut unspents = Vec::new();
        unspents.push(utxo);

        let tx_input = BtcForkTxInput {
            to: "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc".to_string(),
            amount: 500000,
            unspents,
            fee: 100000,
            change_address_index: 2u32, //not match
            change_address: "mzNzXMAr177bkh229sMUbHtX6wrkViy6dE".to_string(),
            seg_wit: "NONE".to_string(),
        };

        let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap();
        let transaction_req_data = BtcForkTransaction {
            tx_input,
            coin_info,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Testnet,
            &"m/44'/2'/0'/".to_string(),
            &extra_data,
        );

        assert_eq!(
            "01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000006b483045022100b73ecae568a16b17c556d86afab4e71131848f02e888439a978cb9c1b32df95702201a4d63b36cc5a623114443a6fe9d3ee8dc95611488f49bcdfbcb89df9c89dd3b01210289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7bffffffff0220a10700000000001976a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac801a0600000000001976a914cee8ec4d3d43bfe9150e0e66c781bf1d84e6ad3288ac00000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_segwit_ltc() {
        //binding device
        bind_test();
        let extra_data = vec![];
        let unspents = vec![Utxo {
            tx_hash: "e868b66e75376add2154acb558cf45ff7b723f255e2aca794da1548eb945ba8b".to_string(),
            vout: 1,
            amount: 19850000,
            address: "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd".to_string(),
            script_pub_key: "76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac".to_string(),
            derived_path: "0/0".to_string(),
            sequence: 0,
        }];
        let tx_input = BtcForkTxInput {
            to: "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd".to_string(),
            amount: 19800000,
            unspents,
            fee: 50000,
            change_address_index: 1u32,
            change_address: "".to_string(),
            seg_wit: "".to_string(),
        };
        let coin_info = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
        let transaction_req_data = BtcForkTransaction {
            tx_input,
            coin_info,
        };
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Bitcoin,
            &"m/44'/2'/0'/".to_string(),
            &extra_data,
        );

        assert_eq!(
            "020000000001018bba45b98e54a14d79ca2a5e253f727bff45cf58b5ac5421dd6a37756eb668e80100000017160014ca4d8acded69ce4f05d0925946d261f86c675fd8ffffffff01c01f2e010000000017a91400aff21f24bc08af58e41e4186d8492a10b84f9e8702483045022100d11b3f5959fde1a4ce0fc37bc423d0972338f5e116999f1bcbf0c6ac6aa9d3ea02201e223b6115f13c49cc902c6c794c71c43ab5acd1ada5909315f7a321ee06671701210289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7b00000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_segwit_ltc_fullpath() {
        //binding device
        bind_test();
        let extra_data = vec![];
        let unspents = vec![Utxo {
            tx_hash: "e868b66e75376add2154acb558cf45ff7b723f255e2aca794da1548eb945ba8b".to_string(),
            vout: 1,
            amount: 19850000,
            address: "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd".to_string(),
            script_pub_key: "76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac".to_string(),
            derived_path: "".to_string(),
            sequence: 0,
        }];
        let tx_input = BtcForkTxInput {
            to: "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd".to_string(),
            amount: 19800000,
            unspents,
            fee: 50000,
            change_address_index: 1u32,
            change_address: "".to_string(),
            seg_wit: "".to_string(),
        };
        let coin_info = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
        let transaction_req_data = BtcForkTransaction {
            tx_input,
            coin_info,
        };
        let sign_result = transaction_req_data.sign_segwit_transaction(
            Network::Bitcoin,
            &"m/44'/2'/0'/0/0".to_string(),
            &extra_data,
        );

        assert_eq!(
            "020000000001018bba45b98e54a14d79ca2a5e253f727bff45cf58b5ac5421dd6a37756eb668e80100000017160014ca4d8acded69ce4f05d0925946d261f86c675fd8ffffffff01c01f2e010000000017a91400aff21f24bc08af58e41e4186d8492a10b84f9e8702483045022100d11b3f5959fde1a4ce0fc37bc423d0972338f5e116999f1bcbf0c6ac6aa9d3ea02201e223b6115f13c49cc902c6c794c71c43ab5acd1ada5909315f7a321ee06671701210289ca41680edbc5594ee6378ebd937e42cd6b4b969e40dd82c20ef2a8aa5bad7b00000000",
            sign_result.as_ref().unwrap().signature
        );
    }
}
