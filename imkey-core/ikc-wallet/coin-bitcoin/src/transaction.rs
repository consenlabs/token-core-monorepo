use crate::btc_kin_address::{AddressTrait, BtcKinAddress, ImkeyPublicKey};
use crate::common::{get_address_version, get_utxo_pub_key, TxSignResult};
use crate::network::BtcKinNetwork;
use crate::Result;
use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::consensus::{serialize, Encodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::taproot::TapTweakHash;
use bitcoin::{
    Address, EcdsaSighashType, OutPoint, PackedLockTime, SchnorrSighashType, Script, Sequence,
    Transaction, TxIn, TxOut, WPubkeyHash, Witness,
};
use bitcoin_hashes::hash160;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::Hash;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::constants::{
    BTC_SEG_WIT_TYPE_P2WPKH, EACH_ROUND_NUMBER, MAX_OPRETURN_SIZE, MAX_UTXO_NUMBER,
    MIN_NONDUST_OUTPUT, TIMEOUT_LONG,
};
use ikc_common::error::{CoinError, CommonError};
use ikc_common::path::{check_path_validity, get_account_path};
use ikc_common::utility::{bigint_to_byte_vec, hex_to_bytes, network_convert, secp256k1_sign};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_btc_apple_version;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::ecdsa::Signature;
use secp256k1::PublicKey;
use std::str::FromStr;

//The address version set supported by bitcoin applet versions lower than 1.6.00
const VALID_ADDRESS_VERSIONS: [u8; 7] = [0, 111, 5, 196, 113, 30, 22];

#[derive(Clone)]
pub struct Utxo {
    pub txhash: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub script_pubkey: String,
    pub derive_path: String,
    pub sequence: i64,
}

pub struct BtcTransaction {
    pub to: String,
    pub amount: u64,
    pub unspents: Vec<Utxo>,
    pub fee: u64,
    pub chain_type: String,
}

impl BtcTransaction {
    pub fn sign_transaction(
        &self,
        network: &str,
        path: &str,
        change_idx: Option<u32>,
        extra_data: Option<&str>,
        seg_wit: &str,
    ) -> Result<TxSignResult> {
        //path check
        check_path_validity(path)?;

        //check uxto number
        if &self.unspents.len() > &MAX_UTXO_NUMBER {
            return Err(CoinError::ImkeyExceededMaxUtxoNumber.into());
        }

        //calc utxo total amount
        if self.get_total_amount() < self.amount {
            return Err(CoinError::ImkeyInsufficientFunds.into());
        }

        //get current btc applet version
        let btc_version = get_btc_apple_version()?;

        //utxo address verify
        let utxo_pub_key_vec = get_utxo_pub_key(&self.unspents)?;

        let output = self.tx_output(change_idx, &path, network, seg_wit, extra_data)?;

        let mut tx_to_sign = Transaction {
            version: 1i32,
            lock_time: PackedLockTime::ZERO,
            input: vec![],
            output,
        };

        self.calc_tx_hash(&mut tx_to_sign, &btc_version)?;

        //Compatible with Legacy and Nested Segwit transactions without upgrading btc apples
        if btc_version.as_str() >= "1.6.00" {
            self.tx_preview(&tx_to_sign, network)?;
            for (idx, utxo) in self.unspents.iter().enumerate() {
                let script = Script::from_str(&utxo.script_pubkey)?;
                if script.is_p2pkh() {
                    self.sign_p2pkh_input(idx, &utxo_pub_key_vec[idx], &mut tx_to_sign)?;
                } else if script.is_p2sh() {
                    self.sign_p2sh_nested_p2wpkh_input(
                        idx,
                        &utxo_pub_key_vec[idx],
                        &mut tx_to_sign,
                    )?;
                } else if script.is_v0_p2wpkh() {
                    self.sign_p2wpkh_input(idx, &utxo_pub_key_vec[idx], &mut tx_to_sign)?;
                } else if script.is_v1_p2tr() {
                    self.sign_p2tr_input(
                        idx,
                        &utxo_pub_key_vec[idx],
                        &mut tx_to_sign,
                        SchnorrSighashType::Default,
                    )?;
                } else {
                    return Err(CoinError::InvalidUtxo.into());
                };
            }
        } else {
            for utxo in self.unspents.iter() {
                let script = Script::from_str(&utxo.script_pubkey)?;
                if !script.is_p2pkh() && !script.is_p2sh() {
                    return Err(CoinError::InvalidUtxo.into());
                }
            }
            let address_version =
                get_address_version(network_convert(network), &self.to.to_string())?;
            if VALID_ADDRESS_VERSIONS.contains(&address_version) {
                if BTC_SEG_WIT_TYPE_P2WPKH.eq(&seg_wit.to_uppercase()) {
                    self.original_tx_preview(&tx_to_sign, network)?;
                    for (idx, _) in self.unspents.iter().enumerate() {
                        self.sign_p2sh_nested_p2wpkh_input(
                            idx,
                            &utxo_pub_key_vec[idx],
                            &mut tx_to_sign,
                        )?;
                    }
                } else {
                    self.tx_preview(&tx_to_sign, network)?;
                    self.sign_p2pkh_inputs(&utxo_pub_key_vec, &mut tx_to_sign)?;
                }
            } else {
                return Err(CoinError::InvalidAddress.into());
            }
        }

        let tx_bytes = serialize(&tx_to_sign);

        Ok(TxSignResult {
            signature: tx_bytes.to_hex(),
            tx_hash: tx_to_sign.txid().to_hex(),
            wtx_id: tx_to_sign.wtxid().to_hex(),
        })
    }

    pub fn sign_p2pkh_inputs(
        &self,
        utxo_pub_key_vec: &Vec<String>,
        transaction: &mut Transaction,
    ) -> Result<()> {
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
        transaction.input = txinputs;
        Ok(())
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
            if x == idx {
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
        let address = Address::from_str(&unspent.address)?;
        let script = address
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
        let public_key = PublicKey::from_str(pub_key)?;
        let untweaked_public_key = UntweakedPublicKey::from(public_key);
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
            script_pubkey: BtcKinAddress::from_str(&self.to).unwrap().script_pubkey()
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

    pub fn tx_output(
        &self,
        change_idx: Option<u32>,
        change_path: &str,
        network: &str,
        seg_wit: &str,
        extra_data: Option<&str>,
    ) -> Result<Vec<TxOut>> {
        let mut outputs = vec![];
        //to output
        outputs.push(self.build_send_to_output());
        //change output
        if self.get_change_amount() >= MIN_NONDUST_OUTPUT {
            let change_script = if let Some(change_address_index) = change_idx {
                let change_path = format!(
                    "{}{}{}",
                    get_account_path(change_path)?,
                    "/1/",
                    change_address_index
                );
                let pub_key = ImkeyPublicKey::get_pub_key(&change_path)?;
                let network = BtcKinNetwork::find_by_coin(&self.chain_type, network);
                if network.is_none() {
                    return Err(CommonError::MissingNetwork.into());
                }

                let change_address =
                    BtcKinAddress::from_public_key(&pub_key, network.unwrap(), seg_wit)?;
                change_address.script_pubkey()
                // let change_address = Address::from_str(&change_address)?;
                // change_address.script_pubkey()
            } else {
                BtcKinAddress::from_str(&self.unspents[0].address.to_string())?.script_pubkey()
            };
            outputs.push(TxOut {
                value: self.get_change_amount(),
                script_pubkey: change_script,
            });
        }
        //add the op_return
        if extra_data.is_some() {
            let op_return = hex_to_bytes(extra_data.unwrap())?;
            if op_return.len() > MAX_OPRETURN_SIZE {
                return Err(CoinError::ImkeySdkIllegalArgument.into());
            }
            outputs.push(self.build_op_return_output(&op_return))
        }

        Ok(outputs)
    }

    pub fn calc_tx_hash(
        &self,
        transaction: &mut Transaction,
        btc_applet_version: &str,
    ) -> Result<()> {
        let mut txhash_vout_vec = vec![];
        let mut sequence_vec = vec![];
        let mut amount_vec = vec![];
        let mut script_pubkeys_vec = vec![];
        for unspent in self.unspents.iter() {
            let address = BtcKinAddress::from_str(&unspent.address)?;
            if !address.script_pubkey().is_p2pkh() {
                transaction.version = 2i32;
            }

            let tx_in = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&unspent.txhash)?,
                    vout: unspent.vout,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };

            txhash_vout_vec.extend(serialize(&tx_in.previous_output));
            sequence_vec.extend(serialize(&tx_in.sequence));
            amount_vec.extend(serialize(&unspent.amount));
            script_pubkeys_vec.extend(serialize(&address.script_pubkey()));
        }
        if transaction.version == 2 {
            let mut calc_hash_apdu = vec![];
            calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x40, &txhash_vout_vec));
            calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x80, &sequence_vec));
            if btc_applet_version >= "1.6.00" {
                calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x20, &amount_vec));
                calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x21, &script_pubkeys_vec));
            }
            for apdu in calc_hash_apdu {
                ApduCheck::check_response(&send_apdu(apdu)?)?;
            }
        }
        Ok(())
    }

    pub fn tx_preview(&self, transaction: &Transaction, network: &str) -> Result<()> {
        let mut output_serialize_data = serialize(&transaction);

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
        let network = network_convert(network);
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

        Ok(())
    }

    /**
     *original Nested Segwit transaction preview
     **/
    pub fn original_tx_preview(&self, transaction: &Transaction, network: &str) -> Result<()> {
        let mut output_serialize_data = serialize(&transaction);

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
        let network = network_convert(network);
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::{BtcTransaction, Utxo};
    use bitcoin::psbt::serialize::Deserialize;
    use bitcoin::{Address, Network, Transaction};
    use bitcoin_hashes::hex::ToHex;
    use hex::FromHex;
    use ikc_common::utility::hex_to_bytes;
    use ikc_device::device_binding::bind_test;
    use secp256k1::schnorr::Signature;
    use secp256k1::{Message, Secp256k1, XOnlyPublicKey};
    use std::str::FromStr;

    #[test]
    fn test_sign_p2pkh() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a"
                    .to_string(),
                vout: 0,
                amount: 200000000,
                address: "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC".to_string(),
                script_pubkey: "76a914118c3123196e030a8a607c22bafc1577af61497d88ac".to_string(),
                derive_path: "m/44'/1'/0'/0/22".to_string(),
                sequence: 4294967295,
            },
            Utxo {
                txhash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531"
                    .to_string(),
                vout: 1,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 4294967295,
            },
            Utxo {
                txhash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9"
                    .to_string(),
                vout: 0,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 4294967295,
            },
            Utxo {
                txhash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9"
                    .to_string(),
                vout: 1,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 4294967295,
            },
        ];

        let transaction = BtcTransaction {
            to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
            amount: 799988000,
            unspents: utxos,
            fee: 10000,
            chain_type: "DOGECOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/44'/1'/0'".to_string(),
            Some(53),
            Some("0200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa99385"),
            "DEFAULT",
        );
        assert_eq!(
            "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006b483045022100c7755417be55e4fa04896ce424609ef1b12e82a8adb94fbb6c99c62f521f2eb5022075d21cc4fc534024d993c30536fe1a51a4fdf07defe14209d5696acf354edec301210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006a47304402202e3ed884e978eab56b14860b0ce56c230ace84d1ba4bf233df21ec934b57afa00220346a624c16cee70c8fea6818e008c2151946eadd04a62b47b4cc73d8a55ae7ab0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006a473044022011561ce180af03beb2f4a0b4a086bf2d6afc84efd7329104e229c960c54e7c4f0220626bafb1bd38fcf8c2152c94f1563fce89b46f0616ce3533801390bd4663bf960121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006a4730440220420bed1fc49d9ac045c1a16c7acb40676cfb144a7dc82b69a63977ddc44ca99e0220276bec561f39e8c5de8a3a35be4fa80ca5889939537768cca7c26345149aa0690121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff0320d9ae2f000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088acd0070000000000001976a91412967cdd9ceb72bbdbb7e5db85e2dbc6d6c3ab1a88ac0000000000000000536a4c500200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa9938500000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "aa9b55f0bdc2330b31af00ea89aa2f54e508dc708a5aacb4ce76e7431245f29b",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "aa9b55f0bdc2330b31af00ea89aa2f54e508dc708a5aacb4ce76e7431245f29b",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_p2wpkh() {
        bind_test();

        let extra_data = Vec::from_hex("1234").unwrap();
        let utxos = vec![
            Utxo {
                txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf".to_string(),
                script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
                derive_path: "m/49'/1'/0'/0/1".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
            amount: 88000,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            Some("1234"),
            "P2WPKH",
        );
        assert_eq!(
            "dc021850ca46b2fdc3f278020ac4e27ee18d9753dd07cbd97b84a2a0a2af3940",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "4eede542b9da11500d12f38b81c3728ae6cd094b866bc9629cbb2c6ab0810914",
            sign_result.as_ref().unwrap().wtx_id
        );
        assert_eq!(sign_result.as_ref().unwrap().signature, "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff03c05701000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e87d00700000000000017a914755fba51b5c443b9f16b1f86665dec10dd7a25c5870000000000000000046a02123402483045022100c5c33638f7a93094f4c5f30e384ed619f1818ee5095f6c892909b1fde0ec3d45022078d4c458e05d7ffee8dc7807d4b1b576c2ba1311b05d1e6f4c41775da77deb4d0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc0247304402201d0b9fd415cbe3af809709fea17dfab49291d5f9e42c2ec916dc547b8819df8d02203281c5a742093d46d6b681afc837022ae33c6ff3839ac502bb6bf443782f8010012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000");
    }

    #[test]
    fn test_native_segwit_bech32_to_bech32_no_change() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "d7c2e585d5eaa185808addb3ef703f2a8fe09288b4f40b757a812d6d63b7c9c4".to_string(),
            vout: 1,
            amount: 100000,
            address: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            amount: 88000,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            None,
            "VERSION_0",
        );
        assert_eq!(
            "02000000000101c4c9b7636d2d817a750bf4b48892e08f2a3f70efb3dd8a8085a1ead585e5c2d70100000000ffffffff02c057010000000000160014654fbb08267f3d50d715a8f1abb55979b160dd5bd007000000000000160014622347653655d57ee8e8f25983f646bcdf9c503202473044022055b4bbbad7e85e9b359a69e8f68801066e9368dbeb3ed777c418f83f175d1ef802206f2a70af6443083f58df7882028f0c94505d1c06167202db21eb2d98d250289a0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "029cd8e0fcdeac49c6884bf3e848408961aec4ffecf31d089633c4e3784d29f5",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "9d7731cdd9a187a39628e0d75199a62ac1e2575224ad31c318db95d99a9e5897",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_native_segwit_bech32_to_bech32_has_change() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "7c99f906e291d453b2c039939598eefd182dafb20d53bd0eebc2a1aa635ff60f".to_string(),
            vout: 0,
            amount: 88000,
            address: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            amount: 50000,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            None,
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
    fn test_native_segwit_bech32_to_p2pkh() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "64381306678c6a868e8778adee1ee9d1746e5e8dd3535fcbaa1a25baab49f015".to_string(),
            vout: 1,
            amount: 100000,
            address: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
            amount: 30000,
            unspents: utxos,
            fee: 8000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            None,
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
    fn test_native_segwit_bech32_to_p2shp2wpkh() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "fcc622970fd80c14b111ee7950bcc309469b575194072209598176123fd06598".to_string(),
            vout: 0,
            amount: 50000,
            address: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
            amount: 30000,
            unspents: utxos,
            fee: 7000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            None,
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
    fn test_legacy_p2pkh_to_bech32() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "eb3ea0d4b360a304849b90baf49197eb449ca746febd60f8f29cd279c966a3ea".to_string(),
            vout: 0,
            amount: 30000,
            address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 4294967295,
        }];
        let transaction = BtcTransaction {
            to: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            amount: 25000,
            unspents: utxos,
            fee: 5000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/44'/1'/0'".to_string(),
            Some(0),
            None,
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
    fn test_segwit_p2sh_p2wpkh_to_bech32() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "e5add8950cb37b1d80ff18cb2ba775e185e1843b845e18b532dc4b5d8ffec7a9".to_string(),
            vout: 0,
            amount: 30000,
            address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            amount: 26000,
            unspents: utxos,
            fee: 4000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            Some("1234"),
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
    fn test_native_segwit_bech32_to_bech32_multiutxo() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "401959f94ad3c1c55a6d778f8446625a4b00a0a12a2cdb983fb4423ce93261cc"
                    .to_string(),
                vout: 0,
                amount: 26000,
                address: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
                script_pubkey: "0014654fbb08267f3d50d715a8f1abb55979b160dd5b".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "e5add8950cb37b1d80ff18cb2ba775e185e1843b845e18b532dc4b5d8ffec7a9"
                    .to_string(),
                vout: 1,
                amount: 13000,
                address: "tb1qvg35wefk2h2ha68g7fvc8ajxhn0ec5pjekus6j".to_string(),
                script_pubkey: "0014622347653655d57ee8e8f25983f646bcdf9c5032".to_string(),
                derive_path: "m/49'/1'/0'/1/0".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "tb1qv48mkzpx0u74p4c44rc6hd2e0xckph2muvy76k".to_string(),
            amount: 31000,
            unspents: utxos,
            fee: 5000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            None,
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
    fn test_sign_mixed_p2shp2wpkh_utxo_nochange() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "32f734241b2dee423ee736ddfd26ea341d56a0ded67f4e1c658d0119977c1b3a".to_string(),
            vout: 0,
            amount: 100000,
            address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
            script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
            derive_path: "m/49'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "2N5z4KZBCQNULTegkETDftMiNHWEFjrH3m2".to_string(),
            amount: 90000,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/49'/1'/0'", Some(0), None, "P2WPKH");

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
    fn test_sign_mixed_single_legacy_and_segwit_utxo_has_change() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "356d5e8628466f072c1de991e14320226ceef944cfebec251dd5c87ea925823c"
                    .to_string(),
                vout: 1,
                amount: 100000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "b63ca3592561fd7c8b41017fbb0deff12ce6f7d351128c818dcf4ed1a0beae0e"
                    .to_string(),
                vout: 1,
                amount: 1418852,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "2N5z4KZBCQNULTegkETDftMiNHWEFjrH3m2".to_string(),
            amount: 1508852,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'/0/0".to_string(),
            Some(53),
            None,
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

    #[test]
    fn test_sign_mixed_single_bech32_utxo_haschange() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "41eb7058313847d1f1b0cfee964a436d55eab5ca29fdbb42dbb5107a85afdda7".to_string(),
            vout: 1,
            amount: 100000,
            address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95".to_string(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "m/84'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99".to_string(),
            amount: 30000,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/84'/1'/0'".to_string(),
            Some(53),
            None,
            "VERSION_0",
        );
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
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "80f482aa891508c205a8b2fc52756b827d61aeda63ce909c51403d7bea3b040d"
                    .to_string(),
                vout: 1,
                amount: 100000,
                address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95".to_string(),
                script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
                derive_path: "m/84'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "14b3966c886a64e85829a8ed01498495f5514851121048754cc39824b54aaf7f"
                    .to_string(),
                vout: 1,
                amount: 100000,
                address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95".to_string(),
                script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
                derive_path: "m/84'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
        ];

        let transaction_req_data = BtcTransaction {
            to: "tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99".to_string(),
            amount: 110000,
            unspents: utxos,
            fee: 20000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction_req_data.sign_transaction(
            "TESTNET",
            &"m/84'/1'/0'".to_string(),
            Some(53),
            None,
            "VERSION_0",
        );

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
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "0a7937fe1c6d03fb835aced9f3ca5fd3b2f1c78ed1f5f394ad742a01897157d7"
                    .to_string(),
                vout: 0,
                amount: 100000,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "94fbcc624b34c6a1e7681312b490f0fbfaf3fb6efe90efb16a57815ea0c34edd"
                    .to_string(),
                vout: 0,
                amount: 100000,
                address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95".to_string(),
                script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
                derive_path: "m/84'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99".to_string(),
            amount: 90000,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/84'/1'/0'", Some(53), None, "VERSION_0");

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
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "b7b05e82cd4dad038d7f7545f02940ed959aa8f54b1701688927649f99021e60"
                    .to_string(),
                vout: 1,
                amount: 100000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "36671b4b8f72542ae9b9708725119837b233177d28a710204b839343b8a811a0"
                    .to_string(),
                vout: 0,
                amount: 100000,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "6459945baee1c250c9099f2f23e24af5dbd73292f0d994bef076d3f65356563a"
                    .to_string(),
                vout: 1,
                amount: 100000,
                address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95".to_string(),
                script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
                derive_path: "m/84'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "6d1d8f16f93fe99de489e20d5d08b59f0d98754e0a84824889d9a59cc640ffac"
                    .to_string(),
                vout: 1,
                amount: 70000,
                address: "tb1q0qz6vdsay5edatqmvtyn9z92zkfs3hxqvk8k8k".to_string(),
                script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
                derive_path: "m/84'/1'/0'/1/53".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "tb1qpma75pm648xmd9tfzah029edarqn4xtndqhp99".to_string(),
            amount: 310000,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/84'/1'/0'", Some(53), None, "VERSION_0");

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
        bind_test();

        let utxos = vec![Utxo {
            txhash: "1cd9bfa2cabf071aca138e38e7ba281fa0aa26dd554d3518a2f3f74d33e9d3f5".to_string(),
            vout: 0,
            amount: 100000,
            address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
            script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
            derive_path: "m/44'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "2N5z4KZBCQNULTegkETDftMiNHWEFjrH3m2".to_string(),
            amount: 30000,
            unspents: utxos,
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/49'/1'/0'", Some(53), None, "P2WPKH");

        assert_eq!(
            "0100000001f5d3e9334df7f3a218354d55dd26aaa01f28bae7388e13ca1a07bfcaa2bfd91c000000006b48304502210091a1232f0c63dd72dcbf07092b92fe360ebb76425c57cb0281e12addfd92940d022055b500ccd12861bad5d48785a369157fca3a633df09e5cb800053e6e3b3d691c0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02307500000000000017a9148bbb53570df9656926ea0ef029cd2ee84dbc7d0f8760ea00000000000017a914a906137d79fc84a9685de5e6185bf397c2249bcd8700000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "4a8dcbeebdacc54a6c2d7fa4109537a6caa3185460303a70e4ec38c9a9e24a77",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "4a8dcbeebdacc54a6c2d7fa4109537a6caa3185460303a70e4ec38c9a9e24a77",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_with_hd_on_testnet() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a"
                    .to_string(),
                vout: 0,
                amount: 200000000,
                address: "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC".to_string(),
                script_pubkey: "76a914118c3123196e030a8a607c22bafc1577af61497d88ac".to_string(),
                derive_path: "m/44'/1'/0'/0/22".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531"
                    .to_string(),
                vout: 1,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9"
                    .to_string(),
                vout: 0,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9"
                    .to_string(),
                vout: 1,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
            amount: 799988000,
            unspents: utxos.clone(),
            fee: 12000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/44'/1'/0'/0/0", Some(53), None, "NONE");

        assert_eq!(
            "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006b483045022100c610f77f71cc8afcfbd46df8e3d564fb8fb0f2c041bdf0869512c461901a8ad802206b92460cccbcb2a525877db1b4b7530d9b85e135ce88424d1f5f345dc65b881401210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006b483045022100dce4a4c3d79bf9392832f68da3cd2daf85ac7fa851402ecc9aaac69b8761941d02201e1fd6601812ea9e39c6df0030cb754d4c578ff48bc9db6072ba5207a4ebc2b60121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006b483045022100e1802d80d72f5f3be624df3ab668692777188a9255c58067840e4b73a5a61a99022025b23942deb21f5d1959aae85421299ecc9efefb250dbacb46a4130abd538d730121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006a47304402207b82a62ed0d35c9878e6a7946d04679c8a17a8dd0a856b5cc14928fe1e9b554a0220411dd1a61f8ac2a8d7564de84e2c8a2c2583986bd71ac316ade480b8d0b4fffd0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff0120d9ae2f000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac00000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_p2shwpkh_on_testnet() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf".to_string(),
                script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
                derive_path: "m/49'/1'/0'/0/1".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
            amount: 88000,
            unspents: utxos.clone(),
            fee: 12000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/49'/1'/0'/0/0", Some(0), None, "P2WPKH");

        assert_eq!(
            "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff01c05701000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e870247304402205fd9dea5df0db5cc7b1d4b969f63b4526fb00fd5563ab91012cb511744a53d570220784abfe099a2b063b1cfc1f145fef2ffcb100b0891514fa164d357f0ef7ca6bb0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc02483045022100b0246c12428dbf863fcc9060ab6fc46dc2135adaa6cf8117de49f9acecaccf6c022059377d05c9cab24b7dec14242ea3206cc1f464d5ff9904dca515fc71766507cd012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000",
            sign_result.as_ref().unwrap().signature
        );

        let transaction_req_data = BtcTransaction {
            to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
            amount: 80000,
            unspents: utxos.clone(),
            fee: 10000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction_req_data.sign_transaction(
            "TESTNET",
            "m/49'/1'/0'/0/0",
            Some(0),
            None,
            "P2WPKH",
        );

        assert_eq!(
            "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff02803801000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e87102700000000000017a914755fba51b5c443b9f16b1f86665dec10dd7a25c58702483045022100f0c66cd322e50f992ad34448fb3bf823066e5ffaa8e840a901058a863a4d950c02206cdafb1ad1ef4d938122b106069d8b435387e4d55711f50a46a8d91d9f674c550121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc02483045022100cfe92e4ad4fbfc13be20afc6f37429e26426257d015b409d28c260544e581b2c022028412816d1fef11093b474c2c662a25a4062f4e37d06ce66207863de98814a07012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_segwit_with_op_return_on_testnet() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf".to_string(),
                script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
                derive_path: "m/49'/1'/0'/0/1".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
            amount: 88000,
            unspents: utxos.clone(),
            fee: 12000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            "m/49'/1'/0'/0/0",
            Some(0),
            Some("1234"),
            "P2WPKH",
        );

        assert_eq!(
            "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff02c05701000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e870000000000000000046a021234024730440220527c098c320c54ac56445b757a76833f7a47229fa0fe2b179f55bd718822695e022060f48b05c46f8335266eade0fe503448ff4222efc7e84ef86a25abffbe02ead20121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc024730440220551ab42b94841b43e6118a6adb39a561f138ae9ee8d2c00ffa3886839afe66d2022046686666245b94b7272d7cbd17a6f20639532ddefafe0572ecc28dcb246d33f8012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_with_taproot_on_testnet() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "2bdcfa88d5f48954e98018da33aaf11a4951b4167ba8121bc787880890dee5f0".to_string(),
            vout: 1,
            amount: 523000,
            address: "tb1pjvp6z9shfhfpafrnwen9j452cf8tdwpgc0hfnzvz62aqwr4qv92sg7qj9r".to_string(),
            script_pubkey: "51208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233"
                .to_string(),
            derive_path: "m/86'/1'/0'/1/53".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "tb1p3ax2dfecfag2rlsqewje84dgxj6gp3jkj2nk4e3q9cwwgm93cgesa0zwj4".to_string(),
            amount: 40000,
            unspents: utxos.clone(),
            fee: 1000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/86'/1'/0'/0/0", Some(53), None, "VERSION_1");
        assert_eq!(
            "0fb223cd2cd90830827ab235b752de841153d69a75649d8f92ffa2198d645852",
            sign_result.as_ref().unwrap().tx_hash
        );
    }

    #[test]
    fn test_sign_with_p2wpkh_on_testnet() {
        bind_test();

        let utxos = vec![Utxo {
            txhash: "cebc5c2b4f5533428ad0cca94e9bfefa6410a270ed1d7116e2ee8592494c66bd".to_string(),
            vout: 1,
            amount: 100000,
            address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95".to_string(),
            script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
            derive_path: "m/84'/1'/0'/0/0".to_string(),
            sequence: 0,
        }];

        let transaction = BtcTransaction {
            to: "tb1p3ax2dfecfag2rlsqewje84dgxj6gp3jkj2nk4e3q9cwwgm93cgesa0zwj4".to_string(),
            amount: 50000,
            unspents: utxos,
            fee: 20000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/86'/1'/0'/0/0", Some(53), None, "VERSION_1");
        assert_eq!(
            "02000000000101bd664c499285eee216711ded70a21064fafe9b4ea9ccd08a4233554f2b5cbcce0100000000ffffffff0250c30000000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c23330750000000000002251209303a116174dd21ea473766659568ac24eb6b828c3ee998982d2ba070ea0615502483045022100bed2bc8b4bf2beb4dacda077b47f96b4070af659ca241c343eccfe3ebc4a6f600220379c51f6456adff08a7605496a88653689af9e44f5d324e2ad2e1eae330b434f012102e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c000000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "b9d297c17be4fd659959a40fc6df7bf659f5f6e1b46c29d613d6fa25c711616b",
            sign_result.as_ref().unwrap().tx_hash
        );
    }

    #[test]
    fn test_sign_with_multi_payment_on_testnet() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "aea080afe2cdeb23f0d9f546d386329addda5a6fdc521e02d74d5a4e4461dc4a"
                    .to_string(),
                vout: 0,
                amount: 20000,
                address: "tb1p3ax2dfecfag2rlsqewje84dgxj6gp3jkj2nk4e3q9cwwgm93cgesa0zwj4"
                    .to_string(),
                script_pubkey:
                    "51208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233"
                        .to_string(),
                derive_path: "m/86'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "aea080afe2cdeb23f0d9f546d386329addda5a6fdc521e02d74d5a4e4461dc4a"
                    .to_string(),
                vout: 1,
                amount: 283000,
                address: "tb1pjvp6z9shfhfpafrnwen9j452cf8tdwpgc0hfnzvz62aqwr4qv92sg7qj9r"
                    .to_string(),
                script_pubkey:
                    "51209303a116174dd21ea473766659568ac24eb6b828c3ee998982d2ba070ea06155"
                        .to_string(),
                derive_path: "m/86'/1'/0'/1/53".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "13dca25cc94c015067761f5cecf48dfb3afcaea78abeb28ce1b585bf4980cc12"
                    .to_string(),
                vout: 0,
                amount: 100000,
                address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95".to_string(),
                script_pubkey: "00141a7a98a2b9fa09685d28edecb2741250e85882c3".to_string(),
                derive_path: "m/84'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "0122f46a161ded9805d95930549b2e4d93a765ef3dd5f10052c68c9270659e72"
                    .to_string(),
                vout: 1,
                amount: 100000,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "d8929d60667d2a717abd833828a899795c45c843352b3552322fcd75447226a1"
                    .to_string(),
                vout: 1,
                amount: 100000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "tb1pxcrec4q8tzj34phw470pwe5dfkz58k93kljklck6pxpv8yx9v40q66tmr7".to_string(),
            amount: 40000,
            unspents: utxos,
            fee: 40000,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/86'/1'/0'/0/0", Some(53), None, "VERSION_1");
        let tx_sign_result = &sign_result.unwrap();
        let tx =
            Transaction::deserialize(&hex_to_bytes(&tx_sign_result.signature).unwrap()).unwrap();

        let msg = Message::from_slice(
            &Vec::from_hex("f01ba76b329132e48188ad10d00791647ee6d2f7fee5ef397f3481993c898de3")
                .unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&tx.input[0].witness.to_vec()[0]).unwrap();
        let pub_key = XOnlyPublicKey::from_slice(
            &Vec::from_hex("8f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233")
                .unwrap(),
        )
        .unwrap();
        let secp = Secp256k1::new();
        let verify_result = secp.verify_schnorr(&sig, &msg, &pub_key);
        assert!(verify_result.is_ok());

        let msg = Message::from_slice(
            &Vec::from_hex("d0691b5ac1b338b9341790ea69417cb454cf346a718342fb4a846dbb8ae142e8")
                .unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&tx.input[1].witness.to_vec()[0]).unwrap();
        let pub_key = XOnlyPublicKey::from_slice(
            &Vec::from_hex("9303a116174dd21ea473766659568ac24eb6b828c3ee998982d2ba070ea06155")
                .unwrap(),
        )
        .unwrap();
        let verify_result = secp.verify_schnorr(&sig, &msg, &pub_key);
        assert!(verify_result.is_ok());

        assert_eq!(tx.input[2].witness.to_vec()[0].to_hex(), "3044022022c2feaa4a225496fc6789c969fb776da7378f44c588ad812a7e1227ebe69b6302204fc7bf5107c6d02021fe4833629bc7ab71cefe354026ebd0d9c0da7d4f335f9401");
        assert_eq!(
            tx.input[2].witness.to_vec()[1].to_hex(),
            "02e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c0"
        );

        assert_eq!(tx.input[3].witness.to_vec()[0].to_hex(), "3045022100dec4d3fd189b532ef04f41f68319ff7dc6a7f2351a0a8f98cb7f1ec1f6d71c7a02205e507162669b642fdb480a6c496abbae5f798bce4fd42cc390aa58e3847a1b9101");
        assert_eq!(
            tx.input[3].witness.to_vec()[1].to_hex(),
            "031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc"
        );

        assert_eq!(tx.input[4].script_sig.to_hex(), "483045022100ca32abc7b180c84cf76907e4e1e0c3f4c0d6e64de23b0708647ac6fee1c04c5b02206e7412a712424eb9406f18e00a42e0dffbfb5901932d1ef97843d9273865550e0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4e");

        assert_eq!(
            "2bdcfa88d5f48954e98018da33aaf11a4951b4167ba8121bc787880890dee5f0",
            tx_sign_result.tx_hash
        );
    }

    #[test]
    fn test_sign_with_hd_testnet() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a"
                    .to_string(),
                vout: 0,
                amount: 200000000,
                address: "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC".to_string(),
                script_pubkey: "76a914118c3123196e030a8a607c22bafc1577af61497d88ac".to_string(),
                derive_path: "m/44'/1'/0'/0/22".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531"
                    .to_string(),
                vout: 1,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9"
                    .to_string(),
                vout: 0,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9"
                    .to_string(),
                vout: 1,
                amount: 200000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
            amount: 750000000,
            unspents: utxos,
            fee: 502130,
            chain_type: "BITCOIN".to_string(),
        };
        let sign_result =
            transaction.sign_transaction("TESTNET", "m/44'/1'/0'/0/0", Some(53), None, "NONE");
        assert_eq!(
            "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006b483045022100c4f39ce7f2448ab8e7154a7b7ce82edd034e3f33e1f917ca43e4aff822ba804c02206dd146d1772a45bb5e51abb081d066114e78bcb504671f61c5a301a647a494ac01210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006b483045022100d235afda9a56aaa4cbe05df712202e6b1a45aab7a0c83540d3053133f15acc5602201b0e144bec3a02a5c556596040b0be81b0202c19b163bb537b8d965afd61403a0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006b483045022100dd8f1e20116f96a3400f55e0c637a0ad21ae47ff92d83ffb0c3d324c684a54be0220064b0a6d316154ef07a69bd82de3a052e43c3c6bb0e55e4de4de939b093e1a3a0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006a473044022048d8cb0f1480174b3b9186cc6fe410db765f1f9d3ce036b0d4dee0eb19aa3641022073de4bb2b00a0533e9c8f3e074c655e0695c8b223233ddecf3c99a84351d50a60121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff028017b42c000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac0e47f302000000001976a91412967cdd9ceb72bbdbb7e5db85e2dbc6d6c3ab1a88ac00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "3aa6ed94e29c01b96fe3a20c30825d161f421d5e2358eb1ceade43de533e1977",
            sign_result.as_ref().unwrap().tx_hash
        );
    }

    #[test]
    fn test_sign_dogecoin_p2pkh_testnet() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a"
                    .to_string(),
                vout: 0,
                amount: 200000000,
                address: "nVnwhEpurmQg4GWWecpUwQcQLng798GRai".to_string(),
                script_pubkey: "76a914118c3123196e030a8a607c22bafc1577af61497d88ac".to_string(),
                derive_path: "m/44'/1'/0'/0/22".to_string(),
                sequence: 4294967295,
            },
            Utxo {
                txhash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531"
                    .to_string(),
                vout: 1,
                amount: 200000000,
                address: "nZKaSJP5DAv4MSSNG4zyB833s92rHdzyqW".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 4294967295,
            },
            Utxo {
                txhash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9"
                    .to_string(),
                vout: 0,
                amount: 200000000,
                address: "nZKaSJP5DAv4MSSNG4zyB833s92rHdzyqW".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 4294967295,
            },
            Utxo {
                txhash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9"
                    .to_string(),
                vout: 1,
                amount: 200000000,
                address: "nZKaSJP5DAv4MSSNG4zyB833s92rHdzyqW".to_string(),
                script_pubkey: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derive_path: "m/44'/1'/0'/0/0".to_string(),
                sequence: 4294967295,
            },
        ];

        let transaction = BtcTransaction {
            to: "nZKaSJP5DAv4MSSNG4zyB833s92rHdzyqW".to_string(),
            amount: 799988000,
            unspents: utxos,
            fee: 10000,
            chain_type: "DOGECOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/44'/1'/0'".to_string(),
            Some(53),
            None,
            "NONE",
        );
        
        assert_eq!(
            "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006a47304402200eb094ab218f492e15bcae19c61c980111fdca403108ed8502a6c4ada5ffe8b802204afb0b58b770a4523148895ffdb1a154c0642584223306c267ee67e6d2f35fba01210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006a47304402203b7317f8443f49a8c2930b679181feb0640e88447bca3f2a94600cc0078e4ab90220624ec6e2ba25f3bde477df048d84a9aad736087332ffced65377a66b1ea4d3c10121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006b4830450221008541d1e27f76450b4b78a89af8e6707a042a30151d1e59d271f335720a3a4a590220152b688827df0fff697cb8ba47a6293a4785d651e5da426854bebce7ea4d34010121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006a473044022042b27e6639c575f0acf4ebb4b43ee52ff9fef2888caf5d88d38a6c6b062cbbae022048446492f4c315cc5cd37d6dac041d67ffbf1bc199311bfc5f29fbdb102279a60121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff0220d9ae2f000000001976a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688acd0070000000000001976a91412967cdd9ceb72bbdbb7e5db85e2dbc6d6c3ab1a88ac00000000",
            sign_result.as_ref().unwrap().signature
        );
        assert_eq!(
            "365d003e2bb2213e6754e787a576007cab51a46a146bad1c722a59622ff26535",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "365d003e2bb2213e6754e787a576007cab51a46a146bad1c722a59622ff26535",
            sign_result.as_ref().unwrap().wtx_id
        );
    }

    #[test]
    fn test_sign_dogecoin_p2wpkh_testnet() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf".to_string(),
                script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
                derive_path: "m/49'/1'/0'/0/1".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
            amount: 88000,
            unspents: utxos,
            fee: 10000,
            chain_type: "DOGECOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "TESTNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            Some("1234"),
            "P2WPKH",
        );
        assert_eq!(
            "dc021850ca46b2fdc3f278020ac4e27ee18d9753dd07cbd97b84a2a0a2af3940",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "4eede542b9da11500d12f38b81c3728ae6cd094b866bc9629cbb2c6ab0810914",
            sign_result.as_ref().unwrap().wtx_id
        );
        assert_eq!(sign_result.as_ref().unwrap().signature, "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff03c05701000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e87d00700000000000017a914755fba51b5c443b9f16b1f86665dec10dd7a25c5870000000000000000046a02123402483045022100c5c33638f7a93094f4c5f30e384ed619f1818ee5095f6c892909b1fde0ec3d45022078d4c458e05d7ffee8dc7807d4b1b576c2ba1311b05d1e6f4c41775da77deb4d0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc0247304402201d0b9fd415cbe3af809709fea17dfab49291d5f9e42c2ec916dc547b8819df8d02203281c5a742093d46d6b681afc837022ae33c6ff3839ac502bb6bf443782f8010012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000");
    }

    #[test]
    fn test_sign_dogecoin_p2wpkh_mainnet() {
        bind_test();

        let utxos = vec![
            Utxo {
                txhash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "9vZ6j7mhbTHB4WdGpeP3ZNh1ZDqCBLfmjQ".to_string(),
                script_pubkey: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                derive_path: "m/49'/1'/0'/0/0".to_string(),
                sequence: 0,
            },
            Utxo {
                txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                    .to_string(),
                vout: 0,
                amount: 50000,
                address: "A4Fyz4whF7qTtFabuPY4Ti8M7p1faxWKsQ".to_string(),
                script_pubkey: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
                derive_path: "m/49'/1'/0'/0/1".to_string(),
                sequence: 0,
            },
        ];

        let transaction = BtcTransaction {
            to: "A4Fyz4whF7qTtFabuPY4Ti8M7p1faxWKsQ".to_string(),
            amount: 88000,
            unspents: utxos,
            fee: 10000,
            chain_type: "DOGECOIN".to_string(),
        };
        let sign_result = transaction.sign_transaction(
            "MAINNET",
            &"m/49'/1'/0'".to_string(),
            Some(0),
            None,
            "P2WPKH",
        );
        assert_eq!(
            "330df579f9432661cd295cd6317c9f6f0af4356e7e78c258dfd3e40fd4e8ca47",
            sign_result.as_ref().unwrap().tx_hash
        );
        assert_eq!(
            "6e6fe4bf6396e5255f28fb956edc0d6b1968898f7a62b92cf87c71a851899a3f",
            sign_result.as_ref().unwrap().wtx_id
        );
        assert_eq!(sign_result.as_ref().unwrap().signature, "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff02c05701000000000017a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787d00700000000000017a914755fba51b5c443b9f16b1f86665dec10dd7a25c58702483045022100aa512e5b38e828bc2219ea58c8f8c432f5f1ad5e13a7972e01d1b43740e08cf302201ae50dfd52cd1d37d285a085064afe18ec822d7f05187441614cb0865ce8db530121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc0247304402202da72ad7f19306c6aabcf7ee2ce48bcf4c3b508027ce1c572f6cd0ea95bf0a5202204331ddced75e1eb67e2ead1ee328942e4f3b7c6eb2b785a1caa6b7fe2abf7542012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000");
    }
}
