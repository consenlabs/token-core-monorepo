use crate::address::BchAddress;
use crate::common::{
    address_verify, apdu_sign_verify, get_address_version, get_xpub_data, TxSignResult,
};
use crate::Result;
use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::consensus::serialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{
    Address, Network, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_hashes::hash160;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::Hash;
use ikc_common::apdu::{ApduCheck, BtcForkApdu};
use ikc_common::constants::{BTC_FORK_DUST, MAX_OPRETURN_SIZE, MAX_UTXO_NUMBER, TIMEOUT_LONG};
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{bigint_to_byte_vec, secp256k1_sign};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::ecdsa::Signature;
use std::str::FromStr;

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

pub struct BchTransaction {
    pub to: String,
    pub amount: u64,
    pub unspents: Vec<Utxo>,
    pub fee: u64,
}

impl BchTransaction {
    pub fn sign_transaction(
        &self,
        network: Network,
        path: &str,
        change_idx: i32,
        change_address: &str,
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
        if &self.unspents.len() > &MAX_UTXO_NUMBER {
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
        let sign_verify_result = apdu_sign_verify(
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
        )?;

        //calc utxo total amount
        if self.get_total_amount() < self.amount {
            return Err(CoinError::ImkeyInsufficientFunds.into());
        }

        //add send to output
        let mut txouts: Vec<TxOut> = Vec::new();
        txouts.push(self.build_send_to_output());

        //add change output
        if self.get_change_amount() > BTC_FORK_DUST {
            //add change output
            let change_addr = self.get_change_address(network, path, change_idx, change_address)?;
            txouts.push(TxOut {
                value: self.get_change_amount() as u64,
                script_pubkey: change_addr.script_pubkey(),
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
            version: 1i32,
            lock_time: PackedLockTime::ZERO,
            input: vec![],
            output: txouts.clone(),
        };
        let mut output_serialize_data = serialize(&tx_to_sign);

        output_serialize_data.remove(5);
        output_serialize_data.remove(5);

        //add sign type
        output_serialize_data.extend(vec![0x41, 0x00, 0x00, 0x00]);

        //set input number
        output_serialize_data.remove(4);
        output_serialize_data.insert(4, self.unspents.len() as u8);

        //add fee amount
        output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        let address_version = get_address_version(network, self.to.as_str())?;
        output_serialize_data.push(address_version);

        output_serialize_data.extend(self.to.as_bytes());
        output_serialize_data.push(self.to.as_bytes().len() as u8);

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

        let btc_prepare_apdu_vec = BtcForkApdu::btc_fork_prepare(0x47, 0x00, &output_pareper_data);
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
            let script_hex: String = format!("76a914{}88ac", hex::encode(pub_key_hash));
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
            if unspent.derive_path.is_empty() {
                address_data.push(path_str.as_bytes().len() as u8);
                address_data.extend_from_slice(path_str.as_bytes());
            } else {
                address_data.push(unspent.derive_path.as_bytes().len() as u8);
                address_data.extend_from_slice(unspent.derive_path.as_bytes());
            }
            data.extend(address_data.iter());
            if index == self.unspents.len() - 1 {
                sign_apdu_vec.push(BtcForkApdu::btc_fork_segwit_sign(0x48, true, 0x01, data));
            } else {
                sign_apdu_vec.push(BtcForkApdu::btc_fork_segwit_sign(0x48, false, 0x01, data));
            }

            txinputs.push(txin.clone());
        }
        tx_to_sign.input = txinputs;

        let mut txhash_vout_prepare_apdu_vec =
            BtcForkApdu::btc_fork_prepare(0x47, 0x40, &txhash_vout_vec);
        let mut sequence_prepare_apdu_vec =
            BtcForkApdu::btc_fork_prepare(0x47, 0x80, &sequence_vec);
        txhash_vout_prepare_apdu_vec.append(&mut sequence_prepare_apdu_vec);
        for apdu in txhash_vout_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }

        //send sign apdu
        let mut lock_script_ver: Vec<Script> = vec![];
        for (index, sign_apdu) in sign_apdu_vec.iter().enumerate() {
            //sign data
            let btc_sign_apdu_return = send_apdu(sign_apdu.clone())?;
            ApduCheck::check_response(&btc_sign_apdu_return)?;
            let btc_sign_apdu_return =
                &btc_sign_apdu_return[..btc_sign_apdu_return.len() - 4].to_string();
            let sign_result_str =
                btc_sign_apdu_return[2..btc_sign_apdu_return.len() - 2].to_string();

            lock_script_ver.push(self.build_lock_script(
                sign_result_str.as_str(),
                utxo_pub_key_vec.get(index).unwrap(),
            )?);
        }

        let input_with_sigs = tx_to_sign
            .input
            .iter()
            .enumerate()
            .map(|(i, txin)| TxIn {
                script_sig: lock_script_ver.get(i).unwrap().clone(),
                witness: Witness::default(),
                ..*txin
            })
            .collect();
        let signed_tx = Transaction {
            version: 1i32,
            lock_time: PackedLockTime::ZERO,
            input: input_with_sigs,
            output: txouts.clone(),
        };

        let tx_bytes = serialize(&signed_tx);

        Ok(TxSignResult {
            signature: tx_bytes.to_hex(),
            tx_hash: signed_tx.txid().to_hex(),
            wtx_id: signed_tx.ntxid().to_hex(),
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
        let legacy_addr_str = BchAddress::convert_to_legacy_if_need(&self.to).unwrap();
        let legacy_addr = Address::from_str(&legacy_addr_str).unwrap();
        TxOut {
            value: self.amount as u64,
            script_pubkey: legacy_addr.script_pubkey(),
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
        signed_vec.push(0x41 as u8);
        Ok(Builder::new()
            .push_slice(&signed_vec)
            .push_slice(Vec::from_hex(utxo_public_key)?.as_slice())
            .into_script())
    }

    fn get_change_address(
        &self,
        network: Network,
        path: &str,
        change_idx: i32,
        change_address: &str,
    ) -> Result<Address> {
        let legacy_addr = if !change_address.is_empty() {
            if !BchAddress::is_valid(change_address) {
                return Err(CoinError::InvalidAddress.into());
            }
            BchAddress::convert_to_legacy_if_need(change_address)?
        } else {
            let path_temp = format!("{}{}{}", path, "1/", change_idx);
            let bch_address = BchAddress::get_address(network, path_temp.as_str())?;
            BchAddress::convert_to_legacy_if_need(bch_address.as_str())?
        };
        Ok(Address::from_str(legacy_addr.as_str())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_sign_transaction() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "09c3a49c1d01f6341c43ea43dd0de571664a45b4e7d9211945cb3046006a98e2".to_string(),
            vout: 0,
            amount: 100000,
            address: "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r".to_string(),
            script_pubkey: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
            derive_path: "m/44'/145'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let transaction_req_data = BchTransaction {
            to: "qq40fskqshxem2gvz0xkf34ww3h6zwv4dcr7pm0z6s".to_string(),
            amount: 93454,
            unspents: utxos,
            fee: 6000,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Bitcoin,
            &"m/44'/145'/0'/".to_string(),
            0,
            "",
            &extra_data,
        );
        assert_eq!(
            "0100000001e2986a004630cb451921d9e7b4454a6671e50ddd43ea431c34f6011d9ca4c309000000006a473044022069ed7eb35512ac7cd897c8f10aaef4fb1fbbec35fa448e254bcbacda2b614609022003ede9e84e8408b8d410b0a88edeeed894b03961b7150af08bd0e21cc111bc0741210251492dfb299f21e426307180b577f927696b6df0b61883215f88eb9685d3d449ffffffff010e6d0100000000001976a9142af4c2c085cd9da90c13cd64c6ae746fa139956e88ac00000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_transaction_multiple_utxo() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "09c3a49c1d01f6341c43ea43dd0de571664a45b4e7d9211945cb3046006a98e2".to_string(),
            vout: 0,
            amount: 100000,
            address: "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r".to_string(),
            script_pubkey: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
            derive_path: "m/44'/145'/0'/0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74".to_string(),
            vout: 0,
            amount: 500000,
            address: "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r".to_string(),
            script_pubkey: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
            derive_path: "m/44'/145'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        let transaction_req_data = BchTransaction {
            to: "qq40fskqshxem2gvz0xkf34ww3h6zwv4dcr7pm0z6s".to_string(),
            amount: 110000,
            unspents: utxos,
            fee: 6100,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Bitcoin,
            &"m/44'/145'/0'/".to_string(),
            0,
            "",
            &extra_data,
        );
        assert_eq!(
            "0100000002e2986a004630cb451921d9e7b4454a6671e50ddd43ea431c34f6011d9ca4c309000000006a47304402203b2b4f64117152d0e332d0ce18da1bc789643b8ce91047a3f347ddba24c2a601022074fc24b99175044637cece18b64eed1ea40edcfda61fbb158ff5547a6213a57341210251492dfb299f21e426307180b577f927696b6df0b61883215f88eb9685d3d449ffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a000000006a47304402206e0bd590268c6949f063424f0ad58cc500752b35773295584f71e9a90221e2400220133b04eecb1bb992f7799dc73a53f07bbb521b6c80d2ebdbe759be10a7c6367741210251492dfb299f21e426307180b577f927696b6df0b61883215f88eb9685d3d449ffffffff02b0ad0100000000001976a9142af4c2c085cd9da90c13cd64c6ae746fa139956e88ac3c620700000000001976a914292210acdc053840b146d67da98a4e43e7302d7488ac00000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_to_legacy_addr() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "09c3a49c1d01f6341c43ea43dd0de571664a45b4e7d9211945cb3046006a98e2".to_string(),
            vout: 0,
            amount: 100000,
            address: "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r".to_string(),
            script_pubkey: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
            derive_path: "m/44'/145'/0'/0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74".to_string(),
            vout: 0,
            amount: 500000,
            address: "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r".to_string(),
            script_pubkey: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
            derive_path: "m/44'/145'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        let transaction_req_data = BchTransaction {
            to: "14v8bLFeGxuQG7NsKVfbk6P3PsazeduWcK".to_string(),
            amount: 110000,
            unspents: utxos,
            fee: 6100,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Bitcoin,
            &"m/44'/145'/0'/".to_string(),
            0,
            "",
            &extra_data,
        );
        assert_eq!(
            "0100000002e2986a004630cb451921d9e7b4454a6671e50ddd43ea431c34f6011d9ca4c309000000006a47304402203b2b4f64117152d0e332d0ce18da1bc789643b8ce91047a3f347ddba24c2a601022074fc24b99175044637cece18b64eed1ea40edcfda61fbb158ff5547a6213a57341210251492dfb299f21e426307180b577f927696b6df0b61883215f88eb9685d3d449ffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a000000006a47304402206e0bd590268c6949f063424f0ad58cc500752b35773295584f71e9a90221e2400220133b04eecb1bb992f7799dc73a53f07bbb521b6c80d2ebdbe759be10a7c6367741210251492dfb299f21e426307180b577f927696b6df0b61883215f88eb9685d3d449ffffffff02b0ad0100000000001976a9142af4c2c085cd9da90c13cd64c6ae746fa139956e88ac3c620700000000001976a914292210acdc053840b146d67da98a4e43e7302d7488ac00000000",
            sign_result.as_ref().unwrap().signature
        );
    }

    #[test]
    fn test_sign_change_address() {
        //binding device
        bind_test();

        let extra_data = vec![];
        let utxo = Utxo {
            txhash: "09c3a49c1d01f6341c43ea43dd0de571664a45b4e7d9211945cb3046006a98e2".to_string(),
            vout: 0,
            amount: 100000,
            address: "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r".to_string(),
            script_pubkey: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
            derive_path: "m/44'/145'/0'/0/0".to_string(),
            sequence: 0,
        };
        let utxo2 = Utxo {
            txhash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74".to_string(),
            vout: 0,
            amount: 500000,
            address: "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r".to_string(),
            script_pubkey: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
            derive_path: "m/44'/145'/0'/0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        utxos.push(utxo2);
        let transaction_req_data = BchTransaction {
            to: "14v8bLFeGxuQG7NsKVfbk6P3PsazeduWcK".to_string(),
            amount: 110000,
            unspents: utxos,
            fee: 6100,
        };
        let sign_result = transaction_req_data.sign_transaction(
            Network::Bitcoin,
            &"m/44'/145'/0'/".to_string(),
            0,
            "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r",
            &extra_data,
        );
        assert_eq!(
            "0100000002e2986a004630cb451921d9e7b4454a6671e50ddd43ea431c34f6011d9ca4c309000000006a47304402205cb3ae31d6ea0a8b21040c176c39b5b7468423e819f74dd9dc3389e46c3e5f9a02204d1cf42ee8d1409568c3ef907f2b6b8b0b9307b2e40d874dffc32d08692839d041210251492dfb299f21e426307180b577f927696b6df0b61883215f88eb9685d3d449ffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a000000006b483045022100d6b9ad4d0322928ad008650e2a2fc04c4861df90b7e2a2c0d221f93fc95ce4b00220744f50dba959332234677687467a44fbbf2e20537dd25f26bd0608790f946c2c41210251492dfb299f21e426307180b577f927696b6df0b61883215f88eb9685d3d449ffffffff02b0ad0100000000001976a9142af4c2c085cd9da90c13cd64c6ae746fa139956e88ac3c620700000000001976a914bedf37acf35504c9bfd18b09d989d0fb23fd269688ac00000000",
            sign_result.as_ref().unwrap().signature
        );
    }
}
