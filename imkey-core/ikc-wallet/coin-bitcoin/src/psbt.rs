use crate::Result;
use crate::btcapi::{PsbtInput, PsbtOutput};
use bitcoin::consensus::{Decodable, Encodable, serialize};
use bitcoin::psbt::Psbt;
use bitcoin::schnorr::{TapTweak, UntweakedPublicKey};
use bitcoin::{EcdsaSig, EcdsaSighashType, SchnorrSig, SchnorrSighashType, Script, TxOut, WPubkeyHash, Witness, Transaction, PackedLockTime, Network, PublicKey, Address};
use bitcoin_hashes::{hash160, Hash};
use secp256k1::{ecdsa::Signature, PublicKey as Secp256k1PublicKey, schnorr::Signature as SchnorrSignature};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::str::FromStr;
use bitcoin::blockdata::script::Builder;
use bitcoin::util::bip32::{ChainCode, ChildNumber, ExtendedPubKey};
use bitcoin::util::taproot::TapTweakHash;
use hex::FromHex;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::constants::TIMEOUT_LONG;
use ikc_common::error::CoinError;
use ikc_common::utility::{bigint_to_byte_vec, hex_to_bytes, secp256k1_sign, sha256_hash};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use crate::common::{get_address_version, get_xpub_data, select_btc_applet};


pub struct PsbtSigner<'a> {
    psbt: &'a mut Psbt,
    derivation_path: String,
    auto_finalize: bool,
    prevouts: Vec<TxOut>,
}

impl<'a> PsbtSigner<'a> {
    pub fn new(
        psbt: &'a mut Psbt,
        derivation_path: &str,
        auto_finalize: bool,
    ) -> Self {

        PsbtSigner {
            psbt,
            derivation_path: derivation_path.to_string(),
            prevouts: Vec::new(),
            auto_finalize,
        }
    }

    fn sign(&mut self, pub_keys: &Vec<String>) -> Result<()> {
        for idx in 0..self.prevouts.len() {
            let prevout = &self.prevouts[idx];

            if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh(idx, &pub_keys[idx])?;

                if self.auto_finalize {
                    self.finalize_p2pkh(idx);
                }
            } else if prevout.script_pubkey.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh(idx, &pub_keys[idx])?;

                if self.auto_finalize {
                    self.finalize_p2sh_nested_p2wpkh(idx);
                }
            } else if prevout.script_pubkey.is_v0_p2wpkh() {
                self.sign_p2wpkh(idx, &pub_keys[idx])?;

                if self.auto_finalize {
                    self.finalize_p2wpkh(idx);
                }
            } else if !self.psbt.inputs.first().unwrap().tap_scripts.is_empty() {
                // self.sign_p2tr_script(idx)?;

                if self.auto_finalize {
                    self.finalize_p2tr(idx);
                }
            } else if prevout.script_pubkey.is_v1_p2tr() {
                self.sign_p2tr(idx, &pub_keys[idx])?;

                if self.auto_finalize {
                    self.finalize_p2tr(idx);
                }
            }

            if self.auto_finalize {
                self.clear_finalized_input(idx);
            }
        }

        Ok(())
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

    fn get_path(&self, index: usize, is_p2tr: bool) -> Result<String> {
        let input = &self.psbt.inputs[index];
        let mut path = if !self.derivation_path.is_empty() {
            format!("{}/0/0", self.derivation_path)
        } else {
            "".to_string()
        };

        if is_p2tr {
            let tap_bip32_derivation = input.tap_key_origins.first_key_value();

            if let Some((_, key_source)) = tap_bip32_derivation {
                path = key_source.1 .1.to_string();
            }
        } else {
            let bip32_derivations = input.bip32_derivation.first_key_value();

            if let Some((_, key_source)) = bip32_derivations {
                path = key_source.1.to_string();
            }
        }
        Ok(path)
    }

    fn get_pub_key(&self) -> Result<Vec<String>> {
        let mut pub_key_vec = vec![];
        for (idx, tx_out) in self.prevouts.iter().enumerate() {
            let path = if tx_out.script_pubkey.is_v1_p2tr() {
                self.get_path(idx, true)?
            }else {
                self.get_path(idx, false)?
            };

            let xpub_data = get_xpub_data(&path, false)?;
            let derive_pub_key = &xpub_data[..130];
            let public_key = Secp256k1PublicKey::from_str(derive_pub_key)?;
            pub_key_vec.push(public_key.to_string())
        }

        Ok(pub_key_vec)
    }

    fn sign_p2pkh(
        &mut self,
        idx: usize,
        pub_key: &str,
    ) -> Result<()> {
        let mut input_data_vec = vec![];
        for (x, prevout) in self.prevouts.iter().enumerate() {
            let mut temp_serialize_txin = self.psbt.unsigned_tx.input.get(x).expect("get_input_error").clone();
            if (x == idx) {
                temp_serialize_txin.script_sig = prevout.script_pubkey.clone();
            }
            input_data_vec.extend_from_slice(serialize(&temp_serialize_txin).as_slice());
        }
        let btc_perpare_apdu_list = BtcApdu::btc_single_utxo_sign_prepare(0x46, &input_data_vec);
        for apdu in btc_perpare_apdu_list {
            ApduCheck::check_response(&send_apdu(apdu)?)?;
        }
        let path = self.get_path(idx, false)?;
        let btc_sign_apdu = BtcApdu::btc_single_utxo_sign(
            idx as u8,
            EcdsaSighashType::All.to_u32() as u8,
            &path,
        );

        let btc_sign_apdu_return = send_apdu(btc_sign_apdu)?;
        ApduCheck::check_response(&btc_sign_apdu_return)?;
        let btc_sign_apdu_return =
            &btc_sign_apdu_return[..btc_sign_apdu_return.len() - 4].to_string();
        let sign_result_str = btc_sign_apdu_return[2..btc_sign_apdu_return.len() - 2].to_string();

        let mut signature_obj = Signature::from_compact(&hex::decode(&sign_result_str)?)?;
        signature_obj.normalize_s();
        // let pub_key = &self.get_pub_key(idx, false)?;
        let pub_key = PublicKey::from_str(pub_key)?;
        self.psbt.inputs[idx]
            .partial_sigs
            .insert(pub_key, EcdsaSig::sighash_all(signature_obj));

        Ok(())
    }

    fn sign_p2sh_nested_p2wpkh(
        &mut self,
        idx: usize,
        pub_key: &str,
    ) -> Result<()> {
        let mut temp_serialize_txin = self.psbt.unsigned_tx.input.get(idx).expect("get_input_error").clone();
        let prevout = &self.prevouts[idx];
        // let pub_key = &self.get_pub_key(idx, false)?;
        let mut data: Vec<u8> = vec![];
        //txhash and vout
        let txhash_data = serialize(&temp_serialize_txin.previous_output);
        data.extend(txhash_data.iter());
        //lock script
        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(hash160::Hash::hash(
            &hex_to_bytes(pub_key)?,
        )));
        let script = script.p2wpkh_script_code().expect("must be v0_p2wpkh");
        data.extend(serialize(&script).iter());
        //amount
        let mut utxo_amount = num_bigint::BigInt::from(prevout.value).to_signed_bytes_le();
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
        let sign_path = self.get_path(idx, false)?;
        address_data.push(sign_path.as_bytes().len() as u8);
        address_data.extend_from_slice(sign_path.as_bytes());
        data.extend(address_data.iter());

        let sign_apdu = if idx == (self.psbt.unsigned_tx.input.len() - 1) {
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
        let pub_key = PublicKey::from_str(pub_key)?;
        self.psbt.inputs[idx]
            .partial_sigs
            .insert(pub_key, EcdsaSig::sighash_all(signature_obj));
        Ok(())
    }

    fn sign_p2wpkh(
        &mut self,
        idx: usize,
        pub_key: &str,
    ) -> Result<()> {
        let mut temp_serialize_txin = self.psbt.unsigned_tx.input.get(idx).expect("get_input_error").clone();
        let prevout = &self.prevouts[idx];
        let mut data: Vec<u8> = vec![];
        //txhash and vout
        let txhash_data = serialize(&temp_serialize_txin.previous_output);
        data.extend(txhash_data.iter());
        //lock script
        let script = prevout
            .script_pubkey
            .p2wpkh_script_code()
            .expect("must be v0_p2wpkh");
        data.extend(serialize(&script).iter());
        //amount
        let mut utxo_amount = num_bigint::BigInt::from(prevout.value).to_signed_bytes_le();
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
        let sign_path = self.get_path(idx, false)?;
        address_data.push(sign_path.as_bytes().len() as u8);
        address_data.extend_from_slice(sign_path.as_bytes());
        data.extend(address_data.iter());

        let sign_apdu = if idx == (self.psbt.unsigned_tx.input.len() - 1) {
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
        let pub_key = PublicKey::from_str(pub_key)?;
        self.psbt.inputs[idx]
            .partial_sigs
            .insert(pub_key, EcdsaSig::sighash_all(signature_obj));
        Ok(())
    }

    fn sign_p2tr(
        &mut self,
        idx: usize,
        pub_key: &str,
        // transaction: &mut Transaction,
        // sighash_type: SchnorrSighashType,
    ) -> Result<()> {
        let mut data: Vec<u8> = vec![];
        // epoch (1).
        data.push(0x00u8);
        // hash_type (1).
        data.push(SchnorrSighashType::Default as u8);
        //nVersion (4):
        //nLockTime (4)
        // data.extend(serialize(&PackedLockTime::ZERO));
        data.extend(serialize(&self.psbt.unsigned_tx.lock_time));
        //prevouts_hash + amounts_hash + script_pubkeys_hash + sequences_hash + sha_outputs (32)
        //spend_type (1)
        data.push(0x00u8);
        //input_index (4)
        data.extend(serialize(&(idx as u32)));

        let mut path_data: Vec<u8> = vec![];
        let sign_path = self.get_path(idx, true)?;
        path_data.push(sign_path.as_bytes().len() as u8);
        path_data.extend_from_slice(sign_path.as_bytes());
        data.extend(path_data.iter());

        let mut tweaked_pub_key_data: Vec<u8> = vec![];
        let untweaked_public_key = UntweakedPublicKey::from_str(&pub_key[2..66])?;
        let tweaked_pub_key = TapTweakHash::from_key_and_tweak(untweaked_public_key, None).to_vec();
        tweaked_pub_key_data.push(tweaked_pub_key.len() as u8);
        tweaked_pub_key_data.extend_from_slice(&tweaked_pub_key);
        data.extend(tweaked_pub_key_data.iter());

        let sign_apdu = if idx == (self.psbt.unsigned_tx.input.len() - 1) {
            BtcApdu::btc_taproot_sign(true, data)
        } else {
            BtcApdu::btc_taproot_sign(false, data)
        };
        let sign_result = send_apdu(sign_apdu)?;
        ApduCheck::check_response(&sign_result)?;

        let sign_bytes = hex_to_bytes(&sign_result[2..(sign_result.len() - 4)])?;
        let sig = SchnorrSignature::from_slice(&sign_bytes)?;
        self.psbt.inputs[idx].tap_key_sig = Some(SchnorrSig {
            hash_ty: SchnorrSighashType::Default,
            sig,
        });

        Ok(())
    }

    pub fn calc_tx_hash(&self) -> Result<()> {
        let mut txhash_vout_vec = vec![];
        let mut sequence_vec = vec![];
        let mut amount_vec = vec![];
        let mut script_pubkeys_vec = vec![];
        for (idx, tx_in) in self.psbt.unsigned_tx.input.iter().enumerate() {
            let prevout = &self.prevouts[idx];
            txhash_vout_vec.extend(serialize(&tx_in.previous_output));
            sequence_vec.extend(serialize(&tx_in.sequence));
            amount_vec.extend(serialize(&prevout.value));
            script_pubkeys_vec.extend(serialize(&prevout.script_pubkey));
        }
        if self.psbt.unsigned_tx.version == 2 {
            let mut calc_hash_apdu = vec![];
            calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x40, &txhash_vout_vec));
            calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x80, &sequence_vec));
            calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x20, &amount_vec));
            calc_hash_apdu.extend(BtcApdu::btc_prepare(0x31, 0x21, &script_pubkeys_vec));
            for apdu in calc_hash_apdu {
                ApduCheck::check_response(&send_apdu(apdu)?)?;
            }
        }
        Ok(())
    }

    pub fn tx_preview(&self, network: Network) -> Result<()> {
        let mut preview_data= vec![];
        preview_data.extend(&serialize(&self.psbt.unsigned_tx.version));
        preview_data.push(0x01);//input number
        preview_data.extend(&serialize(&self.psbt.unsigned_tx.lock_time));
        let mut sign_hash_type = Vec::new();
        let len = EcdsaSighashType::All
            .to_u32()
            .consensus_encode(&mut sign_hash_type)
            .unwrap();
        debug_assert_eq!(len, sign_hash_type.len());
        preview_data.extend(&sign_hash_type);
        let amount = serialize(&self.psbt.unsigned_tx.output[0].value);
        // preview_data.extend(&hex_to_bytes("8017B42C00000000")?);
        preview_data.extend(amount);
        let script = serialize(&self.psbt.unsigned_tx.output[0].script_pubkey);
        // preview_data.extend(&hex_to_bytes("1976A91455BDC1B42E3BED851959846DDF600E96125423E088AC")?);
        preview_data.extend(script);
        preview_data.extend(&hex_to_bytes("000000000007A972")?);
        // preview_data.push(0x74);//address version
        let address = Address::from_script(&self.psbt.unsigned_tx.output[0].script_pubkey, network)?;
        println!("address->{}", address.to_string());
        let address_version = get_address_version(network, &address.to_string())?;
        preview_data.push(address_version);
        let mut output = vec![];
        for tx_out in self.psbt.unsigned_tx.output.iter() {
            output.extend(serialize(tx_out));
        }
        // serialize(&self.psbt.unsigned_tx.output);
        println!("output-->{}", hex::encode(output.clone()));
        let hash = &sha256_hash(&output);
        println!("output hash-->{}", hex::encode(hash.clone()));
        preview_data.extend_from_slice(hash);



        // output_serialize_data.remove(5);
        // output_serialize_data.remove(5);
        // //add sign type
        // let mut encoder_hash = Vec::new();
        // let len = EcdsaSighashType::All
        //     .to_u32()
        //     .consensus_encode(&mut encoder_hash)
        //     .unwrap();
        // debug_assert_eq!(len, encoder_hash.len());
        // output_serialize_data.extend(encoder_hash);

        //set input number
        // output_serialize_data.remove(4);
        // output_serialize_data.insert(4, self.unspents.len() as u8);

        //add fee amount
        // output_serialize_data.extend(bigint_to_byte_vec(self.fee));

        //add address version
        // let address_version = get_address_version(network, self.to.to_string().as_str())?;
        // output_serialize_data.push(address_version);

        //set 01 tag and length
        preview_data.insert(0, preview_data.len() as u8);
        preview_data.insert(0, 0x01);

        //use local private key sign data
        let key_manager_obj = KEY_MANAGER.lock();
        let mut output_pareper_data =
            secp256k1_sign(&key_manager_obj.pri_key, &preview_data)?;
        output_pareper_data.insert(0, output_pareper_data.len() as u8);
        output_pareper_data.insert(0, 0x00);
        output_pareper_data.extend(preview_data.iter());

        let btc_prepare_apdu_vec = BtcApdu::btc_prepare(0x4B, 0x00, &output_pareper_data);
        for temp_str in btc_prepare_apdu_vec {
            ApduCheck::check_response(&send_apdu_timeout(temp_str, TIMEOUT_LONG)?)?;
        }

        Ok(())
    }

    fn finalize_p2pkh(&mut self, index: usize) {
        let mut input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();

            input.final_script_sig = Some(
                Builder::new()
                    .push_slice(&sig.1.to_vec())
                    .push_slice(&sig.0.to_bytes())
                    .into_script(),
            );
        }
    }

    fn finalize_p2sh_nested_p2wpkh(&mut self, index: usize) {
        let mut input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();

            let script =
                Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(Self::hash160(&sig.0.to_bytes())));

            input.final_script_sig = Some(script);

            let mut witness = Witness::new();
            witness.push(sig.1.to_vec());
            witness.push(sig.0.to_bytes());

            input.final_script_witness = Some(witness);
        }
    }

    fn finalize_p2wpkh(&mut self, index: usize) {
        let mut input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();
            let mut witness = Witness::new();

            witness.push(sig.1.to_vec());
            witness.push(sig.0.to_bytes());

            input.final_script_witness = Some(witness)
        }
    }

    fn finalize_p2tr(&mut self, index: usize) {
        let mut input = &mut self.psbt.inputs[index];

        if input.tap_key_sig.is_some() {
            let mut witness = Witness::new();
            witness.push(input.tap_key_sig.unwrap().to_vec());

            if !input.tap_scripts.is_empty() {
                let (control_block, script_leaf) = input.tap_scripts.first_key_value().unwrap();

                let (script, _) = script_leaf;
                witness.push(script.as_bytes().to_vec());
                witness.push(control_block.serialize())
            }

            input.final_script_witness = Some(witness);
        }
    }

    fn clear_finalized_input(&mut self, index: usize) {
        let mut input = &mut self.psbt.inputs[index];
        input.tap_key_sig = None;
        input.tap_scripts = BTreeMap::new();
        input.tap_internal_key = None;
        input.tap_merkle_root = None;
        input.tap_script_sigs = BTreeMap::new();
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
        input.unknown = BTreeMap::new();
    }

    fn hash160(input: &[u8]) -> hash160::Hash {
        Hash::hash(input)
    }
}

pub fn sign_psbt(
    chain_type: &str,
    derivation_path: &str,
    psbt_input: PsbtInput,
    network: Network,
) -> Result<PsbtOutput> {
    let mut reader = Cursor::new(Vec::<u8>::from_hex(psbt_input.data)?);
    let mut psbt = Psbt::consensus_decode(&mut reader)?;
    let mut signer = PsbtSigner::new(&mut psbt, derivation_path, psbt_input.auto_finalize);

    select_btc_applet()?;

    signer.prevouts()?;

    let pub_keys = signer.get_pub_key()?;

    signer.calc_tx_hash()?;

    signer.tx_preview(network)?;

    signer.sign(&pub_keys)?;

    let mut vec = Vec::<u8>::new();
    let mut writer = Cursor::new(&mut vec);
    psbt.consensus_encode(&mut writer)?;

    return Ok(PsbtOutput { data: hex::encode(vec) });
}

#[cfg(test)]
mod test{
    use crate::btcapi::PsbtInput;
    use ikc_device::device_binding::bind_test;
    use bitcoin::consensus::Decodable;
    use bitcoin::psbt::serialize::{Deserialize, Serialize};
    use bitcoin::psbt::Psbt;
    use bitcoin::schnorr::TapTweak;
    use bitcoin::{schnorr, Network};
    use secp256k1::{Message, XOnlyPublicKey};
    use std::io::Cursor;
    use hex::FromHex;

    #[test]
    fn test_sign_psbt_no_script() {
        bind_test();

        let psbt_input = PsbtInput {
            data: "70736274ff0100db0200000001fa4c8d58b9b6c56ed0b03f78115246c99eb70f99b837d7b4162911d1016cda340200000000fdffffff0350c30000000000002251202114eda66db694d87ff15ddd5d3c4e77306b6e6dd5720cbd90cd96e81016c2b30000000000000000496a47626274340066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229ec20acf33c17e5a6c92cced9f1d530cccab7aa3e53400456202f02fac95e9c481fa00d47b1700000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233d80f03000001012be3bf1d00000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c23301172066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e00000000".to_string(),
            auto_finalize: true,
        };

        let psbt_output = super::sign_psbt("BITCOIN", "m/86'/1'/0'", psbt_input, Network::Bitcoin).unwrap();
        let mut reader = Cursor::new(Vec::<u8>::from_hex(&psbt_output.data).unwrap());
        let psbt = Psbt::consensus_decode(&mut reader).unwrap();
        let tx = psbt.extract_tx();
        let sig = schnorr::SchnorrSig::from_slice(&tx.input[0].witness.to_vec()[0]).unwrap();
        let a = sig.clone().to_vec();
        println!("a->{}", hex::encode(a));
        let data =
            Vec::<u8>::from_hex("3a66cf6ec1a87b10b86fa358baf64484bba8c61c9828e5cbe2eb8a3d4bbf190c")
                .unwrap();
        let msg = Message::from_slice(&data).unwrap();
        let x_pub_key = XOnlyPublicKey::from_slice(
            Vec::<u8>::from_hex("66f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e")
                .unwrap()
                .as_slice(),
        )
            .unwrap();
        let SECP256K1_ENGINE: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
        let tweak_pub_key = x_pub_key.tap_tweak(&SECP256K1_ENGINE, None);

        // assert!(sig.sig.verify(&msg, &tweak_pub_key.0.to_inner()).is_ok());
    }
}
