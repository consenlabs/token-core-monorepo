use crate::hash::new_blake2b;
use crate::nervosapi::{CachedCell, CkbTxInput, CkbTxOutput, OutPoint, Witness};
use crate::serializer::Serializer;
use crate::Result;
use crate::{hex_to_bytes, Error};
use std::collections::HashMap;

use crate::address::CkbAddress;
use ikc_common::apdu::{Apdu, ApduCheck, Secp256k1Apdu};
use ikc_common::constants::NERVOS_AID;
use ikc_common::error::CoinError;
use ikc_common::utility::{secp256k1_sign, uncompress_pubkey_2_compress};
use ikc_common::{constants, utility, SignParam};
use ikc_device::device_binding::KEY_MANAGER;
use lazy_static::lazy_static;
use secp256k1::Signature;
use ikc_transport::message::{send_apdu, send_apdu_timeout};

pub struct CkbSigner {}

pub struct CkbTxSigner<'a> {
    sign_param: &'a SignParam,
}

lazy_static! {
    pub static ref SIGNATURE_PLACEHOLDER: String = "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned();
}

impl<'a> CkbTxSigner<'a> {
    pub fn sign_witnesses(
        &mut self,
        tx_hash: &[u8],
        witnesses: &[Witness],
        input_cells: &[&CachedCell],
    ) -> Result<Vec<String>> {
        // tx_hash must be 256 bit length
        if tx_hash.len() != 32 {
            return Err(Error::InvalidTxHash.into());
        }

        if witnesses.len() == 0 {
            return Err(Error::WitnessEmpty.into());
        }

        let grouped_scripts = self.group_script(input_cells)?;

        let mut raw_witnesses: Vec<String> = vec![];
        for w in witnesses.iter() {
            raw_witnesses.push(format!("0x{}", hex::encode(w.to_raw()?)));
        }

        for item in grouped_scripts.iter() {
            let mut ws = vec![];
            ws.extend(item.1.iter().map(|i| &witnesses[*i]));

            if witnesses.len() > input_cells.len() {
                ws.extend(&witnesses[input_cells.len()..]);
            }

            let path = &input_cells[item.1[0]].derived_path;

            let signed_witness = self.sign_witness_group(tx_hash, &ws, path)?;
            raw_witnesses[item.1[0]] = format!("0x{}", hex::encode(signed_witness.serialize()?));
        }

        Ok(raw_witnesses)
    }

    pub fn sign_witness_group(
        &mut self,
        tx_hash: &[u8],
        witness_group: &[&Witness],
        path: &str,
    ) -> Result<Witness> {
        if witness_group.len() == 0 {
            return Err(Error::WitnessGroupEmpty.into());
        }

        let first = &witness_group[0];

        let mut empty_witness = Witness {
            lock: SIGNATURE_PLACEHOLDER.clone(),
            input_type: first.input_type.clone(),
            output_type: first.output_type.clone(),
        };

        let serialized_empty_witness = empty_witness.serialize()?;
        let serialized_empty_length = serialized_empty_witness.len();

        let mut s = new_blake2b();
        s.update(tx_hash);
        s.update(&Serializer::serialize_u64(serialized_empty_length as u64));
        s.update(&serialized_empty_witness);

        for w in witness_group[1..].iter() {
            let bytes = w.to_raw()?;
            s.update(&Serializer::serialize_u64(bytes.len() as u64));
            s.update(&bytes);
        }

        let mut result = [0u8; 32];
        s.finalize(&mut result);

        let signature = self.sign_recoverable_hash(&result)?;
        empty_witness.lock = format!("0x{}", signature);

        Ok(empty_witness)
    }

    fn sign_recoverable_hash(&mut self, hash: &[u8]) -> Result<String> {
        println!("hash:{}", hex::encode(hash));
        let select_apdu = Apdu::select_applet(NERVOS_AID);
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let pub_key = CkbAddress::get_public_key(&self.sign_param.path)?;
        let comprs_pubkey = uncompress_pubkey_2_compress(&pub_key);
        let testnet_address =
            CkbAddress::from_public_key("TESTNET", &hex::decode(&comprs_pubkey)?).unwrap();
        let mainnet_address =
            CkbAddress::from_public_key("MAINNET", &hex::decode(&comprs_pubkey)?).unwrap();
        if testnet_address != self.sign_param.sender && mainnet_address != self.sign_param.sender {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }

        //organize data
        let mut data_pack: Vec<u8> = Vec::new();

        data_pack.extend([1, hash.len() as u8].iter());
        data_pack.extend(hash.iter());

        //path
        data_pack.extend([2, self.sign_param.path.as_bytes().len() as u8].iter());
        data_pack.extend(self.sign_param.path.as_bytes().iter());
        //payment info in TLV format
        data_pack.extend([7, self.sign_param.payment.as_bytes().len() as u8].iter());
        data_pack.extend(self.sign_param.payment.as_bytes().iter());
        //receiver info in TLV format
        let mut receiver_address = self.sign_param.receiver.clone();
        if receiver_address.len() > 100 {
            receiver_address = format!(
                "{}{}{}",
                &receiver_address[..47].to_string(),
                "***".to_string(),
                &receiver_address[receiver_address.len() - 50..]
            );
        }
        data_pack.extend([8, receiver_address.as_bytes().len() as u8].iter());
        data_pack.extend(receiver_address.as_bytes().iter());
        //fee info in TLV format
        data_pack.extend([9, self.sign_param.fee.as_bytes().len() as u8].iter());
        data_pack.extend(self.sign_param.fee.as_bytes().iter());

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &data_pack).unwrap();

        let mut apdu_pack: Vec<u8> = Vec::new();
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.extend(data_pack.as_slice());

        let mut sign_response = "".to_string();
        let sign_apdus = Secp256k1Apdu::sign(&apdu_pack);
        for apdu in sign_apdus {
            sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }

        // verify
        let sign_source_val = &sign_response[..132];
        let sign_result = &sign_response[132..sign_response.len() - 4];
        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;

        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let sign_compact = hex::decode(&sign_response[2..130]).unwrap();
        let mut signnture_obj = Signature::from_compact(sign_compact.as_slice()).unwrap();
        signnture_obj.normalize_s();
        let normalizes_sig_vec = signnture_obj.serialize_compact();

        let rec_id =
            utility::retrieve_recid(&hash, &normalizes_sig_vec, &hex::decode(&pub_key)?).unwrap();
        let rec_id = rec_id.to_i32();

        let mut signature = hex::encode(&normalizes_sig_vec.as_ref());
        signature.push_str(&format!("{:02x}", &rec_id));

        Ok(signature)
    }

    fn group_script(
        &mut self,
        input_cells: &[&CachedCell],
    ) -> Result<HashMap<Vec<u8>, Vec<usize>>> {
        let mut map: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();

        for i in 0..input_cells.len() {
            let item = &input_cells[i];
            if item.lock.is_none() {
                continue;
            }

            let hash = item.lock.as_ref().unwrap().to_hash()?;
            let indices = map.get_mut(&hash);
            if indices.is_some() {
                indices.unwrap().push(i);
            } else {
                map.insert(hash, vec![i]);
            }
        }

        Ok(map)
    }
}

impl CkbSigner {
    pub fn sign_transaction(tx: &CkbTxInput, sign_param: &SignParam) -> Result<CkbTxOutput> {
        if tx.witnesses.len() == 0 {
            return Err(Error::RequiredWitness.into());
        }

        let find_cache_cell = |x: &OutPoint| -> Result<&CachedCell> {
            for y in tx.cached_cells.iter() {
                if y.out_point.is_some() {
                    let point = y.out_point.as_ref().unwrap();
                    if point.index == x.index && point.tx_hash == x.tx_hash {
                        return Ok(y);
                    }
                }
            }

            Err(Error::CellInputNotCached.into())
        };

        let mut input_cells: Vec<&CachedCell> = vec![];

        for x in tx.inputs.iter() {
            if x.previous_output.is_none() {
                return Err(Error::InvalidOutputPoint.into());
            }

            input_cells.push(find_cache_cell(x.previous_output.as_ref().unwrap())?);
        }

        if tx.witnesses.len() < input_cells.len() || input_cells.len() == 0 {
            return Err(Error::InvalidInputCells.into());
        }

        let mut signer = CkbTxSigner { sign_param };

        let signed_witnesses =
            signer.sign_witnesses(&hex_to_bytes(&tx.tx_hash)?, &tx.witnesses, &input_cells)?;

        let tx_output = CkbTxOutput {
            tx_hash: tx.tx_hash.clone(),
            witnesses: signed_witnesses,
        };

        Ok(tx_output)
    }
}

#[cfg(test)]
mod tests {
    use crate::address::CkbAddress;
    use crate::nervosapi::{CachedCell, CkbTxInput, CkbTxOutput, OutPoint, Witness};
    use crate::signer::CkbSigner;
    use crate::{CellInput, Script};
    use ikc_common::{constants, SignParam};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_sign_transaction() {
        bind_test();

        let tx_hash = "0x719933ec055272734ab709a80492edb44c083e6b675e5c37e5bb3f720fe88e5e";
        let witnesses = vec![Witness::default(), Witness::default(), Witness::default()];
        let cached_cells = vec![
            CachedCell {
                out_point: Some({
                    OutPoint {
                        tx_hash:
                            "0x67b35360a09ecbdaf7cef55bb9b58b194d1e067007c67d67520ee730fcd1f252"
                                .to_owned(),
                        index: 0,
                    }
                }),
                lock: Some(Script {
                    args: "0xb1e8f5e7b4be7867ca6cd556ee3954a325979f45".to_owned(),
                    code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
                        .to_owned(),
                    hash_type: "type".to_string(),
                }),
                ..CachedCell::default()
            },
            CachedCell {
                out_point: Some({
                    OutPoint {
                        tx_hash:
                            "0x67b35360a09ecbdaf7cef55bb9b58b194d1e067007c67d67520ee730fcd1f252"
                                .to_owned(),
                        index: 1,
                    }
                }),
                lock: Some(Script {
                    args: "0xb1e8f5e7b4be7867ca6cd556ee3954a325979f45".to_owned(),
                    code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
                        .to_owned(),
                    hash_type: "type".to_string(),
                }),
                ..CachedCell::default()
            },
            CachedCell {
                out_point: Some({
                    OutPoint {
                        tx_hash:
                            "0x67b35360a09ecbdaf7cef55bb9b58b194d1e067007c67d67520ee730fcd1f252"
                                .to_owned(),
                        index: 2,
                    }
                }),
                lock: Some(Script {
                    args: "0xb1e8f5e7b4be7867ca6cd556ee3954a325979f45".to_owned(),
                    code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
                        .to_owned(),
                    hash_type: "type".to_string(),
                }),
                ..CachedCell::default()
            },
        ];

        let inputs = vec![
            CellInput {
                previous_output: Some(OutPoint {
                    tx_hash: "0x67b35360a09ecbdaf7cef55bb9b58b194d1e067007c67d67520ee730fcd1f252"
                        .to_owned(),
                    index: 0,
                }),
                since: "".to_owned(),
            },
            CellInput {
                previous_output: Some(OutPoint {
                    tx_hash: "0x67b35360a09ecbdaf7cef55bb9b58b194d1e067007c67d67520ee730fcd1f252"
                        .to_owned(),
                    index: 1,
                }),
                since: "".to_string(),
            },
            CellInput {
                previous_output: Some(OutPoint {
                    tx_hash: "0x67b35360a09ecbdaf7cef55bb9b58b194d1e067007c67d67520ee730fcd1f252"
                        .to_owned(),
                    index: 2,
                }),
                since: "".to_string(),
            },
        ];

        let tx_input = CkbTxInput {
            inputs,
            witnesses,
            tx_hash: tx_hash.clone().to_owned(),
            cached_cells,
            ..CkbTxInput::default()
        };

        let sign_param = SignParam {
            chain_type: "NERVOS".to_string(),
            path: constants::NERVOS_PATH.to_string(),
            network: "TESTNET".to_string(),
            input: None,
            payment: "62 ckb".to_string(),
            receiver: "ckt1qyqtr684u76tu7r8efkd24hw8922xfvhnazskzdzy6".to_string(),
            sender: "ckt1qyqtr684u76tu7r8efkd24hw8922xfvhnazskzdzy6".to_string(),
            fee: "0.0001191 ckb".to_string(),
        };

        let tx_output = CkbSigner::sign_transaction(&tx_input, &sign_param).expect("sign error");
        assert_eq!(tx_output.witnesses[0], "0x55000000100000005500000055000000410000009b87828a6274850b4c8724a286b882aae3ace127c124e4f6687070c09e2533c80b33ace45005a4912f4d092e31f017a8dc9f2f97ef66fb5e2b5e9314ade9b60e00");
    }
}
