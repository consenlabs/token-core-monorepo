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
use ikc_device::async_device_manager::AsyncApduTransport;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use lazy_static::lazy_static;
use secp256k1::ecdsa::Signature;

pub struct CkbSigner {}

pub struct CkbTxSigner<'a> {
    sign_param: &'a SignParam,
}

lazy_static! {
    pub static ref SIGNATURE_PLACEHOLDER: String = "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned();
}

impl<'a> CkbTxSigner<'a> {
    fn witness_hash(tx_hash: &[u8], witness_group: &[&Witness]) -> Result<(Witness, [u8; 32])> {
        let first = witness_group.first().ok_or(Error::WitnessGroupEmpty)?;
        let empty_witness = Witness {
            lock: SIGNATURE_PLACEHOLDER.clone(),
            input_type: first.input_type.clone(),
            output_type: first.output_type.clone(),
        };
        let serialized = empty_witness.serialize()?;
        let mut hasher = new_blake2b();
        hasher.update(tx_hash);
        hasher.update(&Serializer::serialize_u64(serialized.len() as u64));
        hasher.update(&serialized);
        for witness in &witness_group[1..] {
            let bytes = witness.to_raw()?;
            hasher.update(&Serializer::serialize_u64(bytes.len() as u64));
            hasher.update(&bytes);
        }
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        Ok((empty_witness, hash))
    }

    fn validate_sender(&self, pub_key: &str) -> Result<()> {
        let compressed_pubkey = uncompress_pubkey_2_compress(pub_key);
        let pubkey_bytes = hex::decode(compressed_pubkey)?;
        let testnet_address = CkbAddress::from_public_key("TESTNET", &pubkey_bytes)?;
        let mainnet_address = CkbAddress::from_public_key("MAINNET", &pubkey_bytes)?;
        if testnet_address != self.sign_param.sender && mainnet_address != self.sign_param.sender {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }
        Ok(())
    }

    fn prepare_signing_payload(&self, hash: &[u8], path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut data_pack = Vec::new();
        data_pack.extend([1, hash.len() as u8]);
        data_pack.extend(hash);
        data_pack.extend([2, path.len() as u8]);
        data_pack.extend(path.as_bytes());
        data_pack.extend([7, self.sign_param.payment.len() as u8]);
        data_pack.extend(self.sign_param.payment.as_bytes());

        let receiver = if self.sign_param.receiver.len() > 100 {
            format!(
                "{}***{}",
                &self.sign_param.receiver[..47],
                &self.sign_param.receiver[self.sign_param.receiver.len() - 50..]
            )
        } else {
            self.sign_param.receiver.clone()
        };
        data_pack.extend([8, receiver.len() as u8]);
        data_pack.extend(receiver.as_bytes());
        data_pack.extend([9, self.sign_param.fee.len() as u8]);
        data_pack.extend(self.sign_param.fee.as_bytes());

        let (bind_signature, se_pub_key) = {
            let key_manager = KEY_MANAGER.lock();
            (
                secp256k1_sign(&key_manager.pri_key, &data_pack)?,
                key_manager.se_pub_key.clone(),
            )
        };
        let mut apdu_pack = Vec::new();
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(&bind_signature);
        apdu_pack.extend(&data_pack);
        Ok((apdu_pack, se_pub_key))
    }

    fn finish_recoverable_signature(
        hash: &[u8],
        pub_key: &str,
        se_pub_key: &[u8],
        sign_response: &str,
    ) -> Result<String> {
        let payload_end = sign_response
            .len()
            .checked_sub(4)
            .ok_or(CoinError::InvalidParam)?;
        let sign_source = sign_response.get(..132).ok_or(CoinError::InvalidParam)?;
        let sign_result = sign_response
            .get(132..payload_end)
            .ok_or(CoinError::InvalidParam)?;
        if !utility::secp256k1_sign_verify(
            se_pub_key,
            &hex::decode(sign_result)?,
            &hex::decode(sign_source)?,
        )? {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let compact = sign_response.get(2..130).ok_or(CoinError::InvalidParam)?;
        let mut signature = Signature::from_compact(&hex::decode(compact)?)?;
        signature.normalize_s();
        let normalized = signature.serialize_compact();
        let rec_id = utility::retrieve_recid(hash, &normalized, &hex::decode(pub_key)?)?;
        Ok(format!(
            "{}{:02x}",
            hex::encode(normalized),
            i32::from(rec_id)
        ))
    }

    pub async fn sign_witnesses_async<T>(
        &mut self,
        transport: &T,
        tx_hash: &[u8],
        witnesses: &[Witness],
        input_cells: &[&CachedCell],
    ) -> Result<Vec<String>>
    where
        T: AsyncApduTransport + ?Sized,
    {
        if tx_hash.len() != 32 {
            return Err(Error::InvalidTxHash.into());
        }
        if witnesses.is_empty() {
            return Err(Error::WitnessEmpty.into());
        }

        let grouped_scripts = self.group_script(input_cells)?;
        let mut raw_witnesses = witnesses
            .iter()
            .map(|witness| {
                witness
                    .to_raw()
                    .map(|raw| format!("0x{}", hex::encode(raw)))
            })
            .collect::<Result<Vec<_>>>()?;

        for indices in grouped_scripts.values() {
            let mut witness_group = indices
                .iter()
                .map(|index| &witnesses[*index])
                .collect::<Vec<_>>();
            if witnesses.len() > input_cells.len() {
                witness_group.extend(&witnesses[input_cells.len()..]);
            }

            let derived_path = &input_cells[indices[0]].derived_path;
            let path = if derived_path.is_empty() {
                &self.sign_param.path
            } else {
                derived_path
            };
            let signed_witness = self
                .sign_witness_group_async(transport, tx_hash, &witness_group, path)
                .await?;
            raw_witnesses[indices[0]] = format!("0x{}", hex::encode(signed_witness.serialize()?));
        }

        Ok(raw_witnesses)
    }

    async fn sign_witness_group_async<T>(
        &mut self,
        transport: &T,
        tx_hash: &[u8],
        witness_group: &[&Witness],
        path: &str,
    ) -> Result<Witness>
    where
        T: AsyncApduTransport + ?Sized,
    {
        let (mut empty_witness, hash) = Self::witness_hash(tx_hash, witness_group)?;
        empty_witness.lock = format!(
            "0x{}",
            self.sign_recoverable_hash_async(transport, &hash, path)
                .await?
        );
        Ok(empty_witness)
    }

    async fn sign_recoverable_hash_async<T>(
        &mut self,
        transport: &T,
        hash: &[u8],
        path: &str,
    ) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        let select_apdu = Apdu::try_select_applet(NERVOS_AID)?;
        let select_result = transport.send_apdu(&select_apdu, 20).await?;
        ApduCheck::check_response(&select_result)?;

        let pub_key = CkbAddress::get_public_key_async(transport, path).await?;
        self.validate_sender(&pub_key)?;
        let (apdu_pack, se_pub_key) = self.prepare_signing_payload(hash, path)?;

        let mut sign_response = String::new();
        for apdu in Secp256k1Apdu::sign(&apdu_pack) {
            sign_response = transport.send_apdu(&apdu, constants::TIMEOUT_LONG).await?;
            ApduCheck::check_response(&sign_response)?;
        }

        Self::finish_recoverable_signature(hash, &pub_key, &se_pub_key, &sign_response)
    }

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

        if witnesses.is_empty() {
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

            let derived_path = &input_cells[item.1[0]].derived_path;
            let path = if derived_path.is_empty() {
                &self.sign_param.path
            } else {
                derived_path
            };

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
        let (mut empty_witness, hash) = Self::witness_hash(tx_hash, witness_group)?;
        let signature = self.sign_recoverable_hash(&hash, path)?;
        empty_witness.lock = format!("0x{}", signature);
        Ok(empty_witness)
    }

    fn sign_recoverable_hash(&mut self, hash: &[u8], path: &str) -> Result<String> {
        let select_apdu = Apdu::try_select_applet(NERVOS_AID)?;
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let pub_key = CkbAddress::get_public_key(path)?;
        self.validate_sender(&pub_key)?;
        let (apdu_pack, se_pub_key) = self.prepare_signing_payload(hash, path)?;

        let mut sign_response = "".to_string();
        let sign_apdus = Secp256k1Apdu::sign(&apdu_pack);
        for apdu in sign_apdus {
            sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }

        Self::finish_recoverable_signature(hash, &pub_key, &se_pub_key, &sign_response)
    }

    fn group_script(
        &mut self,
        input_cells: &[&CachedCell],
    ) -> Result<HashMap<Vec<u8>, Vec<usize>>> {
        let mut map: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();

        for (i, item) in input_cells.iter().enumerate() {
            if item.lock.is_none() {
                continue;
            }

            let hash = item.lock.as_ref().unwrap().to_hash()?;
            if let Some(indices) = map.get_mut(&hash) {
                indices.push(i);
            } else {
                map.insert(hash, vec![i]);
            }
        }

        Ok(map)
    }
}

impl CkbSigner {
    fn input_cells(tx: &CkbTxInput) -> Result<Vec<&CachedCell>> {
        let find_cache_cell = |out_point: &OutPoint| -> Result<&CachedCell> {
            tx.cached_cells
                .iter()
                .find(|cell| {
                    cell.out_point.as_ref().is_some_and(|cached_point| {
                        cached_point.index == out_point.index
                            && cached_point.tx_hash == out_point.tx_hash
                    })
                })
                .ok_or_else(|| Error::CellInputNotCached.into())
        };
        let input_cells = tx
            .inputs
            .iter()
            .map(|input| {
                input
                    .previous_output
                    .as_ref()
                    .ok_or_else(|| Error::InvalidOutputPoint.into())
                    .and_then(find_cache_cell)
            })
            .collect::<Result<Vec<_>>>()?;
        if tx.witnesses.len() < input_cells.len() || input_cells.is_empty() {
            return Err(Error::InvalidInputCells.into());
        }
        Ok(input_cells)
    }

    pub async fn sign_transaction_async<T>(
        transport: &T,
        tx: &CkbTxInput,
        sign_param: &SignParam,
    ) -> Result<CkbTxOutput>
    where
        T: AsyncApduTransport + ?Sized,
    {
        if tx.witnesses.is_empty() {
            return Err(Error::RequiredWitness.into());
        }

        let input_cells = Self::input_cells(tx)?;

        let mut signer = CkbTxSigner { sign_param };
        let signed_witnesses = signer
            .sign_witnesses_async(
                transport,
                &hex_to_bytes(&tx.tx_hash)?,
                &tx.witnesses,
                &input_cells,
            )
            .await?;

        Ok(CkbTxOutput {
            tx_hash: tx.tx_hash.clone(),
            witnesses: signed_witnesses,
        })
    }

    pub fn sign_transaction(tx: &CkbTxInput, sign_param: &SignParam) -> Result<CkbTxOutput> {
        if tx.witnesses.is_empty() {
            return Err(Error::RequiredWitness.into());
        }

        let input_cells = Self::input_cells(tx)?;

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
    use crate::nervosapi::{CachedCell, CkbTxInput, OutPoint, Witness};
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
            tx_hash: tx_hash.to_owned(),
            cached_cells,
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
            seg_wit: "".to_string(),
        };

        let tx_output = CkbSigner::sign_transaction(&tx_input, &sign_param).expect("sign error");
        assert_eq!(tx_output.witnesses[0], "0x55000000100000005500000055000000410000009b87828a6274850b4c8724a286b882aae3ace127c124e4f6687070c09e2533c80b33ace45005a4912f4d092e31f017a8dc9f2f97ef66fb5e2b5e9314ade9b60e00");
    }
}
