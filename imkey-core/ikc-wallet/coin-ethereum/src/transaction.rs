use crate::address::EthAddress;
use crate::ethapi::{
    EthBatchMessageInput, EthBatchMessageOutput, EthMessageInput, EthMessageOutput, EthTxOutput,
};
use crate::types::{Action, Signature};
use crate::Result as EthResult;
use ethereum_types::{Address, H256, U256};
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, EthApdu};
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{hex_to_bytes, is_valid_hex, keccak_256_hash, secp256k1_sign};
use ikc_common::{constants, utility, SignParam};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use keccak_hash::keccak;
use lazy_static::lazy_static;
use rlp::{self, Encodable, RlpStream};
use secp256k1::{self, Signature as SecpSignature};
use tiny_keccak::Hasher;

lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Transaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: Action,
    pub value: U256,
    pub data: Vec<u8>,
    pub tx_type: String,
    pub max_fee_per_gas: ::std::option::Option<U256>,
    pub max_priority_fee_per_gas: ::std::option::Option<U256>,
    pub access_list: ::std::vec::Vec<AccessListItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}

impl Encodable for AccessListItem {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.address);
        s.append_list(&self.storage_keys);
    }
}

impl Transaction {
    /// Signs the transaction as coming from `sender`.
    pub fn sign(
        &self,
        chain_id: Option<u64>,
        path: &str,
        payment: &str,
        receiver: &str,
        sender: &str,
        fee: &str,
    ) -> EthResult<EthTxOutput> {
        // ) {
        //check path
        check_path_validity(path)?;

        //organize data
        let mut data_pack: Vec<u8> = Vec::new();
        let mut encode_tx = self.rlp_encode_tx(chain_id);
        if &self.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            encode_tx.insert(0, hex::decode(&self.tx_type).unwrap()[0]);
        }
        //rlp encoded tx in TLV format
        data_pack.extend(
            [
                1,
                ((encode_tx.len() & 0xFF00) >> 8) as u8,
                (encode_tx.len() & 0x00FF) as u8,
            ]
            .iter(),
        );
        data_pack.extend(encode_tx.iter());
        //payment info in TLV format
        if payment.len() <= constants::ETH_MAX_SUPPORT_PAYMENT_LEN {
            data_pack.extend([7, payment.as_bytes().len() as u8].iter());
            data_pack.extend(payment.as_bytes().iter());
        } else {
            data_pack.extend([7, constants::ETH_MAX_SUPPORT_PAYMENT_LEN as u8].iter());
            data_pack.extend(
                payment[..constants::ETH_MAX_SUPPORT_PAYMENT_LEN]
                    .as_bytes()
                    .iter(),
            );
        }
        //receiver info in TLV format
        data_pack.extend([8, receiver.as_bytes().len() as u8].iter());
        data_pack.extend(receiver.as_bytes().iter());
        //fee info in TLV format
        data_pack.extend([9, fee.as_bytes().len() as u8].iter());
        data_pack.extend(fee.as_bytes().iter());

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &data_pack).unwrap();

        let mut apdu_pack: Vec<u8> = Vec::new();
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.extend(data_pack.as_slice());

        //select applet
        let select_apdu = EthApdu::select_applet();
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        //prepare apdu
        let msg_prepare = EthApdu::prepare_sign(apdu_pack);
        for msg in msg_prepare {
            let res = send_apdu_timeout(msg, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&res)?;
        }

        //get public
        let msg_pubkey = EthApdu::get_xpub(path, false);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        let pubkey_raw = hex_to_bytes(&res_msg_pubkey[..130]).unwrap();

        let address_main = EthAddress::address_from_pubkey(pubkey_raw.clone()).unwrap();
        let address_checksummed = EthAddress::address_checksummed(&address_main);
        //compare address
        if address_checksummed != *sender {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }
        //sign
        let msg_sign = EthApdu::sign_digest(path);
        let res_msg_sign = send_apdu(msg_sign)?;
        ApduCheck::check_response(&res_msg_sign)?;

        let sign_compact = &res_msg_sign[2..130];
        let sign_compact_vec = hex_to_bytes(sign_compact).unwrap(); //todo error

        let mut signature_obj = SecpSignature::from_compact(sign_compact_vec.as_slice()).unwrap();
        signature_obj.normalize_s();
        let normalizes_sig_vec = signature_obj.serialize_compact();

        let msg_hash = self.hash(chain_id);

        let rec_id =
            utility::retrieve_recid(&msg_hash[..], &normalizes_sig_vec, &pubkey_raw).unwrap();

        let mut data_arr = [0; 65];
        data_arr[0..64].copy_from_slice(&normalizes_sig_vec[0..64]);
        data_arr[64] = rec_id.to_i32() as u8;
        let sig = Signature(data_arr);

        let signed = self.with_signature(sig, chain_id);

        let mut tx_hash = hex::encode(signed.1.hash);
        if !tx_hash.starts_with("0x") {
            tx_hash.insert_str(0, "0x");
        }

        let mut signature = hex::encode(signed.0);
        if &self.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            signature.insert_str(0, &self.tx_type);
        }
        let tx_sign_result = EthTxOutput { signature, tx_hash };

        Ok(tx_sign_result)
    }

    pub fn rlp_encode_tx(&self, chain_id: Option<u64>) -> Vec<u8> {
        let mut stream = RlpStream::new();
        self.rlp_append_unsigned_transaction(&mut stream, chain_id);
        stream.as_raw().to_vec()
    }

    /// The message hash of the transaction.
    pub fn hash(&self, chain_id: Option<u64>) -> H256 {
        let mut stream = RlpStream::new();
        self.rlp_append_unsigned_transaction(&mut stream, chain_id);
        let mut encode_tx = stream.as_raw().to_vec();
        if &self.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            encode_tx.insert(0, hex::decode(&self.tx_type).unwrap()[0]);
        }
        keccak(encode_tx)
    }

    pub fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream, chain_id: Option<u64>) {
        s.begin_list(self.rlp_list_size(chain_id));

        if &self.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            s.append(&chain_id.unwrap());
            s.append(&self.nonce);
            s.append(&self.max_priority_fee_per_gas.unwrap());
            s.append(&self.max_fee_per_gas.unwrap());
        } else {
            s.append(&self.nonce);
            s.append(&self.gas_price);
        }
        s.append(&self.gas_limit);
        s.append(&self.to);
        s.append(&self.value);
        s.append(&self.data);

        if &self.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            s.append_list(&self.access_list);
        } else {
            if let Some(n) = chain_id {
                s.append(&n);
                s.append(&0u8);
                s.append(&0u8);
            }
        }
    }

    pub fn rlp_list_size(&self, chain_id: Option<u64>) -> usize {
        if &self.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            9
        } else {
            if chain_id.is_none() {
                6
            } else {
                9
            }
        }
    }

    pub fn hexstring_to_hex256(hex_string: &str) -> H256 {
        let mut hex_string = hex_string;
        if hex_string.starts_with("0x") {
            hex_string = &hex_string[2..];
        }
        let hex_vec = hex::decode(hex_string).unwrap();
        let mut result = [0u8; 32];
        result[0..32].copy_from_slice(&hex_vec.as_slice());
        H256(result)
    }

    pub fn with_signature(
        &self,
        sig: Signature,
        chain_id: Option<u64>,
    ) -> (Vec<u8>, UnverifiedTransaction) {
        let unverified = UnverifiedTransaction {
            unsigned: self.clone(),
            r: sig.r().into(),
            s: sig.s().into(),
            v: self.add_chain_replay_protection(sig.v() as u64, chain_id),
            hash: H256::zero(),
            chain_id: chain_id,
        };

        (unverified.rlp_bytes().to_vec(), unverified.compute_hash())
    }

    pub fn add_chain_replay_protection(&self, v: u64, chain_id: Option<u64>) -> u64 {
        if &self.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            v
        } else {
            v + if let Some(n) = chain_id {
                35 + n * 2
            } else {
                27
            }
        }
    }

    pub fn sign_message(
        input: EthMessageInput,
        sign_param: &SignParam,
    ) -> EthResult<EthMessageOutput> {
        check_path_validity(&sign_param.path)?;

        let message_to_sign;
        if is_valid_hex(&input.message) {
            let value = if input.message.to_lowercase().starts_with("0x") {
                &input.message[2..]
            } else {
                &input.message
            };

            message_to_sign = hex::decode(value).unwrap();
        } else {
            message_to_sign = input.message.into_bytes();
        }

        let mut data = Vec::new();
        if input.is_personal_sign {
            let header = format!("Ethereum Signed Message:\n{}", &message_to_sign.len());
            data.extend(header.as_bytes());
        }
        data.extend(message_to_sign);

        let mut data_to_sign: Vec<u8> = Vec::new();
        data_to_sign.push(0x01);
        data_to_sign.push(((data.len() & 0xFF00) >> 8) as u8);
        data_to_sign.push((data.len() & 0x00FF) as u8);
        data_to_sign.extend(data.as_slice());

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &data_to_sign)?;

        let mut apdu_pack: Vec<u8> = vec![];
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.extend(data_to_sign.as_slice());

        let select_apdu = EthApdu::select_applet();
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let msg_pubkey = EthApdu::get_xpub(&sign_param.path, false);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        let pubkey_raw = hex_to_bytes(&res_msg_pubkey[..130]).unwrap();
        let address_main = EthAddress::address_from_pubkey(pubkey_raw.clone()).unwrap();
        let address_checksummed = EthAddress::address_checksummed(&address_main);

        if &address_checksummed != &sign_param.sender {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }

        let prepare_apdus = EthApdu::prepare_personal_sign(apdu_pack);
        for apdu in prepare_apdus {
            let res = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&res)?;
        }

        let sign_apdu = EthApdu::personal_sign(&sign_param.path);
        let sign_response = send_apdu(sign_apdu)?;
        ApduCheck::check_response(&sign_response)?;

        let sign_compact = hex::decode(&sign_response[2..130]).unwrap();
        let mut signature_obj = SecpSignature::from_compact(sign_compact.as_slice()).unwrap();
        signature_obj.normalize_s();
        let normalizes_sig_vec = signature_obj.serialize_compact();

        let mut keccak256 = tiny_keccak::Keccak::v256();
        keccak256.update(data.as_slice());
        let mut data_hash = [0u8; 256 / 8];
        keccak256.finalize(&mut data_hash);
        let rec_id = utility::retrieve_recid(&data_hash, &normalizes_sig_vec, &pubkey_raw).unwrap();
        let rec_id = rec_id.to_i32();
        let v = rec_id + 27;

        let mut signature = hex::encode(&normalizes_sig_vec.as_ref());
        signature.push_str(&format!("{:02x}", &v));

        Ok(EthMessageOutput { signature })
    }

    pub fn batch_message_sign(
        input: EthBatchMessageInput,
        sign_param: &SignParam,
    ) -> EthResult<EthBatchMessageOutput> {
        check_path_validity(&sign_param.path)?;

        let select_apdu = EthApdu::select_applet();
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        //sender address check
        let msg_pubkey = EthApdu::get_xpub(&sign_param.path, false);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        let pubkey_raw = hex_to_bytes(&res_msg_pubkey[..130]).unwrap();
        let address_main = EthAddress::address_from_pubkey(pubkey_raw.clone()).unwrap();
        let address_checksummed = EthAddress::address_checksummed(&address_main);
        if &address_checksummed != &sign_param.sender {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }
        //path
        let path_bytes = sign_param.path.as_bytes();
        let mut tlv_path = vec![];
        tlv_path.push(0x02);
        tlv_path.push(path_bytes.len() as u8);
        tlv_path.extend(path_bytes);

        //total number
        let sign_number = input.messages.len();
        let mut tlv_total_number = vec![];
        tlv_total_number.push(0x04);
        tlv_total_number.push(0x02);
        tlv_total_number.extend(hex::decode(format!("{:04X}", sign_number))?);

        let mut singatures = vec![];
        for (index, msg) in input.messages.iter().enumerate() {
            let message = if is_valid_hex(&msg) {
                let value = if msg.to_lowercase().starts_with("0x") {
                    &msg[2..]
                } else {
                    msg.as_str()
                };
                hex::decode(value)?
            } else {
                msg.as_bytes().to_vec()
            };

            let mut sign_data = vec![];
            if input.is_personal_sign {
                sign_data
                    .extend(format!("Ethereum Signed Message:\n{}", &message.len()).as_bytes());
            }
            sign_data.extend(message);
            let hash = keccak_256_hash(&sign_data.as_ref());

            let key_manager_obj = KEY_MANAGER.lock();
            let sdk_prikey_signature = secp256k1_sign(&key_manager_obj.pri_key, &hash)?;

            let mut data: Vec<u8> = Vec::new();
            //signature
            data.push(0x00);
            data.push(sdk_prikey_signature.len() as u8);
            data.extend(sdk_prikey_signature.as_slice());
            //hash
            data.push(0x01);
            data.push(hash.len() as u8);
            data.extend(hash.iter());
            //path
            data.extend(tlv_path.clone());
            //index
            data.push(0x03);
            data.push(0x02);
            data.extend(hex::decode(format!("{:04X}", index + 1))?);
            //total number
            data.extend(tlv_total_number.clone());

            let p1 = if index == 0 { 0x00 } else { 0x80 };
            let p2 = if index == sign_number - 1 { 0x80 } else { 0x00 };
            let sign_apdu = EthApdu::batch_personal_sign(p1, p2, data);
            println!("sign_apdu:{}", sign_apdu);

            let sign_response = send_apdu(sign_apdu)?;
            ApduCheck::check_response(&sign_response)?;

            let sign_compact = hex::decode(&sign_response[2..130]).unwrap();
            let mut signature_obj = SecpSignature::from_compact(sign_compact.as_slice()).unwrap();
            signature_obj.normalize_s();
            let normalizes_sig_vec = signature_obj.serialize_compact();

            let rec_id = utility::retrieve_recid(&hash, &normalizes_sig_vec, &pubkey_raw).unwrap();
            let rec_id = rec_id.to_i32();
            let v = rec_id + 27;

            let mut signature = hex::encode(&normalizes_sig_vec.as_ref());
            signature.push_str(&format!("{:02x}", &v));

            singatures.push(signature);
        }
        Ok(EthBatchMessageOutput {
            signatures: singatures,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnverifiedTransaction {
    /// Plain Transaction.
    unsigned: Transaction,
    /// The V field of the signature; the LS bit described which half of the curve our point falls
    /// in. The MS bits describe which chain this transaction is for. If 27/28, its for all chains.
    v: u64,
    /// The R field of the signature; helps describe the point on the curve.
    r: U256,
    /// The S field of the signature; helps describe the point on the curve.
    s: U256,
    /// Hash of the transaction
    pub hash: H256,
    pub chain_id: ::std::option::Option<u64>,
}

impl rlp::Encodable for UnverifiedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.rlp_append_sealed_transaction(s)
    }
}

impl UnverifiedTransaction {
    /// Used to compute hash of created transactions
    fn compute_hash(mut self) -> UnverifiedTransaction {
        let mut rlp_bytes = self.rlp_bytes().to_vec();
        if &self.unsigned.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            rlp_bytes.insert(0, hex::decode(&self.unsigned.tx_type).unwrap()[0]);
        }
        let hash = keccak(&rlp_bytes);
        self.hash = hash;
        println!("hash:{}", &hex::encode(&hash));
        self
    }

    /// Append object with a signature into RLP stream
    fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
        if &self.unsigned.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            s.begin_list(12);
            s.append(&self.chain_id.unwrap());
            s.append(&self.unsigned.nonce);
            s.append(&self.unsigned.max_priority_fee_per_gas.unwrap());
            s.append(&self.unsigned.max_fee_per_gas.unwrap());
        } else {
            s.begin_list(9);
            s.append(&self.unsigned.nonce);
            s.append(&self.unsigned.gas_price);
        }
        s.append(&self.unsigned.gas_limit);
        s.append(&self.unsigned.to);
        s.append(&self.unsigned.value);
        s.append(&self.unsigned.data);

        if &self.unsigned.tx_type == constants::ETH_TRANSACTION_TYPE_EIP1559 {
            s.append_list(&self.unsigned.access_list);
        }
        s.append(&self.v);
        s.append(&self.r);
        s.append(&self.s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{AccessListItem, Transaction};
    use ethereum_types::{Address, U256};
    use hex;
    use ikc_common::constants;
    use ikc_device::device_binding::bind_test;
    use std::str::FromStr;

    #[test]
    fn test_sign_trans() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(8),
            gas_price: U256::from(20000000008 as usize),
            gas_limit: U256::from(189000),
            to: Action::Call(
                Address::from_str("3535353535353535353535353535353535353535").unwrap(),
            ),
            value: U256::from(512 as usize),
            data: Vec::new(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "f867088504a817c8088302e248943535353535353535353535353535353535353535820200805ba03aa62abb45b77418caf139dda0179aea802c99967b3d690b87d586a87bc805afa02b5ce94f40dc865ca63403e0e5e723e1523884f001573677cd8cec11c7ca332f".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0x09fa41c4d6b92482506c8c56f65b217cc3398821caec7695683110997426db01".to_string()
        );
    }

    #[test]
    fn test_data_is_null() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from_dec_str("13").unwrap(),
            gas_price: U256::from_dec_str("150000").unwrap(),
            gas_limit: U256::from_dec_str("21000000000").unwrap(),
            to: Action::Call(
                Address::from_str("7c47ef93268a311f4cad0c750724299e9b72c268").unwrap(),
            ),
            value: U256::from_dec_str("10000000000000000").unwrap(),
            data: Vec::new(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };
        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0x7c47ef93268a311f4cad0c750724299e9b72c268".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.tx_hash,
            "0x9cb10bab794454c5c2606b5475a35f6429f5ff54c3e088d0c5d330f56155b0be".to_string()
        );
    }

    #[test]
    fn test_data_is_long() {
        bind_test();

        let data = "0x60056013565b6101918061001d6000396000f35b3360008190555056006001600060e060020a6000350480630a874df61461003a57806341c0e1b514610058578063a02b161e14610066578063dbbdf0831461007757005b610045600435610149565b80600160a060020a031660005260206000f35b610060610161565b60006000f35b6100716004356100d4565b60006000f35b61008560043560243561008b565b60006000f35b600054600160a060020a031632600160a060020a031614156100ac576100b1565b6100d0565b8060018360005260205260406000208190555081600060005260206000a15b5050565b600054600160a060020a031633600160a060020a031614158015610118575033600160a060020a0316600182600052602052604060002054600160a060020a031614155b61012157610126565b610146565b600060018260005260205260406000208190555080600060005260206000a15b50565b60006001826000526020526040600020549050919050565b600054600160a060020a031633600160a060020a0316146101815761018f565b600054600160a060020a0316ff5b56".to_string();
        let data_vec;
        if data.starts_with("0x") {
            // data = hex::encode(&data[2..]);
            data_vec = hex::decode(&data[2..]).unwrap();
        } else {
            data_vec = hex::decode(&data).unwrap();
        }

        let tx = Transaction {
            nonce: U256::from_dec_str("13").unwrap(),
            gas_price: U256::from_dec_str("150000").unwrap(),
            gas_limit: U256::from_dec_str("21000000000").unwrap(),
            to: Action::Call(
                Address::from_str("7c47ef93268a311f4cad0c750724299e9b72c268").unwrap(),
            ),
            value: U256::from_dec_str("10000000000000000").unwrap(),
            data: Vec::from(data_vec.as_slice()),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };
        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0x7c47ef93268a311f4cad0c750724299e9b72c268".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.tx_hash,
            "0xff0c83a7c9208ea28712900cabc8cd5fe624b9c6bdc208517b6725c706422e08".to_string()
        );
    }

    #[test]
    fn test_zero_bytes() {
        bind_test();

        let data = "0x0000000000000000000000000000000000000000000000000000000000".to_string();
        let data_vec;
        if data.starts_with("0x") {
            // data = hex::encode(&data[2..]);
            data_vec = hex::decode(&data[2..]).unwrap();
        } else {
            data_vec = hex::decode(&data).unwrap();
        }

        let tx = Transaction {
            nonce: U256::from_dec_str("13").unwrap(),
            gas_price: U256::from_dec_str("150000").unwrap(),
            gas_limit: U256::from_dec_str("21000000000").unwrap(),
            to: Action::Call(
                Address::from_str("7c47ef93268a311f4cad0c750724299e9b72c268").unwrap(),
            ),
            value: U256::from_dec_str("10000000000000000").unwrap(),
            data: Vec::from(data_vec.as_slice()),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };
        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0x7c47ef93268a311f4cad0c750724299e9b72c268".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.tx_hash,
            "0x5481b9f73cb42eb2be84c4a3995ec1ea2fafc93597f564fe46b40d82026c4224".to_string()
        );
    }

    #[test]
    fn test_sign_personal_message() {
        bind_test();

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: constants::ETH_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "".to_string(),
        };
        let input = EthMessageInput {
            message: "Hello imKey".to_string(),
            is_personal_sign: true,
        };
        let output = Transaction::sign_message(input, &sign_param).unwrap();
        assert_eq!(
            output.signature,
            "d928f76ad80d63003c189b095078d94ae068dc2f18a5cafd97b3a630d7bc47465bd6f1e74de2e88c05b271e1c5a8b93564d9d8842c207482b20634d68f2d54e51b".to_string()
        );

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: constants::ETH_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "".to_string(),
        };
        let input = EthMessageInput {
            message: "0x8d61d40bb0761526fe24d84199321d5e9f6542e56c52018c401b963d64ef21678c18563a3eba889229ab078a8a1baed22226913f".to_string(),
            is_personal_sign: true
        };

        let output = Transaction::sign_message(input, &sign_param).unwrap();
        assert_eq!(
            output.signature,
            "35a94616ce12ddb79f6d351c2644c0fa2f496bd152b17102a5672359f583373b6dd5d2a60f5d9909cf84e6af7dc40176179c819a7cbd9b199f4c2e868530293f1b".to_string()
        );
    }

    #[test]
    fn test_ec_sign() {
        bind_test();

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: constants::ETH_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "".to_string(),
        };
        let input = EthMessageInput {
            message: "Hello imKey".to_string(),
            is_personal_sign: false,
        };
        let output = Transaction::sign_message(input, &sign_param).unwrap();
        assert_eq!(
            output.signature,
            "57c976d1fa15c7e833fd340bcb3a96974060ed555369d443449ac4429c1933433afa5304d1cfcb6799403f2b97a1e83309b98fae8ad5fade62335664d90e819f1b".to_string()
        );

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: constants::ETH_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "".to_string(),
        };
        let input = EthMessageInput {
            message: "0x8d61d40bb0761526fe24d84199321d5e9f6542e56c52018c401b963d64ef21678c18563a3eba889229ab078a8a1baed22226913f".to_string(),
            is_personal_sign: false
        };
        let output = Transaction::sign_message(input, &sign_param).unwrap();
        assert_eq!(
            output.signature,
            "3d8ba5e7375900476d715b479938e48a2e46e59f8e2e12673adb5e3df78a622050053ae0183f5e555e5db34ff43293de255f384709bd3fe6e00b8239c7f1a3561c".to_string()
        );
    }

    #[test]
    fn test_retrieve_recid() {
        let hash = "123faa96160f0b89a758c4f8585500d0ab6559565e184a02882c8b3cda20263d";
        let sign = "397828f985a5d19546fe59425d44c745c72152eac845e54fd748b457ba306c682582567be75888645d623225af599cc0ae9f285f8d0d020e7c9a9246985b4dda";
        let pubkey = "04aaf80e479aac0813b17950c390a16438b307aee9a814689d6706be4fb4a4e30a4d2a7f75ef43344fa80580b5b1fbf9f233c378d99d5adb5cac9ae86f562803e1";

        let rec_id = utility::retrieve_recid(
            &hex::decode(hash).unwrap(),
            &&hex::decode(sign).unwrap(),
            &&hex::decode(pubkey).unwrap(),
        )
        .unwrap();
        let rec_id = rec_id.to_i32();
        assert_eq!(rec_id, 0);
    }

    #[test]
    fn test_address_mismatch() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from_dec_str("13").unwrap(),
            gas_price: U256::from_dec_str("150000").unwrap(),
            gas_limit: U256::from_dec_str("21000000000").unwrap(),
            to: Action::Call(
                Address::from_str("7c47ef93268a311f4cad0c750724299e9b72c268").unwrap(),
            ),
            value: U256::from_dec_str("10000000000000000").unwrap(),
            data: Vec::new(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };
        let path = "m/44'/60'/0'/0/1".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0x7c47ef93268a311f4cad0c750724299e9b72c268".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx.sign(Some(28), &path, &payment, &receiver, &sender, &fee);
        assert_eq!(
            format!("{}", tx_result.err().unwrap()),
            "imkey_address_mismatch_with_path"
        );

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path,
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "".to_string(),
        };
        let input = EthMessageInput {
            message: "Hello imKey".to_string(),
            is_personal_sign: true,
        };
        let output = Transaction::sign_message(input, &sign_param);
        assert_eq!(
            format!("{}", output.err().unwrap()),
            "imkey_address_mismatch_with_path"
        );
    }

    #[test]
    fn test_sign_eip1559_trans1() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(549),
            gas_price: U256::from(0 as usize),
            gas_limit: U256::from(21000),
            to: Action::Call(
                Address::from_str("03e2B0f5369297a2E7A13d6F8e6d4BFbB9cf7dC7").unwrap(),
            ),
            value: U256::from(500000000000000 as usize),
            data: Vec::new(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: Some(U256::from(2000000000)),
            max_priority_fee_per_gas: Some(U256::from(2000000000)),
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(42), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "02f8732a820225847735940084773594008252089403e2b0f5369297a2e7a13d6f8e6d4bfbb9cf7dc78701c6bf5263400080c001a0b6bd8b2f4d94910d72906cb20f83e9ec0808e00e92e8338f68a496ee77c29245a00c77abda1141f4991774b240f0fcd55faa19584e06d2bd43d4d5ceb6d4381207".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0x812824e60c60f8d46aa5e211c8e4a50baf92350c98c83e71c379d273ce0a0787".to_string()
        );
    }

    #[test]
    fn test_sign_eip1559_trans2() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(548),
            gas_price: U256::from(0 as usize),
            gas_limit: U256::from(220),
            to: Action::Call(
                Address::from_str("87e65b8280098da8f9bb3a69643573378da87542").unwrap(),
            ),
            value: U256::from(44902 as usize),
            data: hex::decode("3400711e1d0bfbcf").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: Some(U256::from(2298206284 as usize)),
            max_priority_fee_per_gas: Some(U256::from(163)),
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(42), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "02f8722a82022481a38488fbd84c81dc9487e65b8280098da8f9bb3a69643573378da8754282af66883400711e1d0bfbcfc001a03e202f7d17126f8cc3f17a3fb96508d52d7cdd93dc862481ff9b9653c71bb254a04d34bef9821db11b7f5b6d4b303b07793248fc0f34223b5884601f5511da3abc".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0x90b1a2325ee4acb953e67a9b05c5b7048dc30ac222f8736b82ea4222b5a5721e".to_string()
        );
    }

    #[test]
    fn test_sign_eip1559_trans3() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(8),
            gas_price: U256::from(0 as usize),
            gas_limit: U256::from(14298499),
            to: Action::Call(
                Address::from_str("ef970655297d1234174bcfe31ee803aaa97ad0ca").unwrap(),
            ),
            value: U256::from(11 as usize),
            data: hex::decode("ee").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: Some(U256::from(850895266216 as usize)),
            max_priority_fee_per_gas: Some(U256::from(69)),
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(130), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "02f86a8182084585c61d4f61a883da2d8394ef970655297d1234174bcfe31ee803aaa97ad0ca0b81eec001a043b16ce6f245f8ec1d145e8b1f36bb9f6e7a7fd9030139a8143c3e0e9ccb6e9ca04020e1ae4920cfbf7c88e7be6a73751bb28d9bc8e6ecf3c5c989310c5871de8a".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0xd38f47550c709e39519a3e35024a5ec135a8893890001658f2bd96e60f88fd9a".to_string()
        );
    }

    #[test]
    fn test_sign_eip1559_trans4() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(4),
            gas_price: U256::from(0 as usize),
            gas_limit: U256::from(54),
            to: Action::Call(
                Address::from_str("d5539a0e4d27ebf74515fc4acb38adcc3c513f25").unwrap(),
            ),
            value: U256::from(64 as usize),
            data: hex::decode("f579eebd8a5295c6f9c86e").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: Some(U256::from(963240322143 as usize)),
            max_priority_fee_per_gas: Some(U256::from(28710)),
            access_list: vec![AccessListItem {
                address: Address::from_str("70b361fc3a4001e4f8e4e946700272b51fe4f0c4").unwrap(),
                storage_keys: vec![
                    Transaction::hexstring_to_hex256(
                        "8419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63",
                    ),
                    Transaction::hexstring_to_hex256(
                        "8a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3",
                    ),
                    Transaction::hexstring_to_hex256(
                        "897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab9",
                    ),
                ],
            }],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(276), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "02f8f18201140482702685e04598e45f3694d5539a0e4d27ebf74515fc4acb38adcc3c513f25408bf579eebd8a5295c6f9c86ef87cf87a9470b361fc3a4001e4f8e4e946700272b51fe4f0c4f863a08419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63a08a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3a0897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab980a0bacd306ae19a67ffe6a6864b982dda2adc433cea38b13bfc21ca3155f1655bb6a039dad052cbb7c685c4048cafb16df681ce9e554c0cca173620a216935654c00b".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0xe66abf92ea7b79ec05519444d1f360a121f224e9d6981a41e2ada82f7f50afe9".to_string()
        );
    }

    #[test]
    fn test_sign_eip1559_trans5() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(6),
            gas_price: U256::from(0 as usize),
            gas_limit: U256::from(10884139),
            to: Action::Call(
                Address::from_str("d24911709fa01130804188b5c76ed65bfdfd6a05").unwrap(),
            ),
            value: U256::from(4990 as usize),
            data: hex::decode("e9290f2d3d754ba522").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: Some(U256::from(2984486799 as usize)),
            max_priority_fee_per_gas: Some(U256::from(183)),
            access_list: vec![AccessListItem {
                address: Address::from_str("55a7ce45514b6e71743bbb67e9959bd19eefb8ed").unwrap(),
                storage_keys: vec![
                    Transaction::hexstring_to_hex256(
                        "766d2c1aef5f615a3f935de247800dfbf9a8bb7be5a43795f78f9c83f24f013d",
                    ),
                    Transaction::hexstring_to_hex256(
                        "b34339a846e7a304ad82e20b3cf05260698566efc1c6488bf851689a279d262e",
                    ),
                ],
            }],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(225), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "02f8d081e10681b784b1e3a78f83a6142b94d24911709fa01130804188b5c76ed65bfdfd6a0582137e89e9290f2d3d754ba522f85bf8599455a7ce45514b6e71743bbb67e9959bd19eefb8edf842a0766d2c1aef5f615a3f935de247800dfbf9a8bb7be5a43795f78f9c83f24f013da0b34339a846e7a304ad82e20b3cf05260698566efc1c6488bf851689a279d262e80a05c809f542d668d0374e0d8d4f037f41329e223ce3dcd36aace638a5356e530e9a027c52a58a8eccbfea253475f01e5b9008af158a6558c017547cb7e28c8c785ae".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0x14f39a9febd6868e2c8caa0ac90ec4f6bdbab64e5b1e54986f9a7e7e61be1b74".to_string()
        );
    }

    #[test]
    fn test_sign_eip1559_trans6() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(3),
            gas_price: U256::from(0 as usize),
            gas_limit: U256::from(41708),
            to: Action::Call(
                Address::from_str("af9031dff5db0a02d25cd09b3cbb0d3f7f332faf").unwrap(),
            ),
            value: U256::from(44939 as usize),
            data: hex::decode("4f").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: Some(U256::from(259340687386 as usize)),
            max_priority_fee_per_gas: Some(U256::from(223)),
            access_list: vec![AccessListItem {
                address: Address::from_str("4824aec0a347a627d2bd88ae1f69a41b0665fed0").unwrap(),
                storage_keys: vec![],
            }],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(365), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "02f88382016d0381df853c61e8d81a82a2ec94af9031dff5db0a02d25cd09b3cbb0d3f7f332faf82af8b4fd7d6944824aec0a347a627d2bd88ae1f69a41b0665fed0c001a051eb287fd9a429613c49a04022607c4a8a948b0d2293bc28dc0cba5ce72c761ea00f73ffb9fdcc229c660410d581ad511a9ccf125a973e2c4c3a115ed3da0fa7b2".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0x285e791baec6449df732c39e29d7f73aebf0f20db7783ddf401fc7e451fae0a1".to_string()
        );
    }

    #[test]
    fn test_sign_eip1559_trans7() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(1),
            gas_price: U256::from(0 as usize),
            gas_limit: U256::from(4286),
            to: Action::Call(
                Address::from_str("6f4ecd70932d65ac08b56db1f4ae2da4391f328e").unwrap(),
            ),
            value: U256::from(3490361 as usize),
            data: hex::decode("200184c0486d5f082a27").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: Some(U256::from(1076634600920 as usize)),
            max_priority_fee_per_gas: Some(U256::from(226)),
            access_list: vec![
                AccessListItem {
                    address: Address::from_str("019fda53b3198867b8aae65320c9c55d74de1938").unwrap(),
                    storage_keys: vec![],
                },
                AccessListItem {
                    address: Address::from_str("1b976cdbc43cfcbeaad2623c95523981ea1e664a").unwrap(),
                    storage_keys: vec![Transaction::hexstring_to_hex256(
                        "d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2",
                    )],
                },
                AccessListItem {
                    address: Address::from_str("f1946eba70f89687d67493d8106f56c90ecba943").unwrap(),
                    storage_keys: vec![
                        Transaction::hexstring_to_hex256(
                            "b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9",
                        ),
                        Transaction::hexstring_to_hex256(
                            "6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82",
                        ),
                        Transaction::hexstring_to_hex256(
                            "0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064",
                        ),
                    ],
                },
            ],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(63), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "02f901413f0181e285faac6c45d88210be946f4ecd70932d65ac08b56db1f4ae2da4391f328e833542398a200184c0486d5f082a27f8cbd694019fda53b3198867b8aae65320c9c55d74de1938c0f7941b976cdbc43cfcbeaad2623c95523981ea1e664ae1a0d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2f87a94f1946eba70f89687d67493d8106f56c90ecba943f863a0b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9a06a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82a00c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb206480a0c5dfcb3a472086ca8c29fa31b9a86c40a6bbaeeb9db938c6729305e5f35aaeb1a04a83adc3c02b706c2c3d67de0274aa771b75c2da04c4c21ed0745637a6f937de".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0xabb4c4b2b6f406b3598b5d8c5e0e7780209a50503ca5350c87ddcb82b5f518ff".to_string()
        );
    }

    #[test]
    fn test_display() {
        bind_test();

        // eth transfer
        // payment： 0.000000000000000512 ETH
        // receiver：0x3535353535353535353535353535353535353535
        // Fee: 0.0032 ether
        let tx = Transaction {
            nonce: U256::from(8),
            gas_price: U256::from(20000000008 as usize),
            gas_limit: U256::from(189000),
            to: Action::Call(
                Address::from_str("3535353535353535353535353535353535353535").unwrap(),
            ),
            value: U256::from(512 as usize),
            data: Vec::new(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();

        // bnb transfer
        // payment： 0.8026 BNB
        // receiver：0x4ae26e87e97374f44fbf25eab31461256840520f
        // Fee: 0.002499941511088808 ether
        let tx = Transaction {
            nonce: U256::from(11),
            gas_price: U256::from(20000000008 as usize),
            gas_limit: U256::from(189000),
            to: Action::Call(
                Address::from_str("b8c77482e45f1f44de1745f52c74426c631bdd52").unwrap(),
            ),
            value: U256::from(0 as usize),
            data: hex::decode("a9059cbb0000000000000000000000004ae26e87e97374f44fbf25eab31461256840520f0000000000000000000000000000000000000000000000000b23687298ba8000").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.002499941511088808 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();

        // usdt transfer
        // payment： 217.608457 USDT
        // receiver：0xcad5475a669cdd9b27caef99efbd1b21c82c6ec3
        // Fee: 0.002654792885876068 ether
        let tx = Transaction {
            nonce: U256::from(11),
            gas_price: U256::from(20000000008 as usize),
            gas_limit: U256::from(189000),
            to: Action::Call(
                Address::from_str("dac17f958d2ee523a2206206994597c13d831ec7").unwrap(),
            ),
            value: U256::from(0 as usize),
            data: hex::decode("a9059cbb000000000000000000000000cad5475a669cdd9b27caef99efbd1b21c82c6ec3000000000000000000000000000000000000000000000000000000000cf87109").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.002654792885876068 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();

        // eip1559 eth transfer
        // payment： 0.000000000003490361 ETH
        // receiver：0x6f4ecd70932d65ac08b56db1f4ae2da4391f328e
        // Fee: 0.0033 ether
        let tx = Transaction {
            nonce: U256::from(1),
            gas_price: U256::from(0 as usize),
            gas_limit: U256::from(4286),
            to: Action::Call(
                Address::from_str("6f4ecd70932d65ac08b56db1f4ae2da4391f328e").unwrap(),
            ),
            value: U256::from(3490361 as usize),
            data: hex::decode("200184c0486d5f082a27").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: Some(U256::from(1076634600920 as usize)),
            max_priority_fee_per_gas: Some(U256::from(226)),
            access_list: vec![
                AccessListItem {
                    address: Address::from_str("019fda53b3198867b8aae65320c9c55d74de1938").unwrap(),
                    storage_keys: vec![],
                },
                AccessListItem {
                    address: Address::from_str("1b976cdbc43cfcbeaad2623c95523981ea1e664a").unwrap(),
                    storage_keys: vec![Transaction::hexstring_to_hex256(
                        "d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2",
                    )],
                },
                AccessListItem {
                    address: Address::from_str("f1946eba70f89687d67493d8106f56c90ecba943").unwrap(),
                    storage_keys: vec![
                        Transaction::hexstring_to_hex256(
                            "b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9",
                        ),
                        Transaction::hexstring_to_hex256(
                            "6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82",
                        ),
                        Transaction::hexstring_to_hex256(
                            "0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064",
                        ),
                    ],
                },
            ],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0033 ether".to_string();

        let tx_result = tx
            .sign(Some(63), &path, &payment, &receiver, &sender, &fee)
            .unwrap();

        // other
        // payment： 0.01 ETH
        // receiver：0xE6F4142dfFA574D1d9f18770BF73814df07931F3
        // Fee: 0.11 ether
        let tx = Transaction {
            nonce: U256::from(11),
            gas_price: U256::from(20000000008 as usize),
            gas_limit: U256::from(189000),
            to: Action::Call(
                Address::from_str("dac17f958d2ee523a2206206994597c13d831ec7").unwrap(),
            ),
            value: U256::from(0 as usize),
            data: hex::decode("11059cbb000000000000000000000000cad5475a669cdd9b27caef99efbd1b21c82c6ec3000000000000000000000000000000000000000000000000000000000cf87109").unwrap(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "0.01 ETH".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.11 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
    }

    #[test]
    fn test_longest_payment_info() {
        bind_test();

        let tx = Transaction {
            nonce: U256::from(8),
            gas_price: U256::from(20000000008 as usize),
            gas_limit: U256::from(189000),
            to: Action::Call(
                Address::from_str("3535353535353535353535353535353535353535").unwrap(),
            ),
            value: U256::from(512 as usize),
            data: Vec::new(),
            tx_type: String::from(constants::ETH_TRANSACTION_TYPE_LEGACY),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        };

        let path = "m/44'/60'/0'/0/0".to_string();
        let payment = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890!@&#&".to_string();
        let receiver = "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string();
        let sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string();
        let fee = "0.0032 ether".to_string();

        let tx_result = tx
            .sign(Some(28), &path, &payment, &receiver, &sender, &fee)
            .unwrap();
        assert_eq!(
            tx_result.signature,
            "f867088504a817c8088302e248943535353535353535353535353535353535353535820200805ba03aa62abb45b77418caf139dda0179aea802c99967b3d690b87d586a87bc805afa02b5ce94f40dc865ca63403e0e5e723e1523884f001573677cd8cec11c7ca332f".to_string()
        );
        assert_eq!(
            tx_result.tx_hash,
            "0x09fa41c4d6b92482506c8c56f65b217cc3398821caec7695683110997426db01".to_string()
        );
    }

    #[test]
    fn test_batch_personal_sign() {
        bind_test();

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: constants::ETH_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "".to_string(),
        };
        let mut messages = vec![];
        messages.push(hex::encode("Hello imKey".as_bytes()));
        messages.push("0x8d61d40bb0761526fe24d84199321d5e9f6542e56c52018c401b963d64ef21678c18563a3eba889229ab078a8a1baed22226913f".to_string());
        let input = EthBatchMessageInput {
            is_personal_sign: true,
            messages,
        };
        let output = Transaction::batch_message_sign(input, &sign_param).unwrap();
        assert_eq!(
            output.signatures[0],
            "d928f76ad80d63003c189b095078d94ae068dc2f18a5cafd97b3a630d7bc47465bd6f1e74de2e88c05b271e1c5a8b93564d9d8842c207482b20634d68f2d54e51b".to_string()
        );
        assert_eq!(
            output.signatures[1],
            "35a94616ce12ddb79f6d351c2644c0fa2f496bd152b17102a5672359f583373b6dd5d2a60f5d9909cf84e6af7dc40176179c819a7cbd9b199f4c2e868530293f1b".to_string()
        );
    }
}
