use crate::eosapi::{EosMessageInput, EosMessageOutput, EosSignResult, EosTxInput, EosTxOutput};
use crate::pubkey::EosPubkey;
use crate::Result;
use anyhow::anyhow;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::util::base58;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::{ripemd160, Hash};
use bytes::BufMut;
use hex::FromHex;
use ikc_common::apdu::{Apdu, ApduCheck, CoinCommonApdu, EosApdu, Secp256k1Apdu};
use ikc_common::constants::EOS_AID;
use ikc_common::error::CoinError;
use ikc_common::utility::{retrieve_recid, secp256k1_sign, sha256_hash};
use ikc_common::{constants, path, utility, SignParam};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};

#[derive(Debug)]
pub struct EosTransaction {}

impl EosTransaction {
    pub fn sign_tx(tx_input: EosTxInput, sign_param: &SignParam) -> Result<EosTxOutput> {
        path::check_path_validity(&sign_param.path)?;

        // let select_apdu = EosApdu::select_applet();
        let select_response = send_apdu("00A4040006695F656F7311".to_string())?;
        ApduCheck::check_response(&select_response)?;

        let mut trans_multi_signs: Vec<EosSignResult> = Vec::new();

        for sign_data in &tx_input.transactions {
            let mut sign_result = EosSignResult {
                hash: "".to_string(),
                signs: vec![],
            };
            //tx hash
            let tx_data_bytes = hex::decode(&sign_data.tx_hex).unwrap();
            let tx_hash = sha256_hash(&tx_data_bytes).to_hex();
            sign_result.hash = tx_hash;

            //pack tx data
            let mut tx_data_pack: Vec<u8> = Vec::new();
            tx_data_pack.put_slice(hex::decode(&sign_data.chain_id).unwrap().as_slice());
            tx_data_pack.put_slice(hex::decode(&sign_data.tx_hex).unwrap().as_slice());
            let context_free_actions = [0; 32];
            tx_data_pack.put_slice(&context_free_actions);

            //tx data hash
            let tx_data_hash = sha256_hash(&tx_data_pack);

            //sign
            for pub_key in &sign_data.public_keys {
                let select_apdu = Apdu::select_applet(EOS_AID);
                let select_result = send_apdu(select_apdu)?;
                ApduCheck::check_response(&select_result)?;

                let key_manager_obj = KEY_MANAGER.lock();
                let path_signature =
                    secp256k1_sign(&key_manager_obj.pri_key, &sign_param.path.as_bytes())?;
                let mut path_pack: Vec<u8> = vec![];
                path_pack.push(0x00);
                path_pack.push(path_signature.len() as u8);
                path_pack.extend(path_signature.as_slice());
                path_pack.push(0x01);
                path_pack.push(sign_param.path.as_bytes().len() as u8);
                path_pack.extend(sign_param.path.as_bytes());

                let msg_pubkey = Secp256k1Apdu::get_xpub(&path_pack);
                let res_msg_pubkey = send_apdu(msg_pubkey)?;
                let pubkey_raw = hex::decode(&res_msg_pubkey[..130]).unwrap();
                let comprs_pubkey = utility::uncompress_pubkey_2_compress(&res_msg_pubkey);
                let mut comprs_pubkey_slice = hex::decode(comprs_pubkey)?;
                let pubkey_hash = ripemd160::Hash::hash(&comprs_pubkey_slice);
                let check_sum = &pubkey_hash[0..4];
                comprs_pubkey_slice.extend(check_sum);
                let eos_pk = "EOS".to_owned() + base58::encode_slice(&comprs_pubkey_slice).as_ref();
                if pub_key != &eos_pk {
                    return Err(anyhow!("imkey_publickey_mismatch_with_path"));
                }

                let mut data_pack = Vec::new();

                data_pack.push(0x01);
                data_pack.push(tx_data_hash.len() as u8);
                data_pack.extend(&tx_data_hash);

                let path = sign_param.path.as_bytes();
                data_pack.push(0x02);
                data_pack.push(path.len() as u8);
                data_pack.extend(path);

                let payment = sign_data.payment.as_bytes();
                data_pack.push(0x07);
                data_pack.push(payment.len() as u8);
                data_pack.extend(payment);

                let to = sign_data.receiver.as_bytes();
                data_pack.push(0x08);
                data_pack.push(to.len() as u8);
                data_pack.extend(to);

                // let key_manager_obj = KEY_MANAGER.lock();
                let data_pack_sig = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;

                let mut data_pack_with_sig = Vec::new();
                data_pack_with_sig.push(0x00);
                data_pack_with_sig.push(data_pack_sig.len() as u8);
                data_pack_with_sig.extend(&data_pack_sig);
                data_pack_with_sig.extend(&data_pack);

                let sign_apdus = Secp256k1Apdu::prepare_eos(&data_pack_with_sig);
                for apdu in sign_apdus {
                    let sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
                    ApduCheck::check_response(&sign_response)?;
                }

                //sign
                let mut nonce = 0;
                let mut signature = "".to_string();
                loop {
                    let sign_apdu = Secp256k1Apdu::sign_eos(nonce);
                    let sign_response = send_apdu(sign_apdu)?;
                    ApduCheck::check_response(&sign_response)?;

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

                    let sign_result_vec = Vec::from_hex(&sign_result[2..130]).unwrap();
                    let mut signature_obj =
                        Signature::from_compact(sign_result_vec.as_slice()).unwrap();
                    //generator der sign data
                    signature_obj.normalize_s();
                    let signatrue_der = signature_obj.serialize_der().to_vec();
                    let normalizes_sig_vec = signature_obj.serialize_compact();
                    let sig_str = hex::encode(&normalizes_sig_vec.as_ref());

                    let len_r = signatrue_der[3];
                    let len_s = signatrue_der[5 + len_r as usize];
                    if len_r == 32 && len_s == 32 {
                        //calc v
                        let sign_compact = hex::decode(&sign_response[2..130]).unwrap();
                        let rec_id = retrieve_recid(&tx_data_hash, &sign_compact, &pubkey_raw)?;
                        let rec_id = rec_id.to_i32();
                        let v = rec_id + 27 + 4;

                        signature.push_str(&format!("{:02X}", &v));
                        signature.push_str(&sig_str);
                        break;
                    }
                    nonce = nonce + 1;
                }

                //checksum base58
                let mut to_hash = hex::decode(&signature).unwrap();
                to_hash.put_slice("K1".as_bytes());
                let signature_hash = ripemd160::Hash::hash(&to_hash);
                let check_sum = &signature_hash[0..4];

                let mut signature_slice = hex::decode(&signature).unwrap();
                signature_slice.extend(check_sum);
                let sigature_base58 =
                    "SIG_K1_".to_owned() + base58::encode_slice(&signature_slice).as_ref();
                sign_result.signs.push(sigature_base58);

                trans_multi_signs.push(sign_result.clone());
            }
        }

        let tx_output = EosTxOutput { trans_multi_signs };
        Ok(tx_output)
    }

    pub fn sign_message(
        input: EosMessageInput,
        sign_param: &SignParam,
    ) -> Result<EosMessageOutput> {
        let tx_data_hash = if input.is_hex {
            hex::decode(input.data).unwrap()
        } else {
            sha256_hash(input.data.as_bytes())
        };

        let mut data_pack = Vec::new();

        data_pack.push(0x01);
        data_pack.push(tx_data_hash.len() as u8);
        data_pack.extend(&tx_data_hash);

        let path = sign_param.path.as_bytes();
        data_pack.push(0x02);
        data_pack.push(path.len() as u8);
        data_pack.extend(path);

        let key_manager_obj = KEY_MANAGER.lock();
        let msg_sig = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;
        let mut data_pack_with_sig = Vec::new();
        data_pack_with_sig.push(0x00);
        data_pack_with_sig.push(msg_sig.len() as u8);
        data_pack_with_sig.extend(msg_sig);
        data_pack_with_sig.extend(&data_pack);

        let select_apdu = Apdu::select_applet(EOS_AID);
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let path_signature = secp256k1_sign(&key_manager_obj.pri_key, &sign_param.path.as_bytes())?;
        let mut path_pack: Vec<u8> = vec![];
        path_pack.push(0x00);
        path_pack.push(path_signature.len() as u8);
        path_pack.extend(path_signature.as_slice());
        path_pack.push(0x01);
        path_pack.push(sign_param.path.as_bytes().len() as u8);
        path_pack.extend(sign_param.path.as_bytes());

        let msg_pubkey = Secp256k1Apdu::get_xpub(&path_pack);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        let pubkey_raw = hex::decode(&res_msg_pubkey[..130]).unwrap();
        let comprs_pubkey = utility::uncompress_pubkey_2_compress(&res_msg_pubkey);
        let mut comprs_pubkey_slice = hex::decode(comprs_pubkey)?;
        let pubkey_hash = ripemd160::Hash::hash(&comprs_pubkey_slice);
        let check_sum = &pubkey_hash[0..4];
        comprs_pubkey_slice.extend(check_sum);
        let eos_pk = "EOS".to_owned() + base58::encode_slice(&comprs_pubkey_slice).as_ref();
        if &input.pubkey != &eos_pk {
            return Err(anyhow!("imkey_publickey_mismatch_with_path"));
        }

        let mut data_pack = Vec::new();

        data_pack.push(0x01);
        data_pack.push(tx_data_hash.len() as u8);
        data_pack.extend(&tx_data_hash);

        let path = sign_param.path.as_bytes();
        data_pack.push(0x02);
        data_pack.push(path.len() as u8);
        data_pack.extend(path);

        // let key_manager_obj = KEY_MANAGER.lock();
        let data_pack_sig = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;

        let mut data_pack_with_sig = Vec::new();
        data_pack_with_sig.push(0x00);
        data_pack_with_sig.push(data_pack_sig.len() as u8);
        data_pack_with_sig.extend(&data_pack_sig);
        data_pack_with_sig.extend(&data_pack);

        let sign_apdus = Secp256k1Apdu::prepare_eos(&data_pack_with_sig);
        for apdu in sign_apdus {
            let sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }

        //sign
        let mut nonce = 0;
        let mut signature = "".to_string();
        loop {
            let sign_apdu = Secp256k1Apdu::sign_eos(nonce);
            let sign_response = send_apdu(sign_apdu)?;
            ApduCheck::check_response(&sign_response)?;

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

            let sign_result_vec = Vec::from_hex(&sign_source_val[2..130]).unwrap();
            let mut signature_obj = Signature::from_compact(sign_result_vec.as_slice()).unwrap();
            //generator der sign data
            signature_obj.normalize_s();
            let signatrue_der = signature_obj.serialize_der().to_vec();
            let normalizes_sig_vec = signature_obj.serialize_compact();
            let sig_str = hex::encode(&normalizes_sig_vec.as_ref());

            let len_r = signatrue_der[3];
            let len_s = signatrue_der[5 + len_r as usize];
            if len_r == 32 && len_s == 32 {
                //calc v
                let sign_compact = hex::decode(&sign_response[2..130]).unwrap();
                let rec_id = retrieve_recid(&tx_data_hash, &sign_compact, &pubkey_raw)?;
                let rec_id = rec_id.to_i32();
                let v = rec_id + 27 + 4;

                signature.push_str(&format!("{:02X}", &v));
                signature.push_str(&sig_str);
                break;
            }
            nonce = nonce + 1;
        }

        //checksum base58
        println!("signature: {}", signature);
        let mut to_hash = hex::decode(&signature).unwrap();
        to_hash.put_slice("K1".as_bytes());
        let signature_hash = ripemd160::Hash::hash(&to_hash);
        let check_sum = &signature_hash[0..4];

        let mut signature_slice = hex::decode(&signature).unwrap();
        signature_slice.extend(check_sum);
        let signature = "SIG_K1_".to_owned() + base58::encode_slice(&signature_slice).as_ref();

        let output = EosMessageOutput { signature };
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::eosapi::{EosMessageInput, EosSignData, EosTxInput};
    use crate::transaction::EosTransaction;
    use ikc_common::{constants, SignParam};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_sgin_tx() {
        bind_test();

        let eos_sign_data = EosSignData{
            tx_hex: "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string(),
            chain_id: "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906".to_string(),
            receiver: "bbbb5555bbbb".to_string(),
            sender: "liujianmin12".to_string(),
            payment: "undelegatebw 0.0100 EOS".to_string(),
            public_keys: vec!["EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string()]
        };
        let eox_tx_input = EosTxInput {
            transactions: vec![eos_sign_data],
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let result = EosTransaction::sign_tx(eox_tx_input, &sign_param).unwrap();
        assert_eq!(
            result.trans_multi_signs[0].hash,
            "6af5b3ae9871c25e2de195168ed7423f455a68330955701e327f02276bb34088"
        );
    }

    #[test]
    fn test_sgin_tx_pubkey_error() {
        bind_test();

        let eos_sign_data = EosSignData{
            tx_hex: "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string(),
            chain_id: "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906".to_string(),
            payment: "undelegatebw 0.0100 EOS".to_string(),
            public_keys: vec!["ERROR PUBKEY".to_string()],
            receiver: "bbbb5555bbbb".to_string(),
            sender: "liujianmin12".to_string()
        };
        let eox_tx_input = EosTxInput {
            transactions: vec![eos_sign_data],
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let result = EosTransaction::sign_tx(eox_tx_input, &sign_param);
        assert_eq!(
            format!("{}", result.err().unwrap()),
            "imkey_publickey_mismatch_with_path"
        );
    }

    #[test]
    fn test_sgin_tx_chainid_is_null() {
        bind_test();

        let eos_sign_data = EosSignData{
            tx_hex: "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string(),
            chain_id: "".to_string(),
            payment: "undelegatebw 0.0100 EOS".to_string(),
            public_keys: vec!["EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string()],
            receiver: "bbbb5555bbbb".to_string(),
            sender: "liujianmin12".to_string()
        };
        let eox_tx_input = EosTxInput {
            transactions: vec![eos_sign_data],
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let result = EosTransaction::sign_tx(eox_tx_input, &sign_param).unwrap();
        assert_eq!(
            result.trans_multi_signs[0].hash,
            "6af5b3ae9871c25e2de195168ed7423f455a68330955701e327f02276bb34088"
        );
    }

    #[test]
    fn test_sign_messgage() {
        bind_test();

        let input = EosMessageInput {
            data: "imKey2019".to_string(),
            is_hex: false,
            pubkey: "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            output.unwrap().signature,
            "SIG_K1_K2mrf6ASTK5TCJC6kzZzyQm9uRZm7Jx4fa6gsmWx2sEreokRWmnHQGTRNwKLNF6NVJtXmjmUvR96XYct1DjMJnwRZBbTYR"
        );
    }

    #[test]
    fn test_sign_messgage_hex() {
        bind_test();

        let input = EosMessageInput {
            data: "1122334455667788990011223344556677889900112233445566778899001122".to_string(),
            is_hex: true,
            pubkey: "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            output.unwrap().signature,
            "SIG_K1_Jy1w6cs58tXkFVVBoku9uAVUuiknttFtwQEjXzpZvXY85EsBi6dU27RPf8KQRRh25jewnpdeVgqZDrj6RiYkdJk5fktZyw"
        );
    }

    #[test]
    fn sign_messgage_wrong_pubkey_test() {
        bind_test();

        let input = EosMessageInput {
            data: "imKey2019".to_string(),
            is_hex: false,
            pubkey: "wrong pubkey".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            format!("{}", output.err().unwrap()),
            "imkey_publickey_mismatch_with_path"
        );
    }

    #[test]
    fn sign_messgage_data_is_null_test() {
        bind_test();

        let input = EosMessageInput {
            data: "".to_string(),
            is_hex: false,
            pubkey: "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            output.unwrap().signature,
            "SIG_K1_Kij4tk3eM3UtB5Z1Gz6B5jC9JAtPDj7PQA8kkNPAX97U7JQWePVNCUg4WGso6m91Bz8rWzFoXo3SNhehpYrmJfYtNc4dxJ"
        );
    }

    #[test]
    fn sign_messgage_wrong_path_test() {
        bind_test();

        let input = EosMessageInput {
            data: "imKey2019".to_string(),
            is_hex: false,
            pubkey: "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: "m/44'".to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            format!("{}", output.err().unwrap()),
            "imkey_publickey_mismatch_with_path"
        );
    }
}
