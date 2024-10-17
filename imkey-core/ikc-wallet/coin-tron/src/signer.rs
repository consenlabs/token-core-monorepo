use crate::address::TronAddress;
use crate::tronapi::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};
use crate::Result;
use ikc_common::apdu::{Apdu, ApduCheck, Secp256k1Apdu};
use ikc_common::constants::TRON_AID;
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{secp256k1_sign, sha256_hash};
use ikc_common::{constants, utility, SignParam};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::{self, ecdsa::Signature as SecpSignature};
use tiny_keccak::Hasher;

#[derive(Debug)]
pub struct TronSigner {}

impl TronSigner {
    pub fn sign_message(
        input: TronMessageInput,
        sign_param: &SignParam,
    ) -> Result<TronMessageOutput> {
        check_path_validity(&sign_param.path).unwrap();

        let message = match input.is_hex {
            true => {
                let mut raw_hex: String = input.message.to_owned();
                if raw_hex.to_uppercase().starts_with("0X") {
                    raw_hex.replace_range(..2, "")
                }
                hex::decode(&raw_hex)?
            }
            false => input.message.into_bytes(),
        };

        // this code is from tron wallet
        let header = match input.is_tron_header {
            true => match input.version.to_uppercase().as_str() {
                "V2" => "\x19TRON Signed Message:\n".as_bytes(),
                _ => "\x19TRON Signed Message:\n32".as_bytes(),
            },
            false => "\x19Ethereum Signed Message:\n32".as_bytes(),
        };
        let mut msg_with_header = Vec::new();
        msg_with_header.extend(header);
        msg_with_header.extend(&message);

        let mut data_pack = Vec::new();

        let mut keccak256 = tiny_keccak::Keccak::v256();
        keccak256.update(msg_with_header.as_slice());
        let mut hash = [0u8; 256 / 8];
        keccak256.finalize(&mut hash);

        data_pack.push(0x01);
        data_pack.push(hash.len() as u8);
        data_pack.extend(&hash);

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

        drop(key_manager_obj);
        let signature = TronSigner::sign(
            &sign_param.path,
            &data_pack_with_sig,
            &hash,
            &sign_param.sender,
        )?;
        Ok(TronMessageOutput { signature })
    }

    pub fn sign_transaction(input: TronTxInput, sign_param: &SignParam) -> Result<TronTxOutput> {
        check_path_validity(&sign_param.path).unwrap();

        let mut data_pack = Vec::new();

        let raw_data = hex::decode(input.raw_data)?;
        let hash = sha256_hash(&raw_data);
        data_pack.push(0x01);
        data_pack.push(hash.len() as u8);
        data_pack.extend(&hash);

        let path = sign_param.path.as_bytes();
        data_pack.push(0x02);
        data_pack.push(path.len() as u8);
        data_pack.extend(path);

        let payment = sign_param.payment.as_bytes();
        data_pack.push(0x07);
        data_pack.push(payment.len() as u8);
        data_pack.extend(payment);

        let to = sign_param.receiver.as_bytes();
        data_pack.push(0x08);
        data_pack.push(to.len() as u8);
        data_pack.extend(to);

        let key_manager_obj = KEY_MANAGER.lock();
        let data_pack_sig = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;
        drop(key_manager_obj);

        let mut data_pack_with_sig = Vec::new();
        data_pack_with_sig.push(0x00);
        data_pack_with_sig.push(data_pack_sig.len() as u8);
        data_pack_with_sig.extend(&data_pack_sig);
        data_pack_with_sig.extend(&data_pack);

        let signature = TronSigner::sign(
            &sign_param.path,
            &data_pack_with_sig,
            &hash,
            &sign_param.sender,
        )?;
        Ok(TronTxOutput { signature })
    }

    pub fn sign(path: &str, data_pack: &[u8], hash: &[u8], sender: &str) -> Result<String> {
        let select_apdu = Apdu::select_applet(TRON_AID);
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let key_manager_obj = KEY_MANAGER.lock();
        let path_signature = secp256k1_sign(&key_manager_obj.pri_key, &path.as_bytes())?;
        let mut path_pack: Vec<u8> = vec![];
        path_pack.push(0x00);
        path_pack.push(path_signature.len() as u8);
        path_pack.extend(path_signature.as_slice());
        path_pack.push(0x01);
        path_pack.push(path.as_bytes().len() as u8);
        path_pack.extend(path.as_bytes());

        let msg_pubkey = Secp256k1Apdu::get_xpub(&path_pack);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        let pubkey_raw = hex::decode(&res_msg_pubkey[..130]).unwrap();
        let address = TronAddress::from_pub_key(pubkey_raw.as_slice()).unwrap();
        if !sender.to_string().is_empty() && &address != sender {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }

        let mut sign_response = "".to_string();
        let sign_apdus = Secp256k1Apdu::sign(data_pack);
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
        let mut signnture_obj = SecpSignature::from_compact(sign_compact.as_slice()).unwrap();
        signnture_obj.normalize_s();
        let normalizes_sig_vec = signnture_obj.serialize_compact();

        let rec_id = utility::retrieve_recid(&hash, &normalizes_sig_vec, &pubkey_raw).unwrap();
        let rec_id = rec_id.to_i32();
        let v = rec_id + 27;

        let mut signature = hex::encode(&normalizes_sig_vec.as_ref());
        signature.push_str(&format!("{:02x}", &v));

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::signer::TronSigner;
    use crate::tronapi::{TronMessageInput, TronTxInput};
    use ikc_common::{constants, SignParam};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn sign_message() {
        bind_test();

        let sign_param = SignParam {
            chain_type: "TRON".to_string(),
            path: constants::TRON_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2".to_string(),
            fee: "".to_string(),
        };

        let input = TronMessageInput {
            message: "645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76".to_string(),
            is_hex: true,
            is_tron_header: true,
        };
        let res = TronSigner::sign_message(input, &sign_param).unwrap();
        assert_eq!("16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b", &res.signature);

        let input2 = TronMessageInput {
            message: "645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76".to_string(),
            is_hex: true,
            is_tron_header: false,
        };
        let res = TronSigner::sign_message(input2, &sign_param).unwrap();
        assert_eq!("06ff3c5f98b8e8e257f47a66ce8e953c7a7d0f96eb6687da6a98b66a36c2a725759cab3df94d014bd17760328adf860649303c68c4fa6644d9f307e2f32cc3311c", &res.signature);

        let input3 = TronMessageInput {
            message: "abcdef".to_string(),
            is_hex: false,
            is_tron_header: true,
        };
        let res = TronSigner::sign_message(input3, &sign_param).unwrap();
        assert_eq!("a87eb6ae7e97621b6ba2e2f70db31fe0c744c6adcfdc005044026506b70ac11a33f415f4478b6cf84af32b3b5d70a13a77e53287613449b345bb16fe012c04081b", &res.signature);
    }

    #[test]
    fn sign_transaction() {
        bind_test();
        let sign_param = SignParam {
            chain_type: "TRON".to_string(),
            path: constants::TRON_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "100 TRX".to_string(),
            receiver: "TDQqJsFsStSy5fjG52KuiWW7HhJGAKGJLb".to_string(),
            sender: "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2".to_string(),
            fee: "20 dd".to_string(),
        };
        let input = TronTxInput{
            raw_data: "0a0208312208b02efdc02638b61e40f083c3a7c92d5a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541a1e81654258bf14f63feb2e8d1380075d45b0dac1215410b3e84ec677b3e63c99affcadb91a6b4e086798f186470a0bfbfa7c92d".to_string(),
        };

        let res = TronSigner::sign_transaction(input, &sign_param).unwrap();
        assert_eq!("c65b4bde808f7fcfab7b0ef9c1e3946c83311f8ac0a5e95be2d8b6d2400cfe8b5e24dc8f0883132513e422f2aaad8a4ecc14438eae84b2683eefa626e3adffc61c", &res.signature);
    }
}
