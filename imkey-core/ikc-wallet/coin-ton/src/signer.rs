use crate::tonapi::{TonRawTxIn, TonTxOut};
use crate::Result;
use anyhow::anyhow;
use ikc_common::apdu::{Apdu, ApduCheck, Ed25519Apdu};
use ikc_common::constants::TON_AID;
use ikc_common::error::CoinError;
use ikc_common::hex::FromHex;
use ikc_common::path::check_path_validity;
use ikc_common::utility::secp256k1_sign;
use ikc_common::{constants, utility, SignParam};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};

#[derive(Debug)]
pub struct Transaction {}

impl Transaction {
    pub fn sign_transaction(tx: &TonRawTxIn, sign_param: &SignParam) -> Result<TonTxOut> {
        check_path_validity(&sign_param.path).expect("check path error");

        let path_parts = sign_param.path.split('/').collect::<Vec<_>>();
        if path_parts[2] != "607'" {
            return Err(anyhow!("invalid_sign_path"));
        }

        let select_apdu = Apdu::select_applet(TON_AID);
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let hash = Vec::from_hex_auto(&tx.hash)?;

        //organize data
        let mut data_pack: Vec<u8> = Vec::new();

        data_pack.extend([1, hash.len() as u8].iter());
        data_pack.extend(hash.iter());

        //path
        data_pack.extend([2, sign_param.path.as_bytes().len() as u8].iter());
        data_pack.extend(sign_param.path.as_bytes().iter());
        //payment info in TLV format
        data_pack.extend([7, sign_param.payment.as_bytes().len() as u8].iter());
        data_pack.extend(sign_param.payment.as_bytes().iter());
        //receiver info in TLV format
        data_pack.extend([8, sign_param.receiver.as_bytes().len() as u8].iter());
        data_pack.extend(sign_param.receiver.as_bytes().iter());
        //fee info in TLV format
        data_pack.extend([9, sign_param.fee.as_bytes().len() as u8].iter());
        data_pack.extend(sign_param.fee.as_bytes().iter());

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &data_pack).unwrap();

        let mut apdu_pack: Vec<u8> = Vec::new();
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.extend(data_pack.as_slice());

        //sign
        let mut sign_response = "".to_string();
        let sign_apdus = Ed25519Apdu::sign(&apdu_pack);
        for apdu in sign_apdus {
            sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }

        // verify
        let sign_source_val = &sign_response[..130];
        let sign_result = &sign_response[130..sign_response.len() - 4];
        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;

        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let signature = format!("0x{}", sign_response[2..130].to_lowercase());
        Ok(TonTxOut { signature })
    }
}

#[cfg(test)]
mod test {
    use crate::signer::Transaction;
    use crate::tonapi::TonRawTxIn;
    use ikc_common::constants::TON_PATH;
    use ikc_common::SignParam;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_sign_transaction() {
        bind_test();
        let sign_param = SignParam {
            chain_type: "TON".to_string(),
            path: TON_PATH.to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.01 TON".to_string(),
            receiver: "UQCpecuOS5riOEjasciyaOkKUdjjvIjsPjhxWsk4z9oy6rV8".to_string(),
            sender: "UQDBKGsYs49NgdqM4gMoiVMV9Re5hM-yy3nvR_4XB0ZbUMd7".to_string(),
            fee: "0.007 TON".to_string(),
            seg_wit: "".to_string(),
        };

        let input = TonRawTxIn {
            hash: "0xd356774c21d6a6e2c651a5255f3f876fa973f1cfb7dce941c14ecabc2b1511d0".to_string(),
        };
        let ret =
            Transaction::sign_transaction(&input, &sign_param).expect("sign transaction error");

        assert_eq!("0x9771c1bf4c69630b69cc0f0ae38db635f4ff1d161badc0f70b257b5a8f6a387cd75b72361ebf67fc5803feccdbb22ade85d053d766ed3b7c7029509363990c02", ret.signature);
    }
}
