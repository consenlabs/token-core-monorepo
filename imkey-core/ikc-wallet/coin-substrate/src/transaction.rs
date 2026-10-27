use crate::substrateapi::{SubstrateRawTxIn, SubstrateTxOut};
use crate::{Result, PAYLOAD_HASH_THRESHOLD, SIGNATURE_TYPE_ED25519};
use anyhow::anyhow;
use ikc_common::apdu::{Apdu, ApduCheck, Ed25519Apdu};
use ikc_common::constants::{KUSAMA_AID, POLKADOT_AID};
use ikc_common::error::CoinError;
use ikc_common::utility::secp256k1_sign;
use ikc_common::{constants, utility, SignParam};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use sp_core::blake2_256;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct Transaction {}

impl Transaction {
    // Ref: https://github.com/paritytech/txwrapper-core/blob/8c7c9e16ab877f0247e547ee6368e22e5579b492/packages/txwrapper-core/src/core/construct/createSigningPayload.ts#L37-L42
    pub fn hash_unsigned_payload(payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > PAYLOAD_HASH_THRESHOLD {
            Ok(blake2_256(payload).to_vec())
        } else {
            Ok(payload.to_vec())
        }
    }

    pub fn sign_transaction(
        tx: &SubstrateRawTxIn,
        sign_param: &SignParam,
    ) -> Result<SubstrateTxOut> {
        let (aid, data_pack) = prepare_signing_data(tx, sign_param)?;
        let select_apdu = Apdu::select_applet(aid);
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;

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
        let payload_end = sign_response
            .len()
            .checked_sub(4)
            .ok_or_else(|| anyhow!("invalid_param"))?;
        let sign_source_val = sign_response
            .get(..130)
            .ok_or_else(|| anyhow!("invalid_param"))?;
        let sign_result = sign_response
            .get(130..payload_end)
            .ok_or_else(|| anyhow!("invalid_param"))?;
        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result)?.as_slice(),
            hex::decode(sign_source_val)?.as_slice(),
        )?;

        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let sig = hex::decode(
            sign_response
                .get(2..130)
                .ok_or_else(|| anyhow!("invalid_param"))?,
        )?;
        let sig_with_type = [vec![SIGNATURE_TYPE_ED25519], sig.to_vec()].concat();

        let tx_out = SubstrateTxOut {
            signature: format!("0x{}", hex::encode(&sig_with_type)),
        };
        Ok(tx_out)
    }
}

fn validate_signing_path(path: &str, coin_type: u32) -> Result<()> {
    let invalid = || anyhow!("imkey_path_illegal");
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() != 6 || parts[0] != "m" {
        return Err(invalid());
    }
    let indices: Vec<u32> = parts[1..]
        .iter()
        .map(|part| {
            let digits = part
                .strip_suffix('\'')
                .or_else(|| part.strip_suffix('h'))
                .ok_or_else(invalid)?;
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            let index = digits.parse::<u32>().map_err(|_| invalid())?;
            if index >= (1 << 31) {
                return Err(invalid());
            }
            Ok(index)
        })
        .collect::<Result<_>>()?;
    if indices[0] != 44 || indices[1] != coin_type || indices[3] > 1 {
        return Err(invalid());
    }
    Ok(())
}

fn prepare_signing_data(
    tx: &SubstrateRawTxIn,
    param: &SignParam,
) -> Result<(&'static str, Vec<u8>)> {
    let (aid, coin_type) = match param.chain_type.to_ascii_uppercase().as_str() {
        "POLKADOT" => (POLKADOT_AID, 354),
        "KUSAMA" => (KUSAMA_AID, 434),
        _ => return Err(anyhow!("unsupported_chain_type")),
    };
    validate_signing_path(&param.path, coin_type)?;
    let raw_data = tx.raw_data.strip_prefix("0x").unwrap_or(&tx.raw_data);
    let raw_data = hex::decode(raw_data)?;
    if raw_data.is_empty() {
        return Err(anyhow!("imkey_illegal_param"));
    }
    let hash = Transaction::hash_unsigned_payload(&raw_data)?;
    let payment = "Opaque signing";
    let receiver = format!("hash:{}", hex::encode(blake2_256(&raw_data)));
    let fee = "Unverified";
    for value in [&param.path, &param.payment, &param.receiver, &param.fee] {
        u8::try_from(value.len()).map_err(|_| anyhow!("imkey_illegal_param"))?;
    }
    if (!param.payment.is_empty() && param.payment != payment)
        || (!param.receiver.is_empty() && param.receiver != receiver)
        || (!param.fee.is_empty() && param.fee != fee)
    {
        return Err(anyhow!("imkey_transaction_display_mismatch"));
    }
    let mut data = Vec::new();
    for (tag, value) in [
        (1, hash.as_slice()),
        (2, param.path.as_bytes()),
        (7, payment.as_bytes()),
        (8, receiver.as_bytes()),
        (9, fee.as_bytes()),
    ] {
        let length = u8::try_from(value.len()).map_err(|_| anyhow!("imkey_illegal_param"))?;
        data.extend_from_slice(&[tag, length]);
        data.extend_from_slice(value);
    }
    Ok((aid, data))
}

#[cfg(test)]
mod test {
    use crate::address::{AddressType, SubstrateAddress};
    use crate::substrateapi::SubstrateRawTxIn;
    use crate::transaction::Transaction;
    use ikc_common::constants::{KUSAMA_PATH, POLKADOT_PATH};
    use ikc_common::SignParam;
    use ikc_device::device_binding::bind_test;
    use sp_core::ed25519::Pair;
    use sp_core::{ByteArray, Pair as TraitPair};

    #[test]
    fn test_sign_transaction() {
        bind_test();
        let sign_param = SignParam {
            chain_type: "POLKADOT".to_string(),
            path: POLKADOT_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "25 DOT".to_string(),
            receiver: "12pWV6LvG4iAfNpFNTvvkWy3H9H8wtCkjiXupAzo2BCmPViM".to_string(),
            sender: "147mvrDYhFpZzvFASKBDNVcxoyz8XCVNyyFKSZcpbQxN33TT".to_string(),
            fee: "15.4000 milli DOT".to_string(),
            seg_wit: String::new(),
        };

        let input = SubstrateRawTxIn{
            raw_data: "0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7".to_string()
        };
        let ret =
            Transaction::sign_transaction(&input, &sign_param).expect("sign transaction error");

        let public_key = SubstrateAddress::get_public_key(POLKADOT_PATH, &AddressType::Polkadot)
            .expect("get pub key error");
        let msg = hex::decode(input.raw_data).unwrap();
        let pk = sp_core::ed25519::Public::from_slice(&hex::decode(public_key).unwrap()).unwrap();

        let sig =
            sp_core::ed25519::Signature::from_slice(&hex::decode(&ret.signature[4..]).unwrap())
                .unwrap();
        assert!(
            sp_core::ed25519::Pair::verify(&sig, msg.as_slice(), &pk),
            "assert sig"
        );
    }

    #[test]
    fn test_sign_kusama() {
        bind_test();
        let sign_param = SignParam {
            chain_type: "KUSAMA".to_string(),
            path: KUSAMA_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "25 DOT".to_string(),
            receiver: "12pWV6LvG4iAfNpFNTvvkWy3H9H8wtCkjiXupAzo2BCmPViM".to_string(),
            sender: "147mvrDYhFpZzvFASKBDNVcxoyz8XCVNyyFKSZcpbQxN33TT".to_string(),
            fee: "15.4000 milli DOT".to_string(),
            seg_wit: String::new(),
        };

        let input = SubstrateRawTxIn{
            raw_data: "0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7".to_string()
        };
        let ret =
            Transaction::sign_transaction(&input, &sign_param).expect("sign transaction error");

        let public_key = SubstrateAddress::get_public_key(KUSAMA_PATH, &AddressType::Kusama)
            .expect("get pub key error");
        let msg = hex::decode(input.raw_data).unwrap();
        let pk = sp_core::ed25519::Public::from_slice(&hex::decode(public_key).unwrap()).unwrap();
        let sig =
            sp_core::ed25519::Signature::from_slice(&hex::decode(&ret.signature[4..]).unwrap())
                .unwrap();
        assert!(Pair::verify(&sig, msg.as_slice(), &pk), "assert sig");
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    fn param(path: &str) -> SignParam {
        SignParam {
            chain_type: "POLKADOT".into(),
            path: path.into(),
            ..Default::default()
        }
    }
    #[test]
    fn invalid_or_cross_chain_paths_are_rejected_before_device_access() {
        let tx = SubstrateRawTxIn {
            raw_data: "00".into(),
        };
        for path in [
            "",
            "m",
            "44'/354'/0'/0'/0'",
            "m/44'/434'/0'/0'/0'",
            "m/44'/354'/0'",
            "m/44'/354'/0'/0/0",
            "m/44'/354'/0'/0'/2147483648'",
        ] {
            assert_eq!(
                Transaction::sign_transaction(&tx, &param(path))
                    .unwrap_err()
                    .to_string(),
                "imkey_path_illegal"
            );
        }
        validate_signing_path("m/44'/354'/0'/0'/0'", 354).unwrap();
        validate_signing_path("m/44h/434h/0h/0h/0h", 434).unwrap();
    }
    #[test]
    fn rejects_forged_display_and_tlv_overflow_before_device_access() {
        let mut param = param("m/44'/354'/0'/0'/0'");
        let tx = SubstrateRawTxIn {
            raw_data: "00".into(),
        };
        assert!(prepare_signing_data(&tx, &param)
            .unwrap()
            .1
            .windows(14)
            .any(|x| x == b"Opaque signing"));
        param.payment = "25 DOT".into();
        assert_eq!(
            Transaction::sign_transaction(&tx, &param)
                .unwrap_err()
                .to_string(),
            "imkey_transaction_display_mismatch"
        );
        param.payment.clear();
        let tx = SubstrateRawTxIn {
            raw_data: "00".repeat(256),
        };
        assert_eq!(
            Transaction::sign_transaction(&tx, &param)
                .unwrap_err()
                .to_string(),
            "imkey_illegal_param"
        );
        assert!(prepare_signing_data(
            &SubstrateRawTxIn {
                raw_data: "00".repeat(257)
            },
            &param
        )
        .is_ok());
    }
}
