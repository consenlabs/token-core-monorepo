use crate::address::CosmosAddress;
use crate::cosmosapi::CosmosTxOutput;
use crate::display;
use crate::Result;
use anyhow::anyhow;
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, CosmosApdu};
use ikc_common::constants;
use ikc_common::path::validate_bip44_signing_path;
use ikc_common::utility::{hex_to_bytes, secp256k1_sign, sha256_hash};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::{self, ecdsa::Signature as SecpSignature};
use std::convert::TryFrom;

#[derive(Debug)]
pub struct CosmosTransaction {
    pub sign_data: String,
    pub path: String,
    pub payment_dis: String,
    pub to_dis: String,
    pub fee_dis: String,
}

impl CosmosTransaction {
    pub fn sign(self) -> Result<CosmosTxOutput> {
        validate_bip44_signing_path(&self.path, &[118], &[44])?;
        let sign_data = hex_to_bytes(&self.sign_data)?;
        let display = display::derive(&sign_data)?;
        display::validate_assertions(&display, &self.payment_dis, &self.to_dis, &self.fee_dis)?;
        let sign_hash = sha256_hash(&sign_data);
        let sign_pack_vec = signing_pack(&sign_hash, &display)?;
        let public_key = CosmosAddress::get_pub_key(&self.path)?;
        let public_key = verify_sender(&display, &public_key)?;

        let key_manager_obj = KEY_MANAGER.lock();
        let mut prepare_data = secp256k1_sign(&key_manager_obj.pri_key, sign_pack_vec.as_slice())?;
        std::mem::drop(key_manager_obj);
        prepare_data.insert(0, prepare_data.len() as u8);
        prepare_data.insert(0, 0x00);
        prepare_data.extend(sign_pack_vec.iter());

        let select_apdu = CosmosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let prepare_apdus = CosmosApdu::prepare_sign(prepare_data);

        for apdu in prepare_apdus {
            let response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&response)?;
        }

        let sign_apdu = CosmosApdu::sign_digest(&self.path);

        let sign_result = send_apdu(sign_apdu)?;
        ApduCheck::check_response(&sign_result)?;

        let mut signature_obj = parse_signature(&sign_result)?;
        let digest = <[u8; 32]>::try_from(sign_hash.as_slice())
            .map_err(|_| anyhow!("imkey_illegal_param"))?;
        signature_obj.normalize_s();
        secp256k1::Secp256k1::verification_only().verify_ecdsa(
            &secp256k1::Message::from_slice(&digest)?,
            &signature_obj,
            &public_key,
        )?;
        let normalizes_sig_vec = signature_obj.serialize_compact();
        let signature = base64::encode(&normalizes_sig_vec);

        let output = CosmosTxOutput { signature };
        Ok(output)
    }
}

fn signing_pack(hash: &[u8], display: &display::Display) -> Result<Vec<u8>> {
    let mut pack = vec![1, 32];
    pack.extend_from_slice(hash);
    for (tag, value) in [
        (7, &display.payment),
        (8, &display.receiver),
        (9, &display.fee),
    ] {
        let len = u8::try_from(value.len()).map_err(|_| anyhow!("imkey_illegal_param"))?;
        pack.extend_from_slice(&[tag, len]);
        pack.extend_from_slice(value.as_bytes());
    }
    Ok(pack)
}

fn address_from_pubkey(prefix: &str, public_key: &secp256k1::PublicKey) -> Result<String> {
    use bech32::ToBase32;
    use bitcoin_hashes::{hash160, Hash};
    let hash = hash160::Hash::hash(&public_key.serialize());
    Ok(bech32::encode(
        prefix,
        hash.as_ref().to_base32(),
        bech32::Variant::Bech32,
    )?)
}

fn verify_sender(display: &display::Display, public_key: &str) -> Result<secp256k1::PublicKey> {
    let sender = display.sender.as_str();
    let public_key = public_key
        .get(..130)
        .ok_or_else(|| anyhow!("imkey_apdu_wrong_length"))?;
    let public_key = secp256k1::PublicKey::from_slice(&hex::decode(public_key)?)?;
    if display
        .declared_public_key
        .as_deref()
        .is_some_and(|declared| declared != public_key.serialize())
    {
        return Err(anyhow!("imkey_address_mismatch_with_path"));
    }
    let (prefix, _, _) = bech32::decode(sender)?;
    let derived = address_from_pubkey(&prefix, &public_key)?;
    if derived != sender {
        return Err(anyhow!("imkey_address_mismatch_with_path"));
    }
    Ok(public_key)
}

fn parse_signature(response: &str) -> Result<SecpSignature> {
    ApduCheck::check_response(response)?;
    let body_end = response
        .len()
        .checked_sub(4)
        .ok_or_else(|| anyhow!("imkey_apdu_wrong_length"))?;
    let compact = response
        .get(..body_end)
        .and_then(|body| body.get(2..130))
        .ok_or_else(|| anyhow!("imkey_apdu_wrong_length"))?;
    Ok(SecpSignature::from_compact(&hex::decode(compact)?)?)
}

#[cfg(test)]
mod tests {
    use crate::transaction::CosmosTransaction;
    use ikc_common::constants;
    use ikc_common::utility::{hex_to_bytes, secp256k1_sign};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_ecsign() {
        let sign_pack = hex_to_bytes(
            "0120D560F6EAB74C1D26DD5FAB27B9F700F4C371AC76A82E9A2E534269322D129E2F070008000900",
        )
        .unwrap();
        let private_key =
            hex_to_bytes("F85B222058BBEFFF888AAF7AD1D08B0C9C5FF719027F7DB69859B72A17B28749")
                .unwrap();
        let prepare_data = secp256k1_sign(&private_key, &sign_pack.as_slice()).unwrap();
        let prepare_data_hex = hex::encode(&prepare_data);
        assert_eq!(prepare_data_hex,
                   "3045022100a773a750391978586598843f89921d33083f670049906dc68ad312867df2826d0220312d22dcc102d8ba2a86972c7c73f082c53b29ef0a04ac630def935ed996d9c2"
        );
    }

    #[test]
    fn test_base64() {
        let hex = "477135B0DF08980F927D1569A780B4C4D24DA503BBCF98B87F606C29D47110FB654A8BAC272C80860018D77039563644209011717F4A69691F6B27C44C48002E".to_string();
        let bytes = hex::decode(&hex).unwrap();
        let base64 = base64::encode(&bytes);
        assert_eq!(base64,
                   "R3E1sN8ImA+SfRVpp4C0xNJNpQO7z5i4f2BsKdRxEPtlSousJyyAhgAY13A5VjZEIJARcX9KaWkfayfETEgALg=="
        );
    }

    #[test]
    fn test_sign_delegate() {
        bind_test();
        let sign_data= "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201".to_string();
        let input = CosmosTransaction {
            sign_data,
            path: constants::COSMOS_PATH.to_string(),
            payment_dis: "".to_string(),
            to_dis: "cosmos1yeckxz7tapz34kjwnjxvmxzurerquhtrmxmuxt".to_string(),
            fee_dis: "0.00075 atom".to_string(),
        };
        let cosmos_tx_output = input.sign().unwrap();
        assert_eq!("355fWQ00dYitAZj6+EmnAgYEX1g7QtUrX/kQIqCbv05TCz0dfsWcMgXWVnr1l/I2hrjjQkiLRMoeRrmnqT2CZA==", cosmos_tx_output.signature);
    }

    #[test]
    fn test_sign_payment_dis() {
        bind_test();
        let sign_data = "7b226163636f756e745f6e756d626572223a2231323334353637383930222c22636861696e5f6964223a2274656e6465726d696e745f74657374222c22666565223a7b22616d6f756e74223a5b7b22616d6f756e74223a2230222c2264656e6f6d223a22227d5d2c22676173223a223231393036227d2c226d656d6f223a22222c226d736773223a5b7b2274797065223a22636f736d6f732d73646b2f4d736744656c6567617465222c2276616c7565223a7b22616d6f756e74223a5b7b22616d6f756e74223a223130222c2264656e6f6d223a2261746f6d227d5d2c2264656c656761746f725f61646472657373223a22636f736d6f73317930613873633561797635326632666d35743768723267383871676c6a7a6b346a637a373866222c2276616c696461746f725f61646472657373223a22636f736d6f7376616c6f706572317a6b757072383368727a6b6e33757035656c6b747a63713374756674386e78736d7764716770227d7d5d2c2273657175656e6365223a2231323334353637383930227d".to_string();
        let input = CosmosTransaction {
            sign_data,
            path: constants::COSMOS_PATH.to_string(),
            payment_dis: "0.001 ATOM".to_string(),
            to_dis: "cosmos1yeckxz7tapz34kjwnjxvmxzurerquhtrmxmuxt".to_string(),
            fee_dis: "0.00075 atom".to_string(),
        };
        let cosmos_tx_output = input.sign().unwrap();
        assert_eq!("h4//cOYLTiDYbdw+1NVZufwppIAcEQ1xsWMYcCdcGtsu4xSnYStxyJgIa57445sHnXgWP84VvnQ5geoUZAKxlQ==", cosmos_tx_output.signature);
    }

    #[test]
    fn test_sort_vec() {
        let mut vec = Vec::new();
        vec.push("richard");
        vec.push("charles");
        vec.push("peter");
        vec.push("from");
        vec.push("to");
        vec.push("delegate");
        vec.push("valide");

        vec.sort();
        assert_eq!(
            format!("{:?}", vec),
            "[\"charles\", \"delegate\", \"from\", \"peter\", \"richard\", \"to\", \"valide\"]"
        );
    }
}
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn sender_and_declared_key_must_match_the_device_key() {
        let context = secp256k1::Secp256k1::new();
        let key = secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
        let key = secp256k1::PublicKey::from_secret_key(&context, &key);
        let sender = address_from_pubkey("cosmos", &key).unwrap();
        let mut display = display::Display {
            payment: "1 uatom".into(),
            receiver: sender.clone(),
            fee: "0".into(),
            sender,
            declared_public_key: Some(key.serialize().to_vec()),
        };
        let device = hex::encode(key.serialize_uncompressed());
        verify_sender(&display, &device).unwrap();
        let other = secp256k1::SecretKey::from_slice(&[2; 32]).unwrap();
        let other = secp256k1::PublicKey::from_secret_key(&context, &other);
        display.declared_public_key = Some(other.serialize().to_vec());
        assert!(verify_sender(&display, &device).is_err());
        display.declared_public_key = None;
        display.sender = address_from_pubkey("cosmos", &other).unwrap();
        assert!(verify_sender(&display, &device).is_err());
    }

    #[test]
    fn malformed_signature_responses_cannot_panic() {
        for len in 0..134 {
            let response = format!("{}9000", "0".repeat(len));
            assert!(std::panic::catch_unwind(|| parse_signature(&response)).is_ok());
        }
        for response in ["", "9000", "zz9000", "汉9000", "😀9000"] {
            assert!(parse_signature(response).is_err());
        }
    }
}
