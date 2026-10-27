//! Display summaries for the explicitly supported Cosmos signing schemas.
//! Amounts use the signed base denomination; no caller-supplied ticker/decimals.
use crate::Result;
use anyhow::anyhow;
use bech32::FromBase32;
use prost::Message;
use serde::Deserialize;

const MAX_SIGN_DATA: usize = 1_048_576;

#[derive(Clone, PartialEq, Message, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coin {
    #[prost(string, tag = "1")]
    denom: String,
    #[prost(string, tag = "2")]
    amount: String,
}

#[derive(Clone, PartialEq, Message, Deserialize)]
#[serde(deny_unknown_fields)]
struct Send {
    #[prost(string, tag = "1")]
    from_address: String,
    #[prost(string, tag = "2")]
    to_address: String,
    #[prost(message, repeated, tag = "3")]
    amount: Vec<Coin>,
}

#[derive(Clone, PartialEq, Message, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegate {
    #[prost(string, tag = "1")]
    delegator_address: String,
    #[prost(string, tag = "2")]
    validator_address: String,
    #[prost(message, optional, tag = "3")]
    amount: Option<Coin>,
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
enum AminoMessage {
    #[serde(rename = "cosmos-sdk/MsgSend")]
    Send(Send),
    #[serde(rename = "cosmos-sdk/MsgDelegate")]
    Delegate(Delegate),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AminoFee {
    amount: Vec<Coin>,
    gas: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AminoSignDoc {
    account_number: String,
    chain_id: String,
    fee: AminoFee,
    memo: String,
    msgs: Vec<AminoMessage>,
    sequence: String,
    #[serde(default)]
    timeout_height: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct SignDoc {
    #[prost(bytes, tag = "1")]
    body_bytes: Vec<u8>,
    #[prost(bytes, tag = "2")]
    auth_info_bytes: Vec<u8>,
    #[prost(string, tag = "3")]
    chain_id: String,
    #[prost(uint64, tag = "4")]
    account_number: u64,
}

#[derive(Clone, PartialEq, Message)]
struct TxBody {
    #[prost(message, repeated, tag = "1")]
    messages: Vec<prost_types::Any>,
    #[prost(string, tag = "2")]
    memo: String,
    #[prost(uint64, tag = "3")]
    timeout_height: u64,
    #[prost(message, repeated, tag = "1023")]
    extension_options: Vec<prost_types::Any>,
    #[prost(message, repeated, tag = "2047")]
    non_critical_extension_options: Vec<prost_types::Any>,
}

#[derive(Clone, PartialEq, Message)]
struct AuthInfo {
    #[prost(message, repeated, tag = "1")]
    signer_infos: Vec<SignerInfo>,
    #[prost(message, optional, tag = "2")]
    fee: Option<Fee>,
}

#[derive(Clone, PartialEq, Message)]
struct SignerInfo {
    #[prost(message, optional, tag = "1")]
    public_key: Option<prost_types::Any>,
    #[prost(message, optional, tag = "2")]
    mode_info: Option<ModeInfo>,
    #[prost(uint64, tag = "3")]
    sequence: u64,
}

#[derive(Clone, PartialEq, Message)]
struct ModeInfo {
    #[prost(message, optional, tag = "1")]
    single: Option<SingleMode>,
}

#[derive(Clone, PartialEq, Message)]
struct SingleMode {
    #[prost(int32, tag = "1")]
    mode: i32,
}

#[derive(Clone, PartialEq, Message)]
struct Secp256k1PublicKey {
    #[prost(bytes, tag = "1")]
    key: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct Fee {
    #[prost(message, repeated, tag = "1")]
    amount: Vec<Coin>,
    #[prost(uint64, tag = "2")]
    gas_limit: u64,
    #[prost(string, tag = "3")]
    payer: String,
    #[prost(string, tag = "4")]
    granter: String,
}

#[derive(Debug, PartialEq)]
pub(crate) struct Display {
    pub payment: String,
    pub receiver: String,
    pub fee: String,
    pub sender: String,
    pub declared_public_key: Option<Vec<u8>>,
}

fn invalid() -> anyhow::Error {
    anyhow!("imkey_unsupported_transaction_display")
}

fn number(value: &str) -> Result<&str> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    Ok(value.trim_start_matches('0'))
}

fn coins(coins: &[Coin]) -> Result<String> {
    if coins.len() > 16 {
        return Err(invalid());
    }
    let mut values = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for coin in coins {
        let amount = number(&coin.amount)?;
        if coin.denom.is_empty()
            || coin.denom.len() > 128
            || !coin
                .denom
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/:._-".contains(&byte))
            || !seen.insert(&coin.denom)
        {
            return Err(invalid());
        }
        values.push(format!(
            "{} {}",
            if amount.is_empty() { "0" } else { amount },
            coin.denom
        ));
    }
    values.sort();
    Ok(if values.is_empty() {
        "0".to_owned()
    } else {
        values.join(", ")
    })
}

fn send_display(message: Send, fee: String) -> Result<Display> {
    if message.amount.is_empty() {
        return Err(invalid());
    }
    Ok(Display {
        payment: coins(&message.amount)?,
        receiver: message.to_address,
        sender: message.from_address,
        declared_public_key: None,
        fee,
    })
}

fn delegate_display(message: Delegate, fee: String) -> Result<Display> {
    Ok(Display {
        payment: coins(&[message.amount.ok_or_else(invalid)?])?,
        receiver: format!("delegate:{}", message.validator_address),
        sender: message.delegator_address,
        declared_public_key: None,
        fee,
    })
}

pub(crate) fn derive(data: &[u8]) -> Result<Display> {
    if data.is_empty() || data.len() > MAX_SIGN_DATA {
        return Err(invalid());
    }
    let display = if data.first() == Some(&b'{') {
        let doc: AminoSignDoc = serde_json::from_slice(data).map_err(|_| invalid())?;
        number(&doc.account_number)?;
        number(&doc.sequence)?;
        number(&doc.fee.gas)?;
        if let Some(timeout) = &doc.timeout_height {
            number(timeout)?;
        }
        if doc.chain_id.is_empty() || doc.msgs.len() != 1 {
            return Err(invalid());
        }
        let _memo = &doc.memo;
        let fee = coins(&doc.fee.amount)?;
        match doc.msgs.into_iter().next().ok_or_else(invalid)? {
            AminoMessage::Send(message) => send_display(message, fee)?,
            AminoMessage::Delegate(message) => delegate_display(message, fee)?,
        }
    } else {
        let doc = SignDoc::decode(data).map_err(|_| invalid())?;
        let body = TxBody::decode(doc.body_bytes.as_slice()).map_err(|_| invalid())?;
        let auth = AuthInfo::decode(doc.auth_info_bytes.as_slice()).map_err(|_| invalid())?;
        // Unknown protobuf fields, extensions, and alternate signer layouts are
        // intentionally rejected instead of claiming an incomplete summary.
        if doc.encode_to_vec() != data
            || body.encode_to_vec() != doc.body_bytes
            || auth.encode_to_vec() != doc.auth_info_bytes
            || doc.chain_id.is_empty()
            || body.messages.len() != 1
            || auth.signer_infos.len() != 1
            || !body.extension_options.is_empty()
            || !body.non_critical_extension_options.is_empty()
        {
            return Err(invalid());
        }
        let signer = auth.signer_infos.first().ok_or_else(invalid)?;
        if signer
            .mode_info
            .as_ref()
            .and_then(|info| info.single.as_ref())
            .map(|single| single.mode)
            != Some(1)
        {
            return Err(invalid());
        }
        let public_key = signer.public_key.as_ref().ok_or_else(invalid)?;
        if public_key.type_url != "/cosmos.crypto.secp256k1.PubKey" {
            return Err(invalid());
        }
        let key = Secp256k1PublicKey::decode(public_key.value.as_slice()).map_err(|_| invalid())?;
        if key.encode_to_vec() != public_key.value
            || key.key.len() != 33
            || secp256k1::PublicKey::from_slice(&key.key).is_err()
        {
            return Err(invalid());
        }
        let fee = auth.fee.ok_or_else(invalid)?;
        if !fee.payer.is_empty() || !fee.granter.is_empty() {
            return Err(invalid());
        }
        let fee = coins(&fee.amount)?;
        let message = body.messages.into_iter().next().ok_or_else(invalid)?;
        let mut display = match message.type_url.as_str() {
            "/cosmos.bank.v1beta1.MsgSend" => {
                let value = Send::decode(message.value.as_slice()).map_err(|_| invalid())?;
                if value.encode_to_vec() != message.value {
                    return Err(invalid());
                }
                send_display(value, fee)?
            }
            "/cosmos.staking.v1beta1.MsgDelegate" => {
                let value = Delegate::decode(message.value.as_slice()).map_err(|_| invalid())?;
                if value.encode_to_vec() != message.value {
                    return Err(invalid());
                }
                delegate_display(value, fee)?
            }
            _ => return Err(invalid()),
        };
        display.declared_public_key = Some(key.key);
        display
    };
    for value in [&display.payment, &display.receiver, &display.fee] {
        if value.len() > 255
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() && byte != b' ')
        {
            return Err(invalid());
        }
    }
    let recipient = display
        .receiver
        .strip_prefix("delegate:")
        .unwrap_or(&display.receiver);
    for address in [&display.sender, recipient] {
        let (_, data, variant) = bech32::decode(address).map_err(|_| invalid())?;
        if variant != bech32::Variant::Bech32
            || Vec::<u8>::from_base32(&data).map_err(|_| invalid())?.len() != 20
        {
            return Err(invalid());
        }
    }
    Ok(display)
}

pub(crate) fn validate_assertions(
    display: &Display,
    payment: &str,
    receiver: &str,
    fee: &str,
) -> Result<()> {
    if (!payment.is_empty() && payment != display.payment)
        || (!receiver.is_empty() && receiver != display.receiver)
        || (!fee.is_empty() && fee != display.fee)
    {
        return Err(anyhow!("imkey_transaction_display_mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROM: &str = "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992";
    const TO: &str = "cosmos1yeckxz7tapz34kjwnjxvmxzurerquhtrmxmuxt";

    fn amino() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "account_number":"1","chain_id":"cosmoshub-4","sequence":"2","memo":"",
            "fee":{"amount":[{"amount":"200","denom":"uatom"}],"gas":"100000"},
            "msgs":[{"type":"cosmos-sdk/MsgSend","value":{"from_address":FROM,"to_address":TO,
                "amount":[{"amount":"10000","denom":"uatom"}]}}]
        }))
        .unwrap()
    }

    #[test]
    fn binds_amino_display_to_signed_fields() {
        let display = derive(&amino()).unwrap();
        assert_eq!(display.payment, "10000 uatom");
        assert_eq!(display.receiver, TO);
        assert_eq!(display.fee, "200 uatom");
        validate_assertions(&display, "", "", "").unwrap();
        for (payment, receiver, fee) in [
            ("1 ATOM", TO, "200 uatom"),
            ("10000 uatom", FROM, "200 uatom"),
            ("10000 uatom", TO, "1 uatom"),
        ] {
            assert_eq!(
                validate_assertions(&display, payment, receiver, fee)
                    .unwrap_err()
                    .to_string(),
                "imkey_transaction_display_mismatch"
            );
        }
    }

    #[test]
    fn derives_the_existing_direct_sign_doc_fixture() {
        let bytes = hex::decode("0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201").unwrap();
        let display = derive(&bytes).unwrap();
        assert_eq!(display.payment, "10000 uatom");
        assert_eq!(display.fee, "2004 uatom");
        assert_eq!(
            display.receiver,
            "cosmos1j0clrcqrzca52lagpz27hwtq74wl2re5484awh"
        );
    }

    #[test]
    fn derives_direct_sign_doc_and_rejects_unknown_fields() {
        let send = Send {
            from_address: FROM.into(),
            to_address: TO.into(),
            amount: vec![Coin {
                denom: "uatom".into(),
                amount: "42".into(),
            }],
        };
        let body = TxBody {
            messages: vec![prost_types::Any {
                type_url: "/cosmos.bank.v1beta1.MsgSend".into(),
                value: send.encode_to_vec(),
            }],
            ..Default::default()
        };
        let auth = AuthInfo {
            signer_infos: vec![SignerInfo {
                public_key: Some(prost_types::Any {
                    type_url: "/cosmos.crypto.secp256k1.PubKey".into(),
                    value: Secp256k1PublicKey {
                        key: hex::decode(
                            "0232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d65",
                        )
                        .unwrap(),
                    }
                    .encode_to_vec(),
                }),
                mode_info: Some(ModeInfo {
                    single: Some(SingleMode { mode: 1 }),
                }),
                sequence: 0,
            }],
            fee: Some(Fee {
                amount: vec![],
                ..Default::default()
            }),
        };
        let mut doc = SignDoc {
            body_bytes: body.encode_to_vec(),
            auth_info_bytes: auth.encode_to_vec(),
            chain_id: "cosmoshub-4".into(),
            account_number: 1,
        }
        .encode_to_vec();
        assert_eq!(derive(&doc).unwrap().payment, "42 uatom");
        let mut parsed = SignDoc::decode(doc.as_slice()).unwrap();
        let mut auth = AuthInfo::decode(parsed.auth_info_bytes.as_slice()).unwrap();
        auth.signer_infos[0]
            .mode_info
            .as_mut()
            .unwrap()
            .single
            .as_mut()
            .unwrap()
            .mode = 127;
        parsed.auth_info_bytes = auth.encode_to_vec();
        assert!(derive(&parsed.encode_to_vec()).is_err());
        auth.signer_infos[0]
            .mode_info
            .as_mut()
            .unwrap()
            .single
            .as_mut()
            .unwrap()
            .mode = 1;
        auth.signer_infos[0].public_key.as_mut().unwrap().type_url = "/unknown.PubKey".into();
        parsed.auth_info_bytes = auth.encode_to_vec();
        assert!(derive(&parsed.encode_to_vec()).is_err());
        doc.extend_from_slice(&[40, 1]);
        assert!(derive(&doc).is_err());
    }

    #[test]
    fn rejects_unknown_amino_envelope_fields_duplicates_and_bech32m() {
        let mut doc: serde_json::Value = serde_json::from_slice(&amino()).unwrap();
        doc["msgs"][0]["unrecognized"] = true.into();
        assert!(derive(&serde_json::to_vec(&doc).unwrap()).is_err());
        let raw = String::from_utf8(amino()).unwrap().replace(
            "\"sequence\":\"2\"",
            "\"sequence\":\"2\",\"sequence\":\"3\"",
        );
        assert!(derive(raw.as_bytes()).is_err());
        let mut doc: serde_json::Value = serde_json::from_slice(&amino()).unwrap();
        use bech32::ToBase32;
        let wrong =
            bech32::encode("cosmos", [1u8; 20].to_base32(), bech32::Variant::Bech32m).unwrap();
        doc["msgs"][0]["value"]["from_address"] = wrong.into();
        assert!(derive(&serde_json::to_vec(&doc).unwrap()).is_err());
    }

    #[test]
    fn rejects_opaque_multi_message_and_malformed_data() {
        for data in [
            vec![],
            vec![0xff],
            b"{}".to_vec(),
            b"{\"msgs\":[],\"msgs\":[]}".to_vec(),
        ] {
            assert!(derive(&data).is_err());
        }
        let mut doc: serde_json::Value = serde_json::from_slice(&amino()).unwrap();
        doc["msgs"][0]["type"] = "unsupported".into();
        assert!(derive(&serde_json::to_vec(&doc).unwrap()).is_err());
    }
}
