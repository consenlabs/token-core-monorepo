use bitcoin::consensus::{deserialize, serialize};
use bitcoin::util::sighash::SighashCache;
use bitcoin::{Address, EcdsaSighashType, Network, PublicKey, Script, Transaction, TxIn, TxOut};
use coin_bitcoin::btcapi::{BtcMessageInput, BtcSignatureType};
use coin_bitcoin::message::MessageSinger;
use coin_bitcoin::transaction::{BtcTransaction, Utxo};
use ikc_device::device_binding::KEY_MANAGER;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::sync::{Arc, Mutex};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn command_body(apdu: &[u8]) -> &[u8] {
    let data = &apdu[5..5 + apdu[4] as usize];
    let raw = 2 + data[1] as usize;
    assert_eq!(data[raw], 1);
    assert_eq!(&data[raw + 2..raw + 4], &apdu[2..4]);
    assert_eq!(data[raw + 1] as usize, data.len() - raw - 2);
    &data[raw + 4..]
}

fn setup() -> (SecretKey, PublicKey, Arc<Mutex<Vec<Vec<u8>>>>) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let public = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &secret));
    KEY_MANAGER.lock().pri_key = vec![2; 32];
    (secret, public, Arc::new(Mutex::new(Vec::new())))
}

#[test]
fn omni_uses_verified_funding_and_full_review_for_legacy_and_segwit() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (segwit, account, funding_value, outputs) in [
        (false, "m/44'/0'/0'", 1_700, 3),
        (true, "m/49'/0'/0'", 1_046, 2),
    ] {
        let (secret, public, trace) = setup();
        let capture = trace.clone();
        let source = if segwit {
            Address::p2shwpkh(&public, Network::Bitcoin).unwrap()
        } else {
            Address::p2pkh(&public, Network::Bitcoin)
        };
        let recipient = Address::p2pkh(
            &PublicKey::new(secp256k1::PublicKey::from_secret_key(
                &Secp256k1::new(),
                &SecretKey::from_slice(&[3; 32]).unwrap(),
            )),
            Network::Bitcoin,
        );
        let source_script = source.script_pubkey();
        let funding = Transaction {
            version: 2,
            lock_time: bitcoin::PackedLockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: funding_value,
                script_pubkey: source_script.clone(),
            }],
        };
        let input = Utxo {
            txhash: funding.txid().to_string(),
            vout: 0,
            amount: funding_value,
            address: source.to_string(),
            script_pubkey: hex::encode(source_script.as_bytes()),
            derive_path: format!("{account}/0/0"),
            sequence: 0xffffffff,
        };
        let omni = BtcTransaction {
            to: recipient.to_string(),
            amount: 100,
            fee: 500,
            unspents: vec![input],
            chain_type: "BITCOIN".to_owned(),
        };
        assert!(omni
            .sign_omni_transaction_with_previous_transactions(
                Network::Bitcoin,
                account,
                31,
                segwit,
                &[],
            )
            .err()
            .unwrap()
            .to_string()
            .contains("btc_requires_one_previous_transaction_per_input"));
        let mut preview = Vec::new();
        let key = public.inner.serialize_uncompressed();
        let vout = bitcoin::OutPoint {
            txid: funding.txid(),
            vout: 0,
        };
        ikc_transport::p2wsh_test_mock::install(Box::new(move |apdu, timeout| {
            let bytes = hex::decode(apdu)?;
            capture.lock().unwrap().push(bytes.clone());
            Ok(match bytes[1] {
                0xA4 => format!("{}9000", hex::encode("1.6.13")),
                0x43 => format!("{}{}9000", hex::encode(key), "00".repeat(32)),
                0x53 => {
                    assert_eq!(&command_body(&bytes)[..2], &[1, 0]);
                    assert_eq!(&command_body(&bytes)[2..38], &serialize(&vout));
                    assert_eq!(bytes[3], 0x80);
                    format!("{}9000", "44".repeat(32))
                }
                0x56 | 0x54 | 0x50 => "9000".to_owned(),
                0x57 => {
                    assert_eq!(timeout, if bytes[3] == 0x80 { 120 } else { 20 });
                    preview.extend_from_slice(command_body(&bytes));
                    "9000".to_owned()
                }
                0x32 | 0x45 => {
                    assert_eq!(bytes[1], if segwit { 0x32 } else { 0x45 });
                    if segwit {
                        let end = 5 + bytes[4] as usize;
                        assert_eq!(&bytes[end - 32..end], &[0x44; 32]);
                    }
                    let tx = Transaction {
                        version: i32::from_le_bytes(preview[1..5].try_into()?),
                        lock_time: bitcoin::PackedLockTime::ZERO,
                        input: vec![TxIn {
                            previous_output: vout,
                            sequence: bitcoin::Sequence::MAX,
                            ..TxIn::default()
                        }],
                        output: deserialize(&preview[10..])?,
                    };
                    let hash = if segwit {
                        let script_code = Address::p2wpkh(&public, Network::Bitcoin)
                            .unwrap()
                            .script_pubkey()
                            .p2wpkh_script_code()
                            .unwrap();
                        SighashCache::new(&tx).segwit_signature_hash(
                            0,
                            &script_code,
                            funding_value,
                            EcdsaSighashType::All,
                        )?
                    } else {
                        SighashCache::new(&tx).legacy_signature_hash(
                            0,
                            &source_script,
                            EcdsaSighashType::All.to_u32(),
                        )?
                    };
                    let signature =
                        Secp256k1::new().sign_ecdsa(&Message::from_slice(&hash[..])?, &secret);
                    format!("00{}009000", hex::encode(signature.serialize_compact()))
                }
                command => return Err(anyhow::anyhow!("unexpected Omni APDU {command:02x}")),
            })
        }));
        let result = omni.sign_omni_transaction_with_previous_transactions(
            Network::Bitcoin,
            account,
            31,
            segwit,
            &[serialize(&funding)],
        );
        ikc_transport::p2wsh_test_mock::clear();
        KEY_MANAGER.lock().pri_key.clear();
        let result = result.unwrap_or_else(|error| panic!("Omni signing failed: {error}"));
        let tx: Transaction = deserialize(&hex::decode(result.signature).unwrap()).unwrap();
        assert_eq!(tx.output.len(), outputs);
        assert_eq!(
            tx.output[outputs - 2].script_pubkey,
            recipient.script_pubkey()
        );
        assert_eq!(tx.output[outputs - 2].value, 546);
        assert_eq!(
            tx.output[outputs - 1].script_pubkey,
            Script::from(hex::decode("6a146f6d6e69000000000000001f0000000000000064").unwrap())
        );
        assert_eq!(
            funding_value - tx.output.iter().map(|output| output.value).sum::<u64>(),
            500
        );
        let trace = trace.lock().unwrap();
        let ins: Vec<_> = trace.iter().map(|command| command[1]).collect();
        assert!(
            ins.iter().position(|&value| value == 0x53).unwrap()
                < ins.iter().position(|&value| value == 0x57).unwrap()
        );
        assert!(
            ins.iter().rposition(|&value| value == 0x57).unwrap()
                < ins
                    .iter()
                    .position(|&value| value == if segwit { 0x32 } else { 0x45 })
                    .unwrap()
        );
        assert!(!ins.iter().any(|value| [0x34, 0x44].contains(value)));
    }
}

#[test]
fn bip137_transmits_original_message_and_has_no_legacy_fallback() {
    let _guard = TEST_LOCK.lock().unwrap();
    let singer = MessageSinger {
        derivation_path: "m/44'/0'/0'".to_owned(),
        chain_type: "BITCOIN".to_owned(),
        network: "MAINNET".to_owned(),
        seg_wit: "NONE".to_owned(),
    };
    for (message, supported) in [
        ("A".repeat(253), true),
        (String::new(), true),
        ("hello".to_owned(), false),
    ] {
        let (secret, _, trace) = setup();
        let capture = trace.clone();
        let signature =
            Secp256k1::new().sign_ecdsa(&Message::from_slice(&[1; 32]).unwrap(), &secret);
        ikc_transport::p2wsh_test_mock::install(Box::new(move |apdu, timeout| {
            let bytes = hex::decode(apdu)?;
            capture.lock().unwrap().push(bytes.clone());
            Ok(match bytes[1] {
                0xA4 => format!("{}9000", hex::encode("1.6.13")),
                0x58 if !supported => "6D00".to_owned(),
                0x58 if bytes[3] == 0x80 => {
                    assert_eq!(timeout, 120);
                    format!("00{}009000", hex::encode(signature.serialize_compact()))
                }
                0x58 => {
                    assert_eq!(timeout, 20);
                    "9000".to_owned()
                }
                other => return Err(anyhow::anyhow!("unexpected message APDU {other:02x}")),
            })
        }));
        let result = singer.sign_message(BtcMessageInput {
            message: message.clone(),
            signature_type: BtcSignatureType::Bip137 as i32,
        });
        ikc_transport::p2wsh_test_mock::clear();
        KEY_MANAGER.lock().pri_key.clear();
        assert_eq!(result.is_ok(), supported);
        let trace = trace.lock().unwrap();
        assert!(!trace.iter().any(|command| command[1] == 0x51));
        let commands: Vec<_> = trace.iter().filter(|command| command[1] == 0x58).collect();
        let mut payload = Vec::new();
        for (index, command) in commands.iter().enumerate() {
            assert_eq!(command[2], index as u8);
            assert_eq!(
                command[3],
                if index == commands.len() - 1 { 0x80 } else { 0 }
            );
            payload.extend_from_slice(command_body(command));
        }
        let path_end = 1 + payload[0] as usize;
        assert_eq!(&payload[1..path_end], b"m/44'/0'/0'/0/0");
        assert_eq!(
            &payload[path_end..path_end + 2],
            &(message.len() as u16).to_be_bytes()
        );
        assert_eq!(&payload[path_end + 2..], message.as_bytes());
    }
}
