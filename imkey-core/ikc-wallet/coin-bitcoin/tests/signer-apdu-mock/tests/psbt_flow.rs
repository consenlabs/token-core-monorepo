//! Exercises the production synchronous PSBT path against an in-process APDU
//! substitute. The substitute cannot open HID or connect to a real device.
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::util::sighash::SighashCache;
use bitcoin::{
    Address, EcdsaSighashType, Network, OutPoint, PackedLockTime, PublicKey, Script, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use coin_bitcoin::btcapi::PsbtInput;
use ikc_device::device_binding::KEY_MANAGER;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

static TEST_LOCK: Mutex<()> = Mutex::new(());

const DEST: &str = "bc1q9x6q5phzggl976srhuvnkjzwdtfu27tqld9tdw4hpvcgguw5g7xqp88l3g";
const ACCOUNT: &str = "m/84'/0'/0'";

fn extract_signed_body(apdu: &[u8]) -> &[u8] {
    let data = &apdu[5..5 + apdu[4] as usize];
    assert_eq!(data[0], 0);
    let offset = 2 + data[1] as usize;
    assert_eq!(data[offset], 1);
    assert_eq!(data[offset + 1] as usize, data.len() - offset - 2);
    &data[offset + 2..]
}

fn funding_transaction(script_pubkey: Script, value: u64) -> Transaction {
    Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn {
            witness: Witness::from_vec(vec![vec![1; 32]]),
            ..TxIn::default()
        }],
        output: vec![
            TxOut {
                value: 1_000,
                script_pubkey: script_pubkey.clone(),
            },
            TxOut {
                value: 2_000,
                script_pubkey: script_pubkey.clone(),
            },
            TxOut {
                value,
                script_pubkey,
            },
        ],
    }
}

fn checked_proof(trace: &[Vec<u8>], outpoint: OutPoint, sequence: Sequence) -> Transaction {
    let chunks: Vec<_> = trace.iter().filter(|apdu| apdu[1] == 0x53).collect();
    assert!(chunks.len() > 1);
    let mut body = Vec::new();
    for (index, apdu) in chunks.iter().enumerate() {
        let p1 = if index == 0 { 0 } else { 0x80 };
        let p2 = if index == chunks.len() - 1 { 0x80 } else { 0 };
        assert_eq!(apdu[..4], [0x80, 0x53, p1, p2]);
        let raw = extract_signed_body(apdu);
        assert_eq!(raw[..2], [p1, p2]);
        assert!(raw.len() <= 162);
        if index == 0 {
            assert!(raw.len() > 44);
        }
        assert_host_signature(apdu);
        body.extend_from_slice(&raw[2..]);
    }
    assert_eq!(body[..2], [1, 0]);
    assert_eq!(&body[2..38], &serialize(&outpoint));
    assert_eq!(&body[38..42], &serialize(&sequence));
    let previous_tx: Transaction = deserialize(&body[42..]).unwrap();
    assert_eq!(previous_tx.txid(), outpoint.txid);
    assert!(previous_tx
        .input
        .iter()
        .all(|input| input.witness.is_empty()));
    previous_tx
}

fn assert_host_signature(apdu: &[u8]) {
    let secp = Secp256k1::new();
    let host_key = SecretKey::from_slice(&[2; 32]).unwrap();
    let host_pub = secp256k1::PublicKey::from_secret_key(&secp, &host_key);
    let signature_end = 7 + apdu[6] as usize;
    let signature = secp256k1::ecdsa::Signature::from_der(&apdu[7..signature_end]).unwrap();
    let digest = sha256d::Hash::hash(&apdu[signature_end..]);
    secp.verify_ecdsa(
        &Message::from_slice(&digest[..]).unwrap(),
        &signature,
        &host_pub,
    )
    .unwrap();
}

#[derive(Clone, Copy)]
enum ProofCase {
    Valid,
    Missing,
    WrongTxid,
    WrongVout,
    MismatchedOutput,
}

fn run_case(
    version: &str,
    is_p2wsh: bool,
    extra_outputs: usize,
    legacy_input: bool,
    proof_case: ProofCase,
) -> (
    anyhow::Result<coin_bitcoin::btcapi::PsbtOutput>,
    Vec<Vec<u8>>,
    Transaction,
    Script,
    PublicKey,
) {
    let secp = Secp256k1::new();
    let signing_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let public = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &signing_key));
    let input_address = if legacy_input {
        Address::p2pkh(&public, Network::Bitcoin)
    } else {
        Address::p2wpkh(&public, Network::Bitcoin).unwrap()
    };
    let input_script = input_address.script_pubkey();
    let recipient = if is_p2wsh {
        Address::from_str(DEST).unwrap().script_pubkey()
    } else {
        let other = SecretKey::from_slice(&[3; 32]).unwrap();
        let other_public = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &other));
        Address::p2wpkh(&other_public, Network::Bitcoin)
            .unwrap()
            .script_pubkey()
    };
    let mut outputs = vec![TxOut {
        value: 5000,
        script_pubkey: recipient.clone(),
    }];
    for index in 0..extra_outputs {
        let script_pubkey = if index == 0 {
            input_script.clone()
        } else {
            recipient.clone()
        };
        outputs.push(TxOut {
            value: 100 + index as u64,
            script_pubkey,
        });
    }
    let input_value = outputs.iter().map(|output| output.value).sum::<u64>() + 1000;
    let funding = funding_transaction(input_script.clone(), input_value);
    let outpoint = OutPoint {
        txid: funding.txid(),
        vout: 2,
    };
    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            sequence: Sequence(0xfffffffd),
            ..TxIn::default()
        }],
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    psbt.inputs[0].witness_utxo = Some(funding.output[outpoint.vout as usize].clone());
    psbt.inputs[0].non_witness_utxo = Some(funding);
    match proof_case {
        ProofCase::Valid => {}
        ProofCase::Missing => psbt.inputs[0].non_witness_utxo = None,
        ProofCase::WrongTxid => psbt.inputs[0].non_witness_utxo.as_mut().unwrap().version = 1,
        ProofCase::WrongVout => psbt.unsigned_tx.input[0].previous_output.vout = 4,
        ProofCase::MismatchedOutput => psbt.inputs[0].witness_utxo.as_mut().unwrap().value += 1,
    }
    let sighash = if legacy_input {
        SighashCache::new(&tx)
            .legacy_signature_hash(0, &input_script, EcdsaSighashType::All.to_u32())
            .unwrap()
    } else {
        SighashCache::new(&tx)
            .segwit_signature_hash(
                0,
                &input_script.p2wpkh_script_code().unwrap(),
                input_value,
                EcdsaSighashType::All,
            )
            .unwrap()
    };
    let signature = secp
        .sign_ecdsa(&Message::from_slice(&sighash[..]).unwrap(), &signing_key)
        .serialize_compact();
    KEY_MANAGER.lock().pri_key = vec![2; 32];
    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let capture = Arc::clone(&records);
    let version = version.to_owned();
    let uncompressed = public.inner.serialize_uncompressed();
    ikc_transport::p2wsh_test_mock::install(Box::new(move |apdu, timeout| {
        let bytes = hex::decode(apdu)?;
        capture.lock().unwrap().push(bytes.clone());
        let response = if bytes[0..2] == [0, 0xa4] {
            if bytes.len() > 5 && bytes[5..] == [0x69, 0x5f, 0x62, 0x74, 0x63, 0] {
                format!("{}9000", hex::encode(version.as_bytes()))
            } else {
                "9000".to_string()
            }
        } else {
            match bytes[1] {
                0x43 => format!("{}{}9000", hex::encode(uncompressed), "00".repeat(32)),
                0x53 | 0x50 => "9000".to_string(),
                0x52 => {
                    let expected_timeout = if bytes[3] == 0x80 { 120 } else { 20 };
                    assert_eq!(timeout, expected_timeout);
                    "9000".to_string()
                }
                0x32 | 0x45 => format!("00{}009000", hex::encode(signature)),
                other => return Err(anyhow::anyhow!("unexpected mock APDU INS {:02x}", other)),
            }
        };
        Ok(response)
    }));
    let result = coin_bitcoin::psbt::sign_psbt(
        ACCOUNT,
        PsbtInput {
            psbt: hex::encode(serialize(&psbt)),
            auto_finalize: true,
        },
        Network::Bitcoin,
    );
    ikc_transport::p2wsh_test_mock::clear();
    KEY_MANAGER.lock().pri_key.clear();
    let transcript = records.lock().unwrap().clone();
    (result, transcript, tx, input_script, public)
}

#[test]
fn psbt_version_check_precedes_hashing_and_rejects_legacy_applets() {
    let _guard = TEST_LOCK.lock().unwrap();
    for is_p2wsh in [true, false] {
        let (result, trace, _, _, _) = run_case("1.6.12", is_p2wsh, 0, false, ProofCase::Valid);
        assert_eq!(result.err().unwrap().to_string(), "upgrade_applet");
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x4b, 0x4c, 0x52, 0x53, 0x32].contains(&apdu[1])));
    }
}

#[test]
fn psbt_sends_all_outputs_in_order_and_signs_only_after_confirmation() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (is_p2wsh, extra_outputs) in [(false, 0), (true, 1), (true, 5)] {
        let (result, trace, unsigned, input_script, public) =
            run_case("1.6.13", is_p2wsh, extra_outputs, false, ProofCase::Valid);
        let signed: Psbt = deserialize(&hex::decode(result.unwrap().psbt).unwrap()).unwrap();
        let tx = signed.extract_tx();
        assert_eq!(tx.output, unsigned.output);
        if extra_outputs > 0 {
            assert_eq!(tx.output[1].script_pubkey, input_script);
        }
        let input_value = tx.output.iter().map(|output| output.value).sum::<u64>() + 1000;
        let witness = tx.input[0].witness.to_vec();
        let sig =
            secp256k1::ecdsa::Signature::from_der(&witness[0][..witness[0].len() - 1]).unwrap();
        let hash = SighashCache::new(&tx)
            .segwit_signature_hash(
                0,
                &input_script.p2wpkh_script_code().unwrap(),
                input_value,
                EcdsaSighashType::All,
            )
            .unwrap();
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_slice(&hash[..]).unwrap(),
                &sig,
                &public.inner,
            )
            .unwrap();

        let id = trace
            .iter()
            .rposition(|apdu| apdu[0..2] == [0, 0xa4])
            .unwrap();
        let proof = trace.iter().position(|apdu| apdu[1] == 0x53).unwrap();
        let preview = trace.iter().position(|apdu| apdu[1] == 0x52).unwrap();
        let sign = trace.iter().position(|apdu| apdu[1] == 0x32).unwrap();
        assert!(id < proof && proof < preview && preview < sign);
        let previous = checked_proof(
            &trace,
            unsigned.input[0].previous_output,
            unsigned.input[0].sequence,
        );
        assert_eq!(previous.output[2].value, input_value);
        assert_eq!(previous.output[2].script_pubkey, input_script);
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x4b, 0x4c].contains(&apdu[1])));

        let mut body = Vec::new();
        for (index, apdu) in trace[preview..sign].iter().enumerate() {
            let phase = if preview + index == sign - 1 { 0x80 } else { 0 };
            assert_eq!(apdu[..4], [0x80, 0x52, index as u8, phase]);
            let raw = extract_signed_body(apdu);
            assert_eq!(raw[..2], [index as u8, phase]);
            assert!(raw.len() <= 162);
            if phase == 0 {
                assert_eq!(raw.len(), 162);
            }
            assert_host_signature(apdu);
            body.extend_from_slice(&raw[2..]);
        }
        assert_eq!(body[0], 0);
        assert_eq!(&body[1..5], &unsigned.version.to_le_bytes());
        assert_eq!(body[5], 1);
        assert_eq!(&body[6..10], &serialize(&unsigned.lock_time));
        assert_eq!(&body[10..], &serialize(&unsigned.output));
        assert_eq!(sign - preview, (body.len() + 159) / 160);
    }
}

#[test]
fn psbt_oversize_preview_returns_error_without_a_signing_command() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (result, trace, _, _, _) = run_case("1.6.13", true, 14, false, ProofCase::Valid);
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("psbt_preview_exceeds_output_data_limit"));
    assert!(!trace.iter().any(|apdu| [0x52, 0x32].contains(&apdu[1])));
}

#[test]
fn legacy_psbt_hash_commands_send_only_inputs_after_output_confirmation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (result, trace, unsigned, input_script, _) =
        run_case("1.6.13", true, 1, true, ProofCase::Valid);
    assert!(result.is_ok());
    let preview = trace.iter().rposition(|apdu| apdu[1] == 0x52).unwrap();
    let hash = trace.iter().position(|apdu| apdu[1] == 0x50).unwrap();
    let sign = trace.iter().position(|apdu| apdu[1] == 0x45).unwrap();
    assert!(preview < hash && hash < sign);
    let mut expected_input = unsigned.input[0].clone();
    expected_input.script_sig = input_script;
    let apdu = &trace[hash];
    assert_eq!(&apdu[5..5 + apdu[4] as usize], &serialize(&expected_input));
}

#[test]
fn psbt_rejects_missing_or_inconsistent_previous_transactions_before_proving_inputs() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (fixture, expected) in [
        (ProofCase::Missing, "btc_missing_previous_transaction"),
        (
            ProofCase::WrongTxid,
            "btc_previous_transaction_txid_mismatch",
        ),
        (
            ProofCase::WrongVout,
            "btc_previous_transaction_vout_not_found",
        ),
        (
            ProofCase::MismatchedOutput,
            "btc_previous_transaction_output_mismatch",
        ),
    ] {
        let (result, trace, _, _, _) = run_case("1.6.13", false, 0, false, fixture);
        assert!(result.err().unwrap().to_string().contains(expected));
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x53, 0x52, 0x32].contains(&apdu[1])));
    }
}

fn run_ordinary(
    version: &str,
    is_p2wsh: bool,
    proof_case: ProofCase,
) -> (
    anyhow::Result<coin_bitcoin::common::TxSignResult>,
    Vec<Vec<u8>>,
    Script,
) {
    use coin_bitcoin::transaction::{BtcTransaction, Utxo};
    let secp = Secp256k1::new();
    let signing_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let public = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &signing_key));
    let input = Address::p2wpkh(&public, Network::Bitcoin).unwrap();
    let dest = if is_p2wsh {
        Address::from_str(DEST).unwrap()
    } else {
        let other = SecretKey::from_slice(&[3; 32]).unwrap();
        Address::p2wpkh(
            &PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &other)),
            Network::Bitcoin,
        )
        .unwrap()
    };
    let mut funding = funding_transaction(input.script_pubkey(), 6000);
    let prevout = OutPoint {
        txid: funding.txid(),
        vout: 2,
    };
    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: 5000,
            script_pubkey: dest.script_pubkey(),
        }],
    };
    let sighash = SighashCache::new(&tx)
        .segwit_signature_hash(
            0,
            &input.script_pubkey().p2wpkh_script_code().unwrap(),
            6000,
            EcdsaSighashType::All,
        )
        .unwrap();
    let signature = secp
        .sign_ecdsa(&Message::from_slice(&sighash[..]).unwrap(), &signing_key)
        .serialize_compact();
    KEY_MANAGER.lock().pri_key = vec![2; 32];
    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let capture = Arc::clone(&records);
    let version = version.to_owned();
    let uncompressed = public.inner.serialize_uncompressed();
    ikc_transport::p2wsh_test_mock::install(Box::new(move |apdu, _| {
        let bytes = hex::decode(apdu)?;
        capture.lock().unwrap().push(bytes.clone());
        if bytes[0..2] == [0, 0xa4] {
            return Ok(if bytes.len() > 5 {
                format!("{}9000", hex::encode(version.as_bytes()))
            } else {
                "9000".to_owned()
            });
        }
        Ok(match bytes[1] {
            0x43 => format!("{}{}9000", hex::encode(uncompressed), "00".repeat(32)),
            0x53 | 0x41 => "9000".to_string(),
            0x32 => format!("00{}009000", hex::encode(signature)),
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected ordinary APDU INS {:02x}",
                    other
                ))
            }
        })
    }));
    let transfer = BtcTransaction {
        to: dest.to_string(),
        amount: 5000,
        fee: 1000,
        chain_type: "BITCOIN".to_owned(),
        unspents: vec![Utxo {
            txhash: prevout.txid.to_string(),
            vout: if matches!(proof_case, ProofCase::WrongVout) {
                4
            } else {
                prevout.vout
            },
            amount: if matches!(proof_case, ProofCase::MismatchedOutput) {
                6001
            } else {
                6000
            },
            address: input.to_string(),
            script_pubkey: hex::encode(input.script_pubkey().as_bytes()),
            derive_path: format!("{}/0/0", ACCOUNT),
            sequence: 0xffffffff,
        }],
    };
    if matches!(proof_case, ProofCase::WrongTxid) {
        funding.version = 1;
    }
    let previous_transactions = if matches!(proof_case, ProofCase::Missing) {
        vec![]
    } else {
        vec![serialize(&funding)]
    };
    let result = transfer.sign_transaction_with_previous_transactions(
        "MAINNET",
        ACCOUNT,
        None,
        None,
        "VERSION_0",
        &previous_transactions,
    );
    ikc_transport::p2wsh_test_mock::clear();
    KEY_MANAGER.lock().pri_key.clear();
    let transcript = records.lock().unwrap().clone();
    (result, transcript, dest.script_pubkey())
}

#[test]
fn ordinary_gate_rejects_old_applet_for_any_output_type() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (old, old_trace, _) = run_ordinary("1.6.12", true, ProofCase::Valid);
    assert!(old.is_err());
    assert!(!old_trace
        .iter()
        .any(|a| [0x31, 0x53, 0x41, 0x32].contains(&a[1])));
    for version in ["1.6.13", "1.10.0"] {
        let (result, trace, expected) = run_ordinary(version, true, ProofCase::Valid);
        let result = result.unwrap();
        let tx: Transaction = deserialize(&hex::decode(result.signature).unwrap()).unwrap();
        assert_eq!(tx.output[0].script_pubkey, expected);
        assert!(tx.output[0].script_pubkey.is_v0_p2wsh());
        let witness = tx.input[0].witness.to_vec();
        let public = PublicKey::from_slice(&witness[1]).unwrap();
        let input_script = Address::p2wpkh(&public, Network::Bitcoin)
            .unwrap()
            .script_pubkey();
        let hash = SighashCache::new(&tx)
            .segwit_signature_hash(
                0,
                &input_script.p2wpkh_script_code().unwrap(),
                6000,
                EcdsaSighashType::All,
            )
            .unwrap();
        let sig =
            secp256k1::ecdsa::Signature::from_der(&witness[0][..witness[0].len() - 1]).unwrap();
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_slice(&hash[..]).unwrap(),
                &sig,
                &public.inner,
            )
            .unwrap();
        assert!(!trace.iter().any(|a| a[1] == 0x31));
        let hash = trace.iter().position(|a| a[1] == 0x53).unwrap();
        let preview = trace.iter().position(|a| a[1] == 0x41).unwrap();
        let sign = trace.iter().position(|a| a[1] == 0x32).unwrap();
        assert!(hash < preview && preview < sign);
        let proved = checked_proof(&trace, tx.input[0].previous_output, tx.input[0].sequence);
        assert_eq!(proved.output[2].value, 6000);
        assert_eq!(proved.output[2].script_pubkey, input_script);
        let raw = extract_signed_body(&trace[preview]);
        assert_eq!(&raw[raw.len() - 9..raw.len() - 1], &[0; 8]);
        assert!(extract_signed_body(&trace[preview])
            .windows(expected.len())
            .any(|w| w == expected.as_bytes()));
    }
    let (old_other, trace, _) = run_ordinary("1.6.12", false, ProofCase::Valid);
    assert!(old_other.is_err());
    assert!(!trace
        .iter()
        .any(|a| [0x31, 0x53, 0x41, 0x32].contains(&a[1])));
}

#[test]
fn ordinary_btc_requires_matching_funding_data() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (fixture, expected) in [
        (
            ProofCase::Missing,
            "btc_requires_one_previous_transaction_per_input",
        ),
        (
            ProofCase::WrongTxid,
            "btc_previous_transaction_txid_mismatch",
        ),
        (
            ProofCase::WrongVout,
            "btc_previous_transaction_vout_not_found",
        ),
        (
            ProofCase::MismatchedOutput,
            "btc_previous_transaction_output_mismatch",
        ),
    ] {
        let (result, trace, _) = run_ordinary("1.6.13", false, fixture);
        assert!(result.err().unwrap().to_string().contains(expected));
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x53, 0x41, 0x32].contains(&apdu[1])));
    }
}

#[test]
fn mock_transport_without_handler_fails_closed() {
    let _guard = TEST_LOCK.lock().unwrap();
    ikc_transport::p2wsh_test_mock::clear();
    let err = ikc_transport::message::send_apdu("00".to_owned()).unwrap_err();
    assert_eq!(err.to_string(), "offline APDU mock is not installed");
    assert!(ikc_transport::hid_api::hid_connect("imKey Pro").is_err());
}
