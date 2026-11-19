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
const PSBT_CHANGE_PATH: &str = "m/84'/0'/0'/1/23";
const OTHER_PSBT_CHANGE_PATH: &str = "m/84'/0'/0'/1/25";
const TAPROOT_ACCOUNT: &str = "m/86'/0'/0'";
const TAPROOT_CHANGE_PATH: &str = "m/86'/0'/0'/1/23";

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
    OldAppletWithoutReceipt,
    InvalidReceipt,
    UnexpectedIntermediateData,
    UnsupportedChangeHints,
}

fn receipt_for(index: u8) -> [u8; 32] {
    [0x40 + index; 32]
}

fn proof_response(apdu: &[u8], proof_case: ProofCase, index: &mut u8) -> String {
    if apdu[2] == 0 {
        *index = extract_signed_body(apdu)[3];
    }
    if apdu[3] == 0 {
        return if matches!(proof_case, ProofCase::UnexpectedIntermediateData) {
            "009000".to_owned()
        } else {
            "9000".to_owned()
        };
    }

    match proof_case {
        ProofCase::OldAppletWithoutReceipt => "9000".to_owned(),
        ProofCase::InvalidReceipt => format!("{}9000", "zz".repeat(32)),
        _ => format!("{}9000", hex::encode(receipt_for(*index))),
    }
}

fn change_hint_response(proof_case: ProofCase) -> String {
    if matches!(proof_case, ProofCase::UnsupportedChangeHints) {
        "6D00".to_owned()
    } else {
        "9000".to_owned()
    }
}

fn assert_sign_receipt(apdu: &[u8], index: u8, outpoint: OutPoint) {
    let body = &apdu[5..5 + apdu[4] as usize];
    assert_eq!(&body[1..37], serialize(&outpoint));
    let path_len_offset = 1 + body[0] as usize;
    let path_end = path_len_offset + 1 + body[path_len_offset] as usize;
    assert_eq!(
        &body[path_len_offset + 1..path_end],
        format!("{}/0/0", ACCOUNT).as_bytes()
    );
    assert_eq!(&body[path_end..], receipt_for(index));
}

fn run_case(
    version: &str,
    is_p2wsh: bool,
    extra_outputs: usize,
    legacy_input: bool,
    proof_case: ProofCase,
    multiple_inputs: bool,
) -> (
    anyhow::Result<coin_bitcoin::btcapi::PsbtOutput>,
    Vec<Vec<u8>>,
    Transaction,
    Script,
    PublicKey,
) {
    run_case_with_taproot_change(
        version,
        is_p2wsh,
        extra_outputs,
        legacy_input,
        proof_case,
        multiple_inputs,
        false,
    )
}

fn run_case_with_taproot_change(
    version: &str,
    is_p2wsh: bool,
    extra_outputs: usize,
    legacy_input: bool,
    proof_case: ProofCase,
    multiple_inputs: bool,
    taproot_change: bool,
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
    let (tap_internal_key, _) = public.inner.x_only_public_key();
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
        let script_pubkey = if index == 0 && taproot_change {
            Script::new_v1_p2tr(&secp, tap_internal_key, None)
        } else if index == 0 || (!is_p2wsh && index == 2) {
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
    let mut previous_txs = vec![funding];
    if multiple_inputs {
        let nested = Address::p2shwpkh(&public, Network::Bitcoin).unwrap();
        previous_txs.push(funding_transaction(nested.script_pubkey(), 2_600));
    }
    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: previous_txs
            .iter()
            .enumerate()
            .map(|(index, funding)| TxIn {
                previous_output: OutPoint {
                    txid: funding.txid(),
                    vout: 2,
                },
                sequence: Sequence(0xfffffffd - index as u32),
                ..TxIn::default()
            })
            .collect(),
        output: outputs,
    };
    let mut signatures = Vec::new();
    let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    if taproot_change {
        psbt.outputs[1].tap_internal_key = Some(tap_internal_key);
        psbt.outputs[1].tap_key_origins.insert(
            tap_internal_key,
            (
                Vec::new(),
                (Default::default(), TAPROOT_CHANGE_PATH.parse().unwrap()),
            ),
        );
    } else if extra_outputs > 0 && !legacy_input {
        psbt.outputs[1].bip32_derivation.insert(
            public.inner,
            (Default::default(), PSBT_CHANGE_PATH.parse().unwrap()),
        );
    }
    if extra_outputs > 1 {
        // Well-formed metadata must still match the output script.
        psbt.outputs[2].bip32_derivation.insert(
            public.inner,
            (Default::default(), PSBT_CHANGE_PATH.parse().unwrap()),
        );
    }
    if !is_p2wsh && extra_outputs > 2 {
        psbt.outputs[3].bip32_derivation.insert(
            public.inner,
            (Default::default(), OTHER_PSBT_CHANGE_PATH.parse().unwrap()),
        );
    }
    let script_code = Address::p2wpkh(&public, Network::Bitcoin)
        .unwrap()
        .script_pubkey()
        .p2wpkh_script_code()
        .unwrap();
    for (index, funding) in previous_txs.into_iter().enumerate() {
        let input_value = funding.output[2].value;
        let sighash = if legacy_input {
            SighashCache::new(&tx)
                .legacy_signature_hash(index, &input_script, EcdsaSighashType::All.to_u32())
                .unwrap()
        } else {
            SighashCache::new(&tx)
                .segwit_signature_hash(index, &script_code, input_value, EcdsaSighashType::All)
                .unwrap()
        };
        signatures.push(
            secp.sign_ecdsa(&Message::from_slice(&sighash[..]).unwrap(), &signing_key)
                .serialize_compact(),
        );
        psbt.inputs[index].witness_utxo = Some(funding.output[2].clone());
        psbt.inputs[index].non_witness_utxo = Some(funding);
    }
    match proof_case {
        ProofCase::Missing => psbt.inputs[0].non_witness_utxo = None,
        ProofCase::WrongTxid => psbt.inputs[0].non_witness_utxo.as_mut().unwrap().version = 1,
        ProofCase::WrongVout => psbt.unsigned_tx.input[0].previous_output.vout = 4,
        ProofCase::MismatchedOutput => psbt.inputs[0].witness_utxo.as_mut().unwrap().value += 1,
        _ => {}
    }
    KEY_MANAGER.lock().pri_key = vec![2; 32];
    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let capture = Arc::clone(&records);
    let version = version.to_owned();
    let uncompressed = public.inner.serialize_uncompressed();
    let mut proof_index = 0;
    let mut signature_index = 0;
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
                0x53 => proof_response(&bytes, proof_case, &mut proof_index),
                0x50 => "9000".to_string(),
                0x54 => {
                    let expected_timeout = if bytes[3] == 2 { 120 } else { 20 };
                    assert_eq!(timeout, expected_timeout);
                    change_hint_response(proof_case)
                }
                0x52 => {
                    let expected_timeout = if bytes[3] == 0x80 { 120 } else { 20 };
                    assert_eq!(timeout, expected_timeout);
                    "9000".to_string()
                }
                0x32 | 0x45 => {
                    let signature = signatures[signature_index];
                    signature_index += 1;
                    format!("00{}009000", hex::encode(signature))
                }
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
        let (result, trace, _, _, _) =
            run_case("1.6.12", is_p2wsh, 0, false, ProofCase::Valid, false);
        assert_eq!(result.err().unwrap().to_string(), "upgrade_applet");
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x4b, 0x4c, 0x52, 0x53, 0x54, 0x32].contains(&apdu[1])));
    }
}

#[test]
fn psbt_sends_all_outputs_in_order_and_signs_only_after_confirmation() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (is_p2wsh, extra_outputs) in [(false, 0), (true, 1), (true, 5), (false, 5)] {
        let (result, trace, unsigned, input_script, public) = run_case(
            "1.6.13",
            is_p2wsh,
            extra_outputs,
            false,
            ProofCase::Valid,
            false,
        );
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
        let mut hints = Vec::new();
        if extra_outputs > 0 {
            hints.push((1, PSBT_CHANGE_PATH));
        }
        if !is_p2wsh && extra_outputs > 2 {
            hints.push((3, OTHER_PSBT_CHANGE_PATH));
        }
        assert_change_hints(&trace, 0x52, &hints);
        assert_sign_receipt(&trace[sign], 0, unsigned.input[0].previous_output);
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
    let (result, trace, _, _, _) = run_case("1.6.13", true, 14, false, ProofCase::Valid, false);
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
        run_case("1.6.13", true, 1, true, ProofCase::Valid, false);
    assert!(result.is_ok());
    let preview = trace.iter().rposition(|apdu| apdu[1] == 0x52).unwrap();
    let hash = trace.iter().position(|apdu| apdu[1] == 0x50).unwrap();
    let sign = trace.iter().position(|apdu| apdu[1] == 0x45).unwrap();
    assert!(preview < hash && hash < sign);
    let sign_apdu = &trace[sign];
    assert_eq!(
        &sign_apdu[5..5 + sign_apdu[4] as usize],
        format!("{}/0/0", ACCOUNT).as_bytes()
    );
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
        let (result, trace, _, _, _) = run_case("1.6.13", false, 0, false, fixture, false);
        assert!(result.err().unwrap().to_string().contains(expected));
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x53, 0x54, 0x52, 0x32].contains(&apdu[1])));
    }
}

fn run_ordinary(
    version: &str,
    is_p2wsh: bool,
    proof_case: ProofCase,
    multiple_inputs: bool,
) -> (
    anyhow::Result<coin_bitcoin::common::TxSignResult>,
    Vec<Vec<u8>>,
    Script,
) {
    run_ordinary_with_change_index(version, is_p2wsh, proof_case, multiple_inputs, None)
}

fn run_ordinary_with_change_index(
    version: &str,
    is_p2wsh: bool,
    proof_case: ProofCase,
    multiple_inputs: bool,
    change_idx: Option<u32>,
) -> (
    anyhow::Result<coin_bitcoin::common::TxSignResult>,
    Vec<Vec<u8>>,
    Script,
) {
    run_ordinary_with_change_mode(
        version,
        is_p2wsh,
        proof_case,
        multiple_inputs,
        change_idx,
        false,
    )
}

fn run_ordinary_with_change_mode(
    version: &str,
    is_p2wsh: bool,
    proof_case: ProofCase,
    multiple_inputs: bool,
    change_idx: Option<u32>,
    taproot_change: bool,
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
    let mut previous_txs = vec![funding_transaction(input.script_pubkey(), 6000)];
    let mut sources = vec![input.clone()];
    if multiple_inputs {
        let nested = Address::p2shwpkh(&public, Network::Bitcoin).unwrap();
        previous_txs.push(funding_transaction(nested.script_pubkey(), 2_600));
        sources.push(nested);
    }
    let mut outputs = vec![TxOut {
        value: 5000,
        script_pubkey: dest.script_pubkey(),
    }];
    if multiple_inputs {
        outputs.push(TxOut {
            value: 2600,
            script_pubkey: input.script_pubkey(),
        });
    }
    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: previous_txs
            .iter()
            .map(|funding| TxIn {
                previous_output: OutPoint {
                    txid: funding.txid(),
                    vout: 2,
                },
                ..TxIn::default()
            })
            .collect(),
        output: outputs,
    };
    let mut signatures = Vec::new();
    let script_code = input.script_pubkey().p2wpkh_script_code().unwrap();
    for (index, previous_tx) in previous_txs.iter().enumerate() {
        let sighash = SighashCache::new(&tx)
            .segwit_signature_hash(
                index,
                &script_code,
                previous_tx.output[2].value,
                EcdsaSighashType::All,
            )
            .unwrap();
        signatures.push(
            secp.sign_ecdsa(&Message::from_slice(&sighash[..]).unwrap(), &signing_key)
                .serialize_compact(),
        );
    }
    KEY_MANAGER.lock().pri_key = vec![2; 32];
    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let capture = Arc::clone(&records);
    let version = version.to_owned();
    let uncompressed = public.inner.serialize_uncompressed();
    let mut proof_index = 0;
    let mut signature_index = 0;
    ikc_transport::p2wsh_test_mock::install(Box::new(move |apdu, timeout| {
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
            0x53 => proof_response(&bytes, proof_case, &mut proof_index),
            0x41 => "9000".to_string(),
            0x54 => {
                let expected_timeout = if bytes[3] == 2 { 120 } else { 20 };
                assert_eq!(timeout, expected_timeout);
                change_hint_response(proof_case)
            }
            0x32 => {
                let signature = signatures[signature_index];
                signature_index += 1;
                format!("00{}009000", hex::encode(signature))
            }
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
        unspents: tx
            .input
            .iter()
            .zip(&previous_txs)
            .zip(&sources)
            .map(|((txin, previous_tx), source)| Utxo {
                txhash: txin.previous_output.txid.to_string(),
                vout: if matches!(proof_case, ProofCase::WrongVout) {
                    4
                } else {
                    2
                },
                amount: previous_tx.output[2].value
                    + u64::from(matches!(proof_case, ProofCase::MismatchedOutput)),
                address: source.to_string(),
                script_pubkey: hex::encode(source.script_pubkey().as_bytes()),
                derive_path: format!("{}/0/0", ACCOUNT),
                sequence: 0xffffffff,
            })
            .collect(),
    };
    if matches!(proof_case, ProofCase::WrongTxid) {
        previous_txs[0].version = 1;
    }
    let previous_transactions = if matches!(proof_case, ProofCase::Missing) {
        vec![]
    } else {
        previous_txs.iter().map(serialize).collect()
    };
    let result = transfer.sign_transaction_with_previous_transactions(
        "MAINNET",
        if taproot_change {
            TAPROOT_ACCOUNT
        } else {
            ACCOUNT
        },
        change_idx,
        None,
        if taproot_change {
            "VERSION_1"
        } else {
            "VERSION_0"
        },
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
    let (old, old_trace, _) = run_ordinary("1.6.12", true, ProofCase::Valid, false);
    assert!(old.is_err());
    assert!(!old_trace
        .iter()
        .any(|a| [0x31, 0x53, 0x54, 0x41, 0x32].contains(&a[1])));
    for version in ["1.6.13", "1.10.0"] {
        let (result, trace, expected) = run_ordinary(version, true, ProofCase::Valid, false);
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
        assert_change_hints(&trace, 0x41, &[]);
        assert_sign_receipt(&trace[sign], 0, tx.input[0].previous_output);
        let proved = checked_proof(&trace, tx.input[0].previous_output, tx.input[0].sequence);
        assert_eq!(proved.output[2].value, 6000);
        assert_eq!(proved.output[2].script_pubkey, input_script);
        let raw = extract_signed_body(&trace[preview]);
        assert_eq!(&raw[raw.len() - 9..raw.len() - 1], &[0; 8]);
        assert!(extract_signed_body(&trace[preview])
            .windows(expected.len())
            .any(|w| w == expected.as_bytes()));
    }
    let (old_other, trace, _) = run_ordinary("1.6.12", false, ProofCase::Valid, false);
    assert!(old_other.is_err());
    assert!(!trace
        .iter()
        .any(|a| [0x31, 0x53, 0x54, 0x41, 0x32].contains(&a[1])));
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
        let (result, trace, _) = run_ordinary("1.6.13", false, fixture, false);
        assert!(result.err().unwrap().to_string().contains(expected));
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x53, 0x54, 0x41, 0x32].contains(&apdu[1])));
    }
}

#[test]
fn each_input_receipt_is_returned_on_native_and_nested_segwit_signatures() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (result, trace, unsigned, _, _) =
        run_case("1.6.13", false, 0, false, ProofCase::Valid, true);
    let signed: Psbt = deserialize(&hex::decode(result.unwrap().psbt).unwrap()).unwrap();
    let finalized = signed.extract_tx();
    assert!(finalized.input[0].script_sig.is_empty());
    assert!(!finalized.input[1].script_sig.is_empty());
    assert_matching_receipts(&trace, &unsigned);

    let (result, trace, _) = run_ordinary("1.6.13", false, ProofCase::Valid, true);
    let signed: Transaction =
        deserialize(&hex::decode(result.unwrap().signature).unwrap()).unwrap();
    assert!(signed.input[0].script_sig.is_empty());
    assert!(!signed.input[1].script_sig.is_empty());
    assert_matching_receipts(&trace, &signed);
}

#[test]
fn ordinary_uses_the_path_of_the_actual_change_output() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (change_idx, expected_path) in [(None, "m/84'/0'/0'/0/0"), (Some(19), "m/84'/0'/0'/1/19")] {
        let (result, trace, _) =
            run_ordinary_with_change_index("1.6.13", false, ProofCase::Valid, true, change_idx);
        let signed: Transaction =
            deserialize(&hex::decode(result.unwrap().signature).unwrap()).unwrap();
        assert_eq!(signed.output.len(), 2);
        assert_eq!(signed.output[1].value, 2600);
        assert_change_hints(&trace, 0x41, &[(1, expected_path)]);
    }
}

fn assert_change_hints(trace: &[Vec<u8>], preview_ins: u8, candidates: &[(u8, &str)]) {
    let proof_end = trace.iter().rposition(|apdu| apdu[1] == 0x53).unwrap();
    let preview = trace
        .iter()
        .position(|apdu| apdu[1] == preview_ins)
        .unwrap();
    let hints = &trace[proof_end + 1..preview];
    assert_eq!(hints.len(), candidates.len() + 1);
    for (apdu, (index, path)) in hints.iter().zip(candidates) {
        assert_eq!(&apdu[..4], &[0x80, 0x54, *index, 0]);
        let raw = extract_signed_body(apdu);
        assert_eq!(&raw[..2], &[*index, 0]);
        assert_eq!(&raw[2..], path.as_bytes());
        assert_host_signature(apdu);
    }
    let end = hints.last().unwrap();
    assert_eq!(&end[..4], &[0x80, 0x54, 0xff, 0x80]);
    assert_eq!(extract_signed_body(end), &[0xff, 0x80, 0]);
    assert_host_signature(end);
}

fn assert_matching_receipts(trace: &[Vec<u8>], tx: &Transaction) {
    let first_proof_chunks: Vec<_> = trace
        .iter()
        .filter(|apdu| apdu[1] == 0x53 && apdu[2] == 0)
        .collect();
    let signatures: Vec<_> = trace.iter().filter(|apdu| apdu[1] == 0x32).collect();
    assert_eq!(first_proof_chunks.len(), 2);
    assert_eq!(signatures.len(), 2);
    for (index, input) in tx.input.iter().enumerate() {
        let proof = extract_signed_body(first_proof_chunks[index]);
        assert_eq!(&proof[2..4], &[2, index as u8]);
        assert_eq!(&proof[4..40], serialize(&input.previous_output));
        assert_sign_receipt(signatures[index], index as u8, input.previous_output);
    }
    assert_eq!(signatures[0][2], 0);
    assert_eq!(signatures[1][2], 0x80);
}

#[test]
fn receipt_protocol_errors_stop_ordinary_and_psbt_before_preview() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (fixture, expected) in [
        (
            ProofCase::OldAppletWithoutReceipt,
            "btc_input_proof_receipt_missing",
        ),
        (ProofCase::InvalidReceipt, "btc_input_proof_invalid_receipt"),
        (
            ProofCase::UnexpectedIntermediateData,
            "btc_input_proof_unexpected_response_data",
        ),
    ] {
        let (ordinary, trace, _) = run_ordinary("1.6.13", false, fixture, false);
        assert!(ordinary.err().unwrap().to_string().contains(expected));
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x54, 0x41, 0x32].contains(&apdu[1])));

        let (psbt, trace, _, _, _) = run_case("1.6.13", false, 0, false, fixture, false);
        assert!(psbt.err().unwrap().to_string().contains(expected));
        assert!(!trace
            .iter()
            .any(|apdu| [0x31, 0x54, 0x52, 0x32].contains(&apdu[1])));
    }

    let (legacy, trace, _, _, _) = run_case(
        "1.6.13",
        false,
        0,
        true,
        ProofCase::OldAppletWithoutReceipt,
        false,
    );
    assert!(legacy
        .err()
        .unwrap()
        .to_string()
        .contains("btc_input_proof_receipt_missing"));
    assert!(!trace
        .iter()
        .any(|apdu| [0x52, 0x50, 0x45].contains(&apdu[1])));
}

#[test]
fn missing_change_hint_protocol_stops_before_transaction_review() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (ordinary, trace, _) =
        run_ordinary("1.6.13", false, ProofCase::UnsupportedChangeHints, false);
    assert_eq!(
        ordinary.err().unwrap().to_string(),
        "imkey_applet_function_not_supported"
    );
    assert_eq!(&trace.last().unwrap()[1..4], &[0x54, 0xff, 0x80]);
    assert!(!trace.iter().any(|apdu| [0x41, 0x32].contains(&apdu[1])));

    let (psbt, trace, _, _, _) = run_case(
        "1.6.13",
        false,
        0,
        false,
        ProofCase::UnsupportedChangeHints,
        false,
    );
    assert_eq!(
        psbt.err().unwrap().to_string(),
        "imkey_applet_function_not_supported"
    );
    assert_eq!(&trace.last().unwrap()[1..4], &[0x54, 0xff, 0x80]);
    assert!(!trace.iter().any(|apdu| [0x52, 0x32].contains(&apdu[1])));
}

#[test]
fn mock_transport_without_handler_fails_closed() {
    let _guard = TEST_LOCK.lock().unwrap();
    ikc_transport::p2wsh_test_mock::clear();
    let err = ikc_transport::message::send_apdu("00".to_owned()).unwrap_err();
    assert_eq!(err.to_string(), "offline APDU mock is not installed");
    assert!(ikc_transport::hid_api::hid_connect("imKey Pro").is_err());
}

#[derive(Clone, Copy)]
enum MultisigCase {
    Complete,
    NoGlobalKeys,
    MixedInputWallets,
    UnsupportedPolicyCommand,
}

struct MultisigMock {
    psbt: Psbt,
    funding: Vec<Transaction>,
    account_keys: Vec<bitcoin::util::bip32::ExtendedPubKey>,
    witness_scripts: Vec<Script>,
    signing_keys: Vec<PublicKey>,
    applet_signature: Vec<[u8; 64]>,
    account: bitcoin::util::bip32::DerivationPath,
}

fn wallet_fixture(nested: bool, case: MultisigCase, pre_sign: bool) -> MultisigMock {
    use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::EcdsaSig;

    let secp = Secp256k1::new();
    let wrapper = if nested { 1 } else { 2 };
    let account: DerivationPath = format!("m/48'/0'/0'/{}'", wrapper).parse().unwrap();
    let masters: Vec<_> = [0x11, 0x22, 0x33, 0x44]
        .iter()
        .map(|seed| ExtendedPrivKey::new_master(Network::Bitcoin, &[*seed; 32]).unwrap())
        .collect();
    let roots: Vec<_> = masters
        .iter()
        .map(|master| master.derive_priv(&secp, &account).unwrap())
        .collect();
    let root_keys: Vec<_> = roots
        .iter()
        .map(|root| ExtendedPubKey::from_priv(&secp, root))
        .collect();
    let child_keys = |branch: u8, index: u32, third_cosigner: usize| {
        let suffix: DerivationPath = format!("m/{}/{}", branch, index).parse().unwrap();
        [0, 1, third_cosigner]
            .iter()
            .map(|&owner| {
                let child = roots[owner].derive_priv(&secp, &suffix).unwrap();
                let key = ExtendedPubKey::from_priv(&secp, &child).public_key;
                let path = account.extend(&suffix);
                (
                    key,
                    masters[owner].fingerprint(&secp),
                    path,
                    child.private_key,
                )
            })
            .collect::<Vec<_>>()
    };
    let wallet_script = |keys: &[(_, _, _, _)]| {
        let mut keys: Vec<secp256k1::PublicKey> = keys.iter().map(|(key, _, _, _)| *key).collect();
        keys.sort_unstable_by_key(secp256k1::PublicKey::serialize);
        let mut witness_bytes = vec![0x52];
        for key in keys {
            witness_bytes.push(33);
            witness_bytes.extend(key.serialize());
        }
        witness_bytes.extend([0x53, 0xae]);
        let witness = Script::from(witness_bytes);
        let program = witness.to_v0_p2wsh();
        let (redeem, locking) = if nested {
            (Some(program.clone()), program.to_p2sh())
        } else {
            (None, program)
        };
        (witness, redeem, locking)
    };

    let input_positions = [
        (0, 5, 2),
        (
            1,
            7,
            if matches!(case, MultisigCase::MixedInputWallets) {
                3
            } else {
                2
            },
        ),
    ];
    let output_positions = [(1, 9, 2), (1, 10, 3), (1, 11, 2)];
    let mut funding = Vec::new();
    let mut psbt_inputs = Vec::new();
    let mut tx_inputs = Vec::new();
    let mut input_signers = Vec::new();
    let mut witness_scripts = Vec::new();
    let mut signing_keys = Vec::new();
    for (branch, index, alternate) in input_positions {
        let keys = child_keys(branch, index, alternate);
        let (witness, redeem, locking) = wallet_script(&keys);
        let previous = funding_transaction(locking, 10_000);
        let mut input = bitcoin::psbt::Input::default();
        input.non_witness_utxo = Some(previous.clone());
        input.witness_utxo = Some(previous.output[2].clone());
        input.witness_script = Some(witness.clone());
        input.redeem_script = redeem;
        input.bip32_derivation = keys
            .iter()
            .map(|(pub_key, fingerprint, path, _)| (*pub_key, (*fingerprint, path.clone())))
            .collect();
        input_signers.push([keys[0].3, keys[1].3]);
        signing_keys.push(PublicKey::new(keys[0].0));
        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(previous.txid(), 2),
            sequence: Sequence(0xfffffffd),
            ..TxIn::default()
        });
        psbt_inputs.push(input);
        witness_scripts.push(witness);
        funding.push(previous);
    }

    let recipient = Address::from_str(DEST).unwrap();
    let mut tx_outputs = vec![TxOut {
        value: 5_000,
        script_pubkey: recipient.script_pubkey(),
    }];
    let mut psbt_outputs = vec![bitcoin::psbt::Output::default()];
    for (branch, index, cosigner) in output_positions {
        let keys = child_keys(branch, index, cosigner);
        let (witness, redeem, locking) = wallet_script(&keys);
        tx_outputs.push(TxOut {
            value: 2_000,
            script_pubkey: locking,
        });
        let mut output = bitcoin::psbt::Output::default();
        output.witness_script = Some(witness);
        output.redeem_script = redeem;
        output.bip32_derivation = keys
            .into_iter()
            .map(|(pub_key, fingerprint, path, _)| (pub_key, (fingerprint, path)))
            .collect();
        psbt_outputs.push(output);
    }
    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };
    let mut applet_signature = Vec::new();
    for (index, (input, [card, other])) in psbt_inputs.iter_mut().zip(input_signers).enumerate() {
        let digest = SighashCache::new(&tx)
            .segwit_signature_hash(
                index,
                &witness_scripts[index],
                10_000,
                EcdsaSighashType::All,
            )
            .unwrap();
        let digest = Message::from_slice(&digest[..]).unwrap();
        applet_signature.push(secp.sign_ecdsa(&digest, &card).serialize_compact());
        if pre_sign {
            let other_public = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &other));
            input.partial_sigs.insert(
                other_public,
                EcdsaSig::sighash_all(secp.sign_ecdsa(&digest, &other)),
            );
        }
    }

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    if !matches!(case, MultisigCase::NoGlobalKeys) {
        psbt.xpub = root_keys
            .iter()
            .zip(&masters)
            .map(|(account_key, master)| {
                (*account_key, (master.fingerprint(&secp), account.clone()))
            })
            .collect();
    }
    psbt.inputs = psbt_inputs;
    psbt.outputs = psbt_outputs;
    MultisigMock {
        psbt,
        funding,
        account_keys: root_keys,
        witness_scripts,
        signing_keys,
        applet_signature,
        account,
    }
}

fn run_multisig_psbt(
    fixture: &MultisigMock,
    case: MultisigCase,
) -> (
    anyhow::Result<coin_bitcoin::btcapi::PsbtOutput>,
    Vec<Vec<u8>>,
) {
    KEY_MANAGER.lock().pri_key = vec![2; 32];
    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let capture = Arc::clone(&records);
    let signing_keys = fixture.signing_keys.clone();
    let signatures = fixture.applet_signature.clone();
    let chain_code = fixture.account_keys[0].chain_code;
    let mut xpub_index = 0;
    let mut proof_index = 0;
    let mut signature_index = 0;
    ikc_transport::p2wsh_test_mock::install(Box::new(move |apdu, timeout| {
        let bytes = hex::decode(apdu)?;
        capture.lock().unwrap().push(bytes.clone());
        if bytes[0..2] == [0, 0xa4] {
            return Ok(
                if bytes.len() > 5 && bytes[5..] == [0x69, 0x5f, 0x62, 0x74, 0x63, 0] {
                    "312e362e31339000".to_owned()
                } else {
                    "9000".to_owned()
                },
            );
        }
        Ok(match bytes[1] {
            0x43 => {
                let key = signing_keys[xpub_index].inner.serialize_uncompressed();
                xpub_index += 1;
                format!(
                    "{}{}9000",
                    hex::encode(key),
                    hex::encode(chain_code.as_bytes())
                )
            }
            0x53 => proof_response(&bytes, ProofCase::Valid, &mut proof_index),
            0x55 => {
                assert_eq!(timeout, 120);
                if matches!(case, MultisigCase::UnsupportedPolicyCommand) {
                    "6D00".to_owned()
                } else {
                    "9000".to_owned()
                }
            }
            0x54 | 0x52 => "9000".to_owned(),
            0x32 => {
                let signature = signatures[signature_index];
                signature_index += 1;
                format!("00{}009000", hex::encode(signature))
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected multisig APDU INS {:02x}",
                    other
                ))
            }
        })
    }));
    let result = coin_bitcoin::psbt::sign_psbt(
        &fixture.account.to_string(),
        PsbtInput {
            psbt: hex::encode(serialize(&fixture.psbt)),
            auto_finalize: true,
        },
        Network::Bitcoin,
    );
    ikc_transport::p2wsh_test_mock::clear();
    KEY_MANAGER.lock().pri_key.clear();
    let trace = records.lock().unwrap().clone();
    (result, trace)
}

#[test]
fn psbt_multisig_policy_precedes_preview_and_matches_all_funding_scripts() {
    let _guard = TEST_LOCK.lock().unwrap();
    for nested in [false, true] {
        let fixture = wallet_fixture(nested, MultisigCase::Complete, nested);
        let (result, trace) = run_multisig_psbt(&fixture, MultisigCase::Complete);
        let result: Psbt = deserialize(&hex::decode(result.unwrap().psbt).unwrap()).unwrap();
        let policy: Vec<_> = trace.iter().filter(|a| a[1] == 0x55).collect();
        let start = trace.iter().position(|a| a[1] == 0x55).unwrap();
        let end = trace.iter().rposition(|a| a[1] == 0x55).unwrap();
        let preview = trace.iter().position(|a| a[1] == 0x52).unwrap();
        assert!(trace.iter().take(start).any(|a| a[1] == 0x53));
        assert!(!trace.iter().skip(start).any(|a| a[1] == 0x53));
        assert!(end < trace.iter().position(|a| a[1] == 0x54).unwrap());
        assert!(end < preview);
        for command in &policy {
            assert_host_signature(command);
            assert_eq!(extract_signed_body(command)[..2], command[2..4]);
        }

        let bodies: Vec<_> = policy
            .iter()
            .map(|a| &extract_signed_body(a)[2..])
            .collect();
        assert_eq!(
            policy.iter().map(|a| (a[2], a[3])).collect::<Vec<_>>(),
            vec![
                (255, 0),
                (0, 1),
                (1, 1),
                (2, 1),
                (0, 2),
                (1, 2),
                (1, 3),
                (3, 3),
                (255, 0x80)
            ]
        );
        assert_eq!(&bodies[0][..4], &[0, if nested { 1 } else { 2 }, 2, 3]);
        assert_eq!(&bodies[0][4..], fixture.account.to_string().as_bytes());
        let mut roots = fixture.account_keys[..3].to_vec();
        roots.sort_by_key(|root| root.public_key.serialize());
        for (body, root) in bodies[1..4].iter().zip(roots) {
            assert_eq!(&body[..65], &root.public_key.serialize_uncompressed());
            assert_eq!(&body[65..], root.chain_code.as_bytes());
        }
        assert_eq!(
            bodies[4..],
            [
                &[0, 0, 0, 0, 5][..],
                &[1, 0, 0, 0, 7],
                &[0, 0, 0, 9],
                &[0, 0, 0, 11],
                &[0]
            ]
        );

        let sign_requests: Vec<_> = trace
            .iter()
            .skip(preview)
            .filter(|a| a[1] == 0x32)
            .collect();
        assert_eq!(sign_requests.len(), 2);
        for (index, request) in sign_requests.iter().enumerate() {
            let data = &request[5..];
            let input = &fixture.psbt.unsigned_tx.input[index];
            let prevout = &fixture.funding[index].output[2];
            assert_eq!(&data[1..37], &serialize(&input.previous_output));
            let script = serialize(&fixture.witness_scripts[index]);
            let amount_offset = 37 + script.len();
            assert_eq!(&data[37..amount_offset], &script);
            assert_eq!(
                &data[amount_offset..amount_offset + 8],
                &prevout.value.to_le_bytes()
            );
            let path_offset = 1 + data[0] as usize;
            let path_end = path_offset + 1 + data[path_offset] as usize;
            let expected_path = format!(
                "{}/{}",
                fixture.account,
                if index == 0 { "0/5" } else { "1/7" }
            );
            assert_eq!(&data[path_offset + 1..path_end], expected_path.as_bytes());
            assert_eq!(&data[path_end..path_end + 32], receipt_for(index as u8));
            if nested {
                let witness = result.inputs[index].final_script_witness.as_ref().unwrap();
                assert_eq!(witness.len(), 4);
                assert_eq!(
                    witness.last().unwrap(),
                    fixture.witness_scripts[index].as_bytes()
                );
                assert!(!result.inputs[index]
                    .final_script_sig
                    .as_ref()
                    .unwrap()
                    .is_empty());
                assert!(result.inputs[index].partial_sigs.is_empty());
            } else {
                assert!(result.inputs[index].final_script_witness.is_none());
                assert_eq!(result.inputs[index].partial_sigs.len(), 1);
                assert!(result.inputs[index]
                    .partial_sigs
                    .contains_key(&fixture.signing_keys[index]));
                assert!(result.inputs[index].witness_script.is_some());
                assert_eq!(result.inputs[index].bip32_derivation.len(), 3);
            }
        }
    }
}

#[test]
fn psbt_multisig_missing_global_keys_and_mixed_wallets_are_not_change_policies() {
    let _guard = TEST_LOCK.lock().unwrap();
    for case in [MultisigCase::NoGlobalKeys, MultisigCase::MixedInputWallets] {
        let fixture = wallet_fixture(false, case, false);
        let (result, trace) = run_multisig_psbt(&fixture, case);
        assert!(result.is_ok());
        assert!(!trace.iter().any(|a| a[1] == 0x55));
        assert_eq!(trace.iter().filter(|a| a[1] == 0x54).count(), 1);
        assert_eq!(trace.iter().filter(|a| a[1] == 0x32).count(), 2);
    }
}

#[test]
fn psbt_multisig_fails_before_preview_if_applet_lacks_policy_protocol() {
    let _guard = TEST_LOCK.lock().unwrap();
    let case = MultisigCase::UnsupportedPolicyCommand;
    let fixture = wallet_fixture(false, case, false);
    let (result, trace) = run_multisig_psbt(&fixture, case);
    assert!(result.is_err());
    assert_eq!(trace.iter().filter(|a| a[1] == 0x55).count(), 1);
    assert!(!trace.iter().any(|a| [0x54, 0x52, 0x32].contains(&a[1])));
}

#[test]
fn ordinary_and_psbt_taproot_change_require_device_tweak_command() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (result, ordinary, _) =
        run_ordinary_with_change_mode("1.6.13", false, ProofCase::Valid, true, Some(23), true);
    assert!(result.is_ok(), "{:?}", result.err());
    let (result, psbt, _, _, _) =
        run_case_with_taproot_change("1.6.13", false, 1, false, ProofCase::Valid, false, true);
    assert!(result.is_ok(), "{:?}", result.err());

    for (trace, review) in [(&ordinary, 0x41), (&psbt, 0x52)] {
        let candidate = trace.iter().position(|a| a[1..4] == [0x54, 1, 2]).unwrap();
        assert!(candidate > trace.iter().rposition(|a| a[1] == 0x53).unwrap());
        assert_eq!(trace[candidate + 1][1..4], [0x54, 0xff, 0x80]);
        assert!(candidate < trace.iter().position(|a| a[1] == review).unwrap());
        assert_eq!(
            &extract_signed_body(&trace[candidate])[2..],
            TAPROOT_CHANGE_PATH.as_bytes()
        );
        assert_host_signature(&trace[candidate]);
    }

    let (result, trace, _, _, _) = run_case_with_taproot_change(
        "1.6.13",
        false,
        1,
        false,
        ProofCase::UnsupportedChangeHints,
        false,
        true,
    );
    assert!(result.is_err());
    assert!(trace.iter().any(|a| a[1..4] == [0x54, 1, 2]));
    assert!(!trace.iter().any(|a| [0x52, 0x32].contains(&a[1])));
}

#[test]
fn psbt_multisig_rejects_non_all_sighash_before_review() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut fixture = wallet_fixture(false, MultisigCase::Complete, false);
    fixture.psbt.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());
    let (result, trace) = run_multisig_psbt(&fixture, MultisigCase::Complete);
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("psbt_unsupported_multisig_sighash"));
    assert!(!trace
        .iter()
        .any(|a| [0x53, 0x55, 0x54, 0x52, 0x32].contains(&a[1])));
}

#[test]
fn invalid_multisig_partial_signature_cannot_trigger_autofinalization() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut fixture = wallet_fixture(false, MultisigCase::Complete, true);
    // Move an otherwise valid signature from another input into this input.
    let wrong_signature = *fixture.psbt.inputs[1].partial_sigs.values().next().unwrap();
    *fixture.psbt.inputs[0]
        .partial_sigs
        .values_mut()
        .next()
        .unwrap() = wrong_signature;
    let (result, _) = run_multisig_psbt(&fixture, MultisigCase::Complete);
    let result: Psbt = deserialize(&hex::decode(result.unwrap().psbt).unwrap()).unwrap();
    assert!(result.inputs[0].final_script_witness.is_none());
    assert_eq!(result.inputs[0].partial_sigs.len(), 2);
    assert!(result.inputs[1].final_script_witness.is_some());
}
