//! Exercises the production synchronous PSBT path against an in-process APDU
//! substitute. The substitute cannot open HID or connect to a real device.
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::psbt::Psbt;
use bitcoin::util::sighash::SighashCache;
use bitcoin::{
    Address, EcdsaSighashType, Network, PackedLockTime, PublicKey, Script, Transaction, TxIn, TxOut,
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

fn run_case(
    version: &str,
    is_p2wsh: bool,
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
    let input_script = Address::p2wpkh(&public, Network::Bitcoin)
        .unwrap()
        .script_pubkey();
    let recipient = if is_p2wsh {
        Address::from_str(DEST).unwrap().script_pubkey()
    } else {
        let other = SecretKey::from_slice(&[3; 32]).unwrap();
        let other_public = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &other));
        Address::p2wpkh(&other_public, Network::Bitcoin)
            .unwrap()
            .script_pubkey()
    };
    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: 5000,
            script_pubkey: recipient,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: 6000,
        script_pubkey: input_script.clone(),
    });
    let sighash = SighashCache::new(&tx)
        .segwit_signature_hash(
            0,
            &input_script.p2wpkh_script_code().unwrap(),
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
        let response = if bytes[0..2] == [0, 0xa4] {
            if bytes.len() > 5 && bytes[5..] == [0x69, 0x5f, 0x62, 0x74, 0x63, 0] {
                format!("{}9000", hex::encode(version.as_bytes()))
            } else {
                "9000".to_string()
            }
        } else {
            match bytes[1] {
                0x43 => format!("{}{}9000", hex::encode(uncompressed), "00".repeat(32)),
                0x31 | 0x4b | 0x4c => "9000".to_string(),
                0x32 => format!("00{}009000", hex::encode(signature)),
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
fn sign_psbt_p2wsh_gates_old_applet_and_previews_new_applet() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (old, old_trace, _, _, _) = run_case("1.6.11", true);
    assert!(old.is_err());
    assert!(!old_trace
        .iter()
        .any(|a| [0x31, 0x4b, 0x4c, 0x32].contains(&a[1])));

    let (result, trace, unsigned, input_script, public) = run_case("1.6.12", true);
    let result = result.unwrap();
    let signed: Psbt = deserialize(&hex::decode(result.psbt).unwrap()).unwrap();
    let tx = signed.extract_tx();
    assert_eq!(tx.output, unsigned.output);
    assert!(tx.output[0].script_pubkey.is_v0_p2wsh());
    let witness = tx.input[0].witness.to_vec();
    let sig = secp256k1::ecdsa::Signature::from_der(&witness[0][..witness[0].len() - 1]).unwrap();
    let hash = SighashCache::new(&tx)
        .segwit_signature_hash(
            0,
            &input_script.p2wpkh_script_code().unwrap(),
            6000,
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

    let isd = trace
        .iter()
        .position(|a| a == &[0x00, 0xa4, 0x04, 0x00, 0x00])
        .unwrap();
    let after_isd = trace
        .iter()
        .skip(isd + 1)
        .position(|a| a[0..2] == [0, 0xa4])
        .unwrap()
        + isd
        + 1;
    let hash_index = trace.iter().position(|a| a[1] == 0x31).unwrap();
    let prep = trace.iter().position(|a| a[1] == 0x4b).unwrap();
    let preview = trace.iter().position(|a| a[1] == 0x4c).unwrap();
    let sign = trace.iter().position(|a| a[1] == 0x32).unwrap();
    assert!(
        isd < after_isd
            && after_isd < hash_index
            && hash_index < prep
            && prep < preview
            && preview < sign
    );
    assert!(!trace[hash_index..sign].iter().any(|a| a[0..2] == [0, 0xa4]));
    let summary = extract_signed_body(&trace[prep]);
    assert_eq!(
        u64::from_be_bytes(summary[13..21].try_into().unwrap()),
        5000
    );
    assert_eq!(
        u64::from_be_bytes(summary[21..29].try_into().unwrap()),
        1000
    );
    use bitcoin::hashes::{sha256, Hash};
    let outputs_hash = sha256::Hash::hash(&serialize(&unsigned.output[0]));
    assert_eq!(&summary[29..61], &outputs_hash[..]);
    assert_eq!(&summary[61..63], &[0, 1]);
    let page = extract_signed_body(&trace[preview]);
    assert_eq!(&page[..6], &[0, 0, 0, 0, 0, 0]);
    assert_eq!(u64::from_le_bytes(page[6..14].try_into().unwrap()), 5000);
    assert_eq!(page[15], b'b');
    assert_eq!(page[16], 34);
    assert_eq!(&page[17..51], tx.output[0].script_pubkey.as_bytes());
}

#[test]
fn old_applet_non_p2wsh_psbt_keeps_existing_path() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (result, trace, _, _, _) = run_case("1.6.11", false);
    assert!(result.is_ok());
    assert!(!trace.iter().any(|a| a == &[0, 0xa4, 0x04, 0, 0]));
    assert!(trace.iter().any(|a| a[1] == 0x4c));
}

fn run_ordinary(
    version: &str,
    is_p2wsh: bool,
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
    let prevout = bitcoin::OutPoint {
        txid: bitcoin::Txid::from_str(&"00".repeat(32)).unwrap(),
        vout: 0,
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
            0x31 | 0x41 => "9000".to_string(),
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
            txhash: "00".repeat(32),
            vout: 0,
            amount: 6000,
            address: input.to_string(),
            script_pubkey: hex::encode(input.script_pubkey().as_bytes()),
            derive_path: format!("{}/0/0", ACCOUNT),
            sequence: 0xffffffff,
        }],
    };
    let result = transfer.sign_transaction("MAINNET", ACCOUNT, None, None, "VERSION_0");
    ikc_transport::p2wsh_test_mock::clear();
    KEY_MANAGER.lock().pri_key.clear();
    let transcript = records.lock().unwrap().clone();
    (result, transcript, dest.script_pubkey())
}

#[test]
fn ordinary_gate_versions_and_legacy_non_p2wsh() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (old, old_trace, _) = run_ordinary("1.6.11", true);
    assert!(old.is_err());
    assert!(!old_trace.iter().any(|a| [0x31, 0x41, 0x32].contains(&a[1])));
    for version in ["1.6.12", "1.10.0"] {
        let (result, trace, expected) = run_ordinary(version, true);
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
        let ins31: Vec<_> = trace
            .iter()
            .filter(|a| a[1] == 0x31)
            .map(|a| a[2])
            .collect();
        assert_eq!(ins31, vec![0x40, 0x80, 0x20, 0x21]);
        let hash = trace.iter().position(|a| a[1] == 0x31).unwrap();
        let preview = trace.iter().position(|a| a[1] == 0x41).unwrap();
        let sign = trace.iter().position(|a| a[1] == 0x32).unwrap();
        assert!(hash < preview && preview < sign);
        assert!(extract_signed_body(&trace[preview])
            .windows(expected.len())
            .any(|w| w == expected.as_bytes()));
    }
    let (old_other, trace, _) = run_ordinary("1.6.11", false);
    assert!(old_other.is_ok());
    assert!(trace.iter().any(|a| a[1] == 0x41));
}

#[test]
fn mock_transport_without_handler_fails_closed() {
    let _guard = TEST_LOCK.lock().unwrap();
    ikc_transport::p2wsh_test_mock::clear();
    let err = ikc_transport::message::send_apdu("00".to_owned()).unwrap_err();
    assert_eq!(err.to_string(), "offline APDU mock is not installed");
    assert!(ikc_transport::hid_api::hid_connect("imKey Pro").is_err());
}
