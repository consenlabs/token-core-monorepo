use super::*;
use bitcoin::{OutPoint, PackedLockTime, Transaction, TxIn};

fn output(script: &str, value: u64) -> TxOut {
    TxOut {
        value,
        script_pubkey: Script::from(hex::decode(script).unwrap()),
    }
}

fn make_psbt(outputs: Vec<TxOut>, input_value: u64) -> Psbt {
    let funding = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: input_value,
            script_pubkey: Script::new(),
        }],
    };
    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding.txid(),
                vout: 0,
            },
            ..TxIn::default()
        }],
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].non_witness_utxo = Some(funding);
    psbt
}

#[test]
fn version_gate_fails_closed_for_old_or_unknown_firmware() {
    for version in [
        "1.6.12",
        "1.6.9",
        "1.6.0",
        "1.+6.13",
        "1.6.4294967296",
        "",
        "1.6",
        "1.6.13-extra",
        "1.6.13.1",
        "banana",
    ] {
        assert!(
            ensure_transaction_preview_version(version).is_err(),
            "{}",
            version
        );
    }
    for version in ["1.6.13", "1.7.0", "1.10.0", "2.0.0"] {
        assert!(
            ensure_transaction_preview_version(version).is_ok(),
            "{}",
            version
        );
    }
}

#[test]
fn all_output_types_require_preparation_and_device_confirmation() {
    let recipient = output(&format!("0020{}", "11".repeat(32)), 1000);
    let mut psbt = make_psbt(vec![recipient], 2000);
    let mut signer =
        PsbtSigner::new(&mut psbt, "m/84'/0'/0'", false, Network::Bitcoin, false).unwrap();
    assert_eq!(
        signer.tx_preview(Network::Bitcoin).unwrap_err().to_string(),
        "imkey_user_not_confirmed"
    );
    assert_eq!(
        signer.sign(&vec![]).unwrap_err().to_string(),
        "imkey_user_not_confirmed"
    );
}

#[test]
fn complete_output_list_preserves_amount_and_order() {
    let outputs = vec![
        output(&format!("0020{}", "11".repeat(32)), 1000),
        output("6a00", 500),
        output(&format!("0020{}", "22".repeat(32)), 2000),
    ];
    for network in [Network::Bitcoin, Network::Testnet] {
        let mut psbt = make_psbt(outputs.clone(), 4000);
        let mut signer = PsbtSigner::new(&mut psbt, "m/84'/0'/0'", false, network, false).unwrap();
        signer.prevouts().unwrap();
        let (total, fee, actual) = signer.get_preview_info().unwrap();
        assert_eq!((total, fee), (3500, 500));
        assert_eq!(actual, outputs);
    }
}

#[test]
fn legacy_bip322_psbt_is_explicitly_unsupported() {
    let mut psbt = make_psbt(vec![output("6a00", 0)], 0);
    let result = PsbtSigner::new(&mut psbt, "m/84'/0'/0'", true, Network::Bitcoin, true);
    assert_eq!(
        result.err().unwrap().to_string(),
        "bip322_signing_requires_a_dedicated_device_protocol"
    );
}

#[test]
fn signer_preserves_sync_trait() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<PsbtSigner<'static>>();
}

#[test]
fn poisoned_preview_state_fails_closed() {
    let a = output(&format!("0020{}", "11".repeat(32)), 1000);
    let mut psbt = make_psbt(vec![a], 2000);
    let mut signer =
        PsbtSigner::new(&mut psbt, "m/84'/0'/0'", false, Network::Bitcoin, false).unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = signer.preview_state.lock().unwrap();
        panic!("simulate interrupted preview");
    }));
    assert_eq!(
        signer.tx_preview(Network::Bitcoin).unwrap_err().to_string(),
        "imkey_user_not_confirmed"
    );
    assert_eq!(
        signer.sign(&vec![]).unwrap_err().to_string(),
        "imkey_user_not_confirmed"
    );
}
