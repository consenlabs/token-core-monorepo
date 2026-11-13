use super::*;
use bitcoin::{PackedLockTime, Transaction, TxIn};
use std::convert::TryInto;

fn output(script: &str, value: u64) -> TxOut {
    TxOut {
        value,
        script_pubkey: Script::from(hex::decode(script).unwrap()),
    }
}

fn make_psbt(outputs: Vec<TxOut>, input_value: u64) -> Psbt {
    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn::default()],
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: input_value,
        script_pubkey: Script::new(),
    });
    psbt
}

#[test]
fn version_gate_fails_closed_for_old_or_unknown_firmware() {
    let p2wsh = output(&format!("0020{}", "11".repeat(32)), 1000);
    let p2tr = output(&format!("5120{}", "11".repeat(32)), 1000);
    for version in [
        "1.6.11",
        "1.6.9",
        "1.6.0",
        "1.+6.12",
        "1.6.4294967296",
        "",
        "1.6",
        "1.6.12-extra",
        "1.6.12.1",
        "banana",
    ] {
        assert!(
            ensure_p2wsh_preview_supported(&[p2wsh.clone()], || Ok(version.to_string())).is_err(),
            "{}",
            version
        );
    }
    for version in ["1.6.12", "1.6.13", "1.7.0", "1.10.0", "2.0.0"] {
        assert!(
            ensure_p2wsh_preview_supported(&[p2wsh.clone()], || Ok(version.to_string())).is_ok(),
            "{}",
            version
        );
    }
    assert!(ensure_p2wsh_preview_supported(&[p2wsh], || Err(anyhow!("read failed"))).is_err());
    // Existing non-P2WSH transactions do not query the applet version.
    assert!(ensure_p2wsh_preview_supported(&[p2tr], || panic!("unexpected version query")).is_ok());
}

#[test]
fn preview_requires_earlier_successful_version_check() {
    let a = output(&format!("0020{}", "11".repeat(32)), 1000);
    let mut psbt = make_psbt(vec![a], 2000);
    let signer = PsbtSigner::new(&mut psbt, "m/84'/0'/0'", false, Network::Bitcoin, false).unwrap();
    let error = signer.tx_preview(Network::Bitcoin).unwrap_err();
    assert!(error.to_string().contains("upgrade"));
}

#[test]
fn p2wsh_cannot_sign_without_successful_preview() {
    let a = output(&format!("0020{}", "11".repeat(32)), 1000);
    let mut psbt = make_psbt(vec![a], 2000);
    let mut signer =
        PsbtSigner::new(&mut psbt, "m/84'/0'/0'", false, Network::Bitcoin, false).unwrap();
    assert_eq!(
        signer.sign(&vec![]).unwrap_err().to_string(),
        "imkey_user_not_confirmed"
    );
    assert!(signer.tx_preview(Network::Bitcoin).is_err());
    assert_eq!(
        signer.sign(&vec![]).unwrap_err().to_string(),
        "imkey_user_not_confirmed"
    );
}

#[test]
fn p2wsh_outputs_are_included_in_amount_and_preserve_order() {
    let a = output(&format!("0020{}", "11".repeat(32)), 1000);
    let b = output(&format!("0020{}", "22".repeat(32)), 2000);
    let op_return = output("6a00", 0);
    for network in [Network::Bitcoin, Network::Testnet] {
        let mut psbt = make_psbt(vec![a.clone(), op_return.clone(), b.clone()], 4000);
        let mut signer = PsbtSigner::new(&mut psbt, "m/84'/0'/0'", false, network, false).unwrap();
        signer.prevouts().unwrap();
        let (total, fee, outputs) = signer.get_preview_info().unwrap();
        assert_eq!((total, fee), (3000, 1000));
        assert_eq!(outputs, vec![a.clone(), b.clone()]);
    }
}

#[test]
fn p2wsh_records_keep_v0_and_paginate_with_other_types() {
    let a = output(&format!("0020{}", "11".repeat(32)), 1000);
    let b = output(&format!("0014{}", "44".repeat(20)), 2000);
    let c = output(&format!("5120{}", "55".repeat(32)), 3000);
    let d = output(&format!("0020{}", "22".repeat(32)), 4000);
    let expected = vec![a.clone(), b, c, d.clone()];
    for (network, prefix) in [(Network::Bitcoin, b'b'), (Network::Testnet, b't')] {
        let mut psbt = make_psbt(expected.clone(), 11000);
        // Isolate page encoding from the unrelated device-derived change lookup.
        let signer = PsbtSigner {
            psbt: &mut psbt,
            derivation_path: String::new(),
            auto_finalize: false,
            prevouts: vec![],
            network,
            preview_output: expected.clone(),
            is_sign_message: false,
            p2wsh_preview_state: Mutex::new(P2wshPreviewState::default()),
        };
        for (page, indexes) in [(0, vec![0usize, 1, 2]), (1, vec![3usize])] {
            let bytes = signer.serizalize_page_data(page, network).unwrap();
            assert_eq!(
                u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
                indexes[0]
            );
            assert_eq!(
                u16::from_be_bytes([bytes[2], bytes[3]]) as usize,
                *indexes.last().unwrap()
            );
            let mut at = 4;
            for idx in indexes {
                assert_eq!(u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize, idx);
                assert_eq!(
                    u64::from_le_bytes(bytes[at + 2..at + 10].try_into().unwrap()),
                    expected[idx].value
                );
                let envelope = bytes[at + 10] as usize;
                assert_eq!(bytes[at + 11], prefix);
                let script_len = bytes[at + 12] as usize;
                assert_eq!(envelope, script_len + 2);
                assert_eq!(
                    &bytes[at + 13..at + 13 + script_len],
                    expected[idx].script_pubkey.as_bytes()
                );
                at += 11 + envelope;
            }
            assert_eq!(at, bytes.len());
        }
        assert!(signer.serizalize_page_data(2, network).is_err());
    }
}

#[test]
fn signer_preserves_sync_trait() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<PsbtSigner<'static>>();
}

#[test]
fn poisoned_p2wsh_state_fails_closed() {
    let a = output(&format!("0020{}", "11".repeat(32)), 1000);
    let mut psbt = make_psbt(vec![a], 2000);
    let mut signer =
        PsbtSigner::new(&mut psbt, "m/84'/0'/0'", false, Network::Bitcoin, false).unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = signer.p2wsh_preview_state.lock().unwrap();
        panic!("simulate interrupted P2WSH operation");
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
