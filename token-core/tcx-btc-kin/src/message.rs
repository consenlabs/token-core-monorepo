use crate::psbt::PsbtSigner;
use crate::transaction::{BtcMessageInput, BtcMessageOutput, BtcSignatureType};
use crate::{BtcKinAddress, Error, Result};
use base64::Engine;
use bitcoin::consensus::serialize as btc_serialize;
use bitcoin::psbt::Psbt;
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf as Script, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use tcx_common::{sha256, utf8_or_hex_to_bytes, FromHex};
use tcx_constants::{CoinInfo, CurveType};
use tcx_keystore::{Address, Keystore, MessageSigner, SignatureParameters, Signer};

const UTXO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TAG: &str = "BIP0322-signed-message";

fn bip137_message_hash(message: &[u8]) -> [u8; 32] {
    let prefix = b"\x18Bitcoin Signed Message:\n";
    let mut data = Vec::new();
    data.extend_from_slice(prefix);

    let len = message.len();
    if len < 0xFD {
        data.push(len as u8);
    } else if len <= 0xFFFF {
        data.push(0xFD);
        data.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        data.push(0xFE);
        data.extend_from_slice(&(len as u32).to_le_bytes());
    }
    data.extend_from_slice(message);

    let first = sha256(&data);
    sha256(&first)
}

fn flag_base_for_bip137(seg_wit: &str) -> Result<u8> {
    match seg_wit {
        "NONE" => Ok(31),
        "P2WPKH" => Ok(35),
        "VERSION_0" => Ok(39),
        _ => Err(Error::Bip137NotSupportedForTaproot.into()),
    }
}

fn sign_message_bip137(
    keystore: &mut Keystore,
    params: &SignatureParameters,
    message: &[u8],
    flag_base: u8,
) -> Result<String> {
    let path = format!("{}/0/0", params.derivation_path);
    let hash = bip137_message_hash(message);
    let sig = keystore.secp256k1_ecdsa_sign_recoverable(&hash, &path)?;

    // sig layout: r(32) + s(32) + recovery_id(1)
    let recovery_id = sig[64];
    let mut compact = Vec::with_capacity(65);
    compact.push(flag_base + recovery_id);
    compact.extend_from_slice(&sig[..64]);

    Ok(base64::engine::general_purpose::STANDARD.encode(&compact))
}

fn get_spend_tx_id(data: &[u8], script_pub_key: Script) -> Result<Txid> {
    let tag_hash = sha256(&TAG.as_bytes().to_vec());
    let mut to_sign = Vec::new();
    to_sign.extend(tag_hash.clone());
    to_sign.extend(tag_hash);
    to_sign.extend(data);

    let hash = sha256(&to_sign);
    let mut script_sig = Vec::new();
    script_sig.extend([0x00, 0x20]);
    script_sig.extend(hash);

    let ins = vec![TxIn {
        previous_output: OutPoint {
            txid: UTXO.parse()?,
            vout: 0xFFFFFFFF,
        },
        script_sig: Script::from(script_sig),
        sequence: Sequence(0),
        witness: Witness::new(),
    }];

    let outs = vec![TxOut {
        value: Amount::from_sat(0),
        script_pubkey: script_pub_key,
    }];

    let tx = Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: ins,
        output: outs,
    };

    Ok(tx.compute_txid())
}

fn create_to_sign_empty(txid: Txid, script_pub_key: Script) -> Result<Psbt> {
    let ins = vec![TxIn {
        previous_output: OutPoint { txid, vout: 0 },
        script_sig: Script::new(),
        sequence: Sequence(0),
        witness: Witness::new(),
    }];

    let outs = vec![TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Script::from(Vec::<u8>::from_hex("6a")?),
    }];

    let tx = Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: ins,
        output: outs,
    };

    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: script_pub_key,
    });

    Ok(psbt)
}

fn witness_to_vec(witness: Vec<Vec<u8>>) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    ret.push(witness.len() as u8);
    for item in witness {
        ret.push(item.len() as u8);
        ret.extend(item);
    }
    ret
}

fn sign_message_bip322_simple(
    keystore: &mut Keystore,
    params: &SignatureParameters,
    data: &[u8],
) -> Result<String> {
    let path = format!("{}/0/0", params.derivation_path);
    let public_key = keystore.get_public_key(CurveType::SECP256k1, &path)?;
    let coin_info = CoinInfo {
        chain_id: "".to_string(),
        coin: params.chain_type.to_string(),
        derivation_path: path.clone(),
        curve: CurveType::SECP256k1,
        network: params.network.to_string(),
        seg_wit: params.seg_wit.to_string(),
        contract_code: "".to_string(),
    };
    let address = BtcKinAddress::from_public_key(&public_key, &coin_info)?;

    let tx_id = get_spend_tx_id(data, address.script_pubkey())?;
    let mut psbt = create_to_sign_empty(tx_id, address.script_pubkey())?;
    let mut psbt_signer = PsbtSigner::new(
        &mut psbt,
        keystore,
        &params.chain_type,
        &params.derivation_path,
        true,
    );
    psbt_signer.sign()?;

    if let Some(witness) = &psbt.inputs[0].final_script_witness {
        Ok(base64::engine::general_purpose::STANDARD.encode(witness_to_vec(witness.to_vec())))
    } else {
        Err(Error::MissingSignature.into())
    }
}

fn sign_message_bip322_full(
    keystore: &mut Keystore,
    params: &SignatureParameters,
    data: &[u8],
) -> Result<String> {
    let path = format!("{}/0/0", params.derivation_path);
    let public_key = keystore.get_public_key(CurveType::SECP256k1, &path)?;
    let coin_info = CoinInfo {
        chain_id: "".to_string(),
        coin: params.chain_type.to_string(),
        derivation_path: path.clone(),
        curve: CurveType::SECP256k1,
        network: params.network.to_string(),
        seg_wit: params.seg_wit.to_string(),
        contract_code: "".to_string(),
    };
    let address = BtcKinAddress::from_public_key(&public_key, &coin_info)?;

    let tx_id = get_spend_tx_id(data, address.script_pubkey())?;
    let mut psbt = create_to_sign_empty(tx_id, address.script_pubkey())?;
    let mut psbt_signer = PsbtSigner::new(
        &mut psbt,
        keystore,
        &params.chain_type,
        &params.derivation_path,
        true,
    );
    psbt_signer.sign()?;

    let tx = psbt.extract_tx()?;
    let serialized = btc_serialize(&tx);
    Ok(base64::engine::general_purpose::STANDARD.encode(serialized))
}

impl MessageSigner<BtcMessageInput, BtcMessageOutput> for Keystore {
    fn sign_message(
        &mut self,
        params: &SignatureParameters,
        message_input: &BtcMessageInput,
    ) -> tcx_keystore::Result<BtcMessageOutput> {
        let data = utf8_or_hex_to_bytes(&message_input.message)?;
        let seg_wit = params.seg_wit.as_str();
        let sig_type = message_input.signature_type;

        let signature = match sig_type {
            t if t == BtcSignatureType::Standard as i32 => {
                if seg_wit == "VERSION_1" {
                    return Err(Error::Bip137NotSupportedForTaproot.into());
                }
                sign_message_bip137(self, params, &data, 31)?
            }
            t if t == BtcSignatureType::Bip137 as i32 => {
                if seg_wit == "VERSION_1" {
                    return Err(Error::Bip137NotSupportedForTaproot.into());
                }
                let flag_base = flag_base_for_bip137(seg_wit)?;
                sign_message_bip137(self, params, &data, flag_base)?
            }
            t if t == BtcSignatureType::Bip322 as i32 => match seg_wit {
                "NONE" | "P2WPKH" => {
                    return Err(Error::Bip322NotSupportedForAddressType(seg_wit.to_string()).into());
                }
                "VERSION_0" => sign_message_bip322_simple(self, params, &data)?,
                "VERSION_1" => sign_message_bip322_full(self, params, &data)?,
                _ => {
                    return Err(Error::Bip322NotSupportedForAddressType(seg_wit.to_string()).into());
                }
            },
            _ => return Err(Error::InvalidSignatureType(sig_type).into()),
        };

        Ok(BtcMessageOutput { signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{sample_hd_keystore, wif_keystore};
    use crate::BtcKinAddress;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use bitcoin::Transaction;
    use tcx_common::ToHex;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{Address, MessageSigner};

    fn make_params(seg_wit: &str, derivation_path: &str) -> SignatureParameters {
        SignatureParameters {
            curve: CurveType::SECP256k1,
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: seg_wit.to_string(),
            derivation_path: derivation_path.to_string(),
        }
    }

    #[test]
    fn test_bip137_message_hash() {
        let hash = bip137_message_hash(b"hello world");
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hash.to_hex(),
            "0b6b6ce07bc55ee4aeba0098a5e5d2c8986cab228a54199723f9962316633733"
        );
    }

    #[test]
    fn test_standard_legacy_p2pkh() {
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("NONE", "m/44'/0'/0'");
        let output = ks
            .sign_message(
                &params,
                &BtcMessageInput {
                    message: "hello world".to_string(),
                    signature_type: BtcSignatureType::Standard as i32,
                },
            )
            .unwrap();

        let sig_bytes = base64::Engine::decode(&BASE64_STANDARD, &output.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65);
        let flag = sig_bytes[0];
        assert!(flag >= 31 && flag <= 34, "flag byte {} not in 31-34", flag);
    }

    #[test]
    fn test_bip137_legacy_p2pkh() {
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("NONE", "m/44'/0'/0'");
        let output = ks
            .sign_message(
                &params,
                &BtcMessageInput {
                    message: "hello world".to_string(),
                    signature_type: BtcSignatureType::Bip137 as i32,
                },
            )
            .unwrap();

        let sig_bytes = base64::Engine::decode(&BASE64_STANDARD, &output.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65);
        let flag = sig_bytes[0];
        assert!(flag >= 31 && flag <= 34, "flag byte {} not in 31-34", flag);
    }

    #[test]
    fn test_bip137_nested_segwit() {
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/49'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("P2WPKH", "m/49'/0'/0'");
        let output = ks
            .sign_message(
                &params,
                &BtcMessageInput {
                    message: "hello world".to_string(),
                    signature_type: BtcSignatureType::Bip137 as i32,
                },
            )
            .unwrap();

        let sig_bytes = base64::Engine::decode(&BASE64_STANDARD, &output.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65);
        let flag = sig_bytes[0];
        assert!(flag >= 35 && flag <= 38, "flag byte {} not in 35-38", flag);
    }

    #[test]
    fn test_standard_nested_segwit_uses_p2pkh_flags() {
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/49'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("P2WPKH", "m/49'/0'/0'");
        let output = ks
            .sign_message(
                &params,
                &BtcMessageInput {
                    message: "hello world".to_string(),
                    signature_type: BtcSignatureType::Standard as i32,
                },
            )
            .unwrap();

        let sig_bytes = base64::Engine::decode(&BASE64_STANDARD, &output.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65);
        let flag = sig_bytes[0];
        assert!(
            flag >= 31 && flag <= 34,
            "Standard format should always use 31-34 range, got {}",
            flag
        );
    }

    #[test]
    fn test_bip137_native_segwit() {
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_0".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("VERSION_0", "m/44'/0'/0'");
        let output = ks
            .sign_message(
                &params,
                &BtcMessageInput {
                    message: "hello world".to_string(),
                    signature_type: BtcSignatureType::Bip137 as i32,
                },
            )
            .unwrap();

        let sig_bytes = base64::Engine::decode(&BASE64_STANDARD, &output.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65);
        let flag = sig_bytes[0];
        assert!(flag >= 39 && flag <= 42, "flag byte {} not in 39-42", flag);
    }

    #[test]
    fn test_bip322_simple_native_segwit_base64() {
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_0".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("VERSION_0", "m/44'/0'/0'");
        let output = ks
            .sign_message(
                &params,
                &BtcMessageInput {
                    message: "hello world".to_string(),
                    signature_type: BtcSignatureType::Bip322 as i32,
                },
            )
            .unwrap();

        // Verify it's valid Base64 and decodes to the same witness data as old hex output
        let decoded = base64::Engine::decode(&BASE64_STANDARD, &output.signature).unwrap();
        assert!(!decoded.is_empty());
        let old_hex = "024830450221009f003820d1db93bf78be08dafdd05b7dde7c31a73c9be36b705a15329bd3d0e502203eb6f1a34466995e4b9c281bf4a093a1f55a21b2ef961438c9ae284efab27dda0121026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868";
        let expected_bytes = Vec::<u8>::from_hex(old_hex).unwrap();
        assert_eq!(decoded, expected_bytes);
    }

    #[test]
    fn test_bip322_full_taproot_base64() {
        let mut ks = wif_keystore("L4F5BYm82Bck6VEY64EbqQkoBXqkegq9X9yc6iLTV3cyJoqUasnY");
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/86'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("VERSION_1", "m/86'/0'/0'");
        let output = ks
            .sign_message(
                &params,
                &BtcMessageInput {
                    message: "Sign this message to log in to https://www.subber.xyz // 200323342"
                        .to_string(),
                    signature_type: BtcSignatureType::Bip322 as i32,
                },
            )
            .unwrap();

        let decoded = base64::Engine::decode(&BASE64_STANDARD, &output.signature).unwrap();
        assert!(!decoded.is_empty());
        // Full format: should be a valid serialized transaction
        let tx: Transaction =
            bitcoin::consensus::deserialize(&decoded).expect("should be valid tx");
        assert_eq!(tx.input.len(), 1);
        assert!(!tx.input[0].witness.is_empty());
    }

    #[test]
    fn test_bip322_not_supported_for_legacy() {
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("NONE", "m/44'/0'/0'");
        let result = ks.sign_message(
            &params,
            &BtcMessageInput {
                message: "hello world".to_string(),
                signature_type: BtcSignatureType::Bip322 as i32,
            },
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("bip322_not_supported"));
    }

    #[test]
    fn test_bip137_not_supported_for_taproot() {
        let mut ks = wif_keystore("L4F5BYm82Bck6VEY64EbqQkoBXqkegq9X9yc6iLTV3cyJoqUasnY");
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/86'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("VERSION_1", "m/86'/0'/0'");
        let result = ks.sign_message(
            &params,
            &BtcMessageInput {
                message: "hello".to_string(),
                signature_type: BtcSignatureType::Bip137 as i32,
            },
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("bip137_not_supported_for_taproot"));
    }

    #[test]
    fn test_standard_not_supported_for_taproot() {
        let mut ks = wif_keystore("L4F5BYm82Bck6VEY64EbqQkoBXqkegq9X9yc6iLTV3cyJoqUasnY");
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/86'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("VERSION_1", "m/86'/0'/0'");
        let result = ks.sign_message(
            &params,
            &BtcMessageInput {
                message: "hello".to_string(),
                signature_type: BtcSignatureType::Standard as i32,
            },
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("bip137_not_supported_for_taproot"));
    }

    #[test]
    fn test_to_spend_tx_id() {
        let message = "hello world";
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_0".to_string(),
            contract_code: "".to_string(),
        };

        let account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
        let address = BtcKinAddress::from_public_key(&account.public_key, &coin_info).unwrap();

        assert_eq!(
            get_spend_tx_id(message.as_bytes(), address.script_pubkey())
                .unwrap()
                .to_string(),
            "24bca2df5140bcf6a6aeafd141ad40b0595aa6998ca0fc733488d7131ca7763f"
        );
    }

    #[test]
    fn test_default_signature_type_is_standard() {
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            contract_code: "".to_string(),
        };
        let _account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params("NONE", "m/44'/0'/0'");
        let output = ks
            .sign_message(
                &params,
                &BtcMessageInput {
                    message: "hello world".to_string(),
                    signature_type: 0, // default = STANDARD
                },
            )
            .unwrap();

        let sig_bytes = base64::Engine::decode(&BASE64_STANDARD, &output.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65);
        let flag = sig_bytes[0];
        assert!(flag >= 31 && flag <= 34);
    }

    fn derive_and_sign(
        ks: &mut Keystore,
        seg_wit: &str,
        path: &str,
        sig_type: BtcSignatureType,
    ) -> String {
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: format!("{}/0/0", path),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: seg_wit.to_string(),
            contract_code: "".to_string(),
        };
        let _ = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let params = make_params(seg_wit, path);
        ks.sign_message(
            &params,
            &BtcMessageInput {
                message: "hello world".to_string(),
                signature_type: sig_type as i32,
            },
        )
        .unwrap()
        .signature
    }

    #[test]
    fn test_cross_validation_sign_message() {
        let mut ks = sample_hd_keystore();

        // ── Legacy (P2PKH) ──
        // Standard and BIP-137 produce identical results for legacy addresses (flag 31-34)
        let legacy_expected = "IMQsiVqUfCWA4lplLb8VJ32ZvpSP/OLM3BDt0HBca+LmZZ/fQ41SnSutgLjqYAgbfTBUa0+jAZfIS303iytBTM0=";
        assert_eq!(
            derive_and_sign(&mut ks, "NONE", "m/44'/0'/0'", BtcSignatureType::Standard),
            legacy_expected
        );
        assert_eq!(
            derive_and_sign(&mut ks, "NONE", "m/44'/0'/0'", BtcSignatureType::Bip137),
            legacy_expected
        );

        // ── Nested SegWit (P2SH-P2WPKH) ──
        // Standard uses legacy-compatible flag (27-30), BIP-137 uses nested segwit flag (35-38)
        assert_eq!(
            derive_and_sign(&mut ks, "P2WPKH", "m/49'/0'/0'", BtcSignatureType::Standard),
            "H9vMHPmn2idEnSPXJGxdufLsusIMyiSl3OixtZKChxksbE0lp3QYONulcETq/tCOS171QF4aJnupvbCcGXRDxRo="
        );
        assert_eq!(
            derive_and_sign(&mut ks, "P2WPKH", "m/49'/0'/0'", BtcSignatureType::Bip137),
            "I9vMHPmn2idEnSPXJGxdufLsusIMyiSl3OixtZKChxksbE0lp3QYONulcETq/tCOS171QF4aJnupvbCcGXRDxRo="
        );

        // ── Native SegWit (P2WPKH) ──
        // Standard uses legacy-compatible flag, BIP-137 uses native segwit flag (39-42)
        assert_eq!(
            derive_and_sign(&mut ks, "VERSION_0", "m/84'/0'/0'", BtcSignatureType::Standard),
            "IAoVnrHx8t+bNFeX5bbPUMsR6Wud/2OLEsk7NUvnkG6wHA8RkmcNZzFOhuHFzKVEa3f7sfKphiqnGLIFM2aCp5c="
        );
        assert_eq!(
            derive_and_sign(&mut ks, "VERSION_0", "m/84'/0'/0'", BtcSignatureType::Bip137),
            "KAoVnrHx8t+bNFeX5bbPUMsR6Wud/2OLEsk7NUvnkG6wHA8RkmcNZzFOhuHFzKVEa3f7sfKphiqnGLIFM2aCp5c="
        );
        // BIP-322 Simple
        assert_eq!(
            derive_and_sign(&mut ks, "VERSION_0", "m/84'/0'/0'", BtcSignatureType::Bip322),
            "AkgwRQIhAIaZgqlIItOUWUuHrV0dlriw6TtYgPPayR/Cr1O1bBIfAiBi1AyhrTFQPhtwSinfHE5+824+HBCCQ/xT6ESEBY0hJgEhAyR3j5NKIKnKBs7D+3F2zLwFQni51dfwoQd1gjZ6+S51"
        );

        // ── Taproot (P2TR) BIP-322 Full ──
        // Schnorr signatures use random nonces (BIP-340), verify structure instead of exact bytes
        let taproot_sig = derive_and_sign(
            &mut ks,
            "VERSION_1",
            "m/86'/0'/0'",
            BtcSignatureType::Bip322,
        );
        let decoded = base64::Engine::decode(&BASE64_STANDARD, &taproot_sig).unwrap();
        let tx: Transaction =
            bitcoin::consensus::deserialize(&decoded).expect("valid serialized tx");
        assert_eq!(tx.version, bitcoin::transaction::Version(0));
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert!(!tx.input[0].witness.is_empty());
        let schnorr_sig = &tx.input[0].witness.to_vec()[0];
        assert_eq!(schnorr_sig.len(), 64);
    }
}
