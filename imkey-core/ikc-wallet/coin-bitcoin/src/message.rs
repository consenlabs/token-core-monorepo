use crate::address::BtcAddress;
use crate::btcapi::{BtcMessageInput, BtcMessageOutput, BtcSignatureType};
use crate::common::{ensure_transaction_preview_version, select_btc_applet};
use crate::input_proof::{authenticated_transaction_chunk, TRANSACTION_CHUNK_BYTES};
use crate::psbt::PsbtSigner;
use crate::Result;
use bitcoin::consensus::serialize as btc_serialize;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{
    Address, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use hex::FromHex;
use ikc_common::apdu::ApduCheck;
use ikc_common::constants::TIMEOUT_LONG;
use ikc_common::error::CoinError;
use ikc_common::utility::{network_convert, sha256_hash, utf8_or_hex_to_bytes};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_btc_apple_version;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::ecdsa::Signature as EcdsaSignature;
use std::str::FromStr;

const BTC_MSG_SIGN_INS: u8 = 0x58;
const MAX_MESSAGE_BYTES: usize = 32767;

pub struct MessageSinger {
    pub derivation_path: String,
    pub chain_type: String,
    pub network: String,
    pub seg_wit: String,
}

fn flag_base_for_bip137(seg_wit: &str) -> Result<u8> {
    match seg_wit {
        "NONE" => Ok(31),
        "P2WPKH" => Ok(35),
        "VERSION_0" => Ok(39),
        _ => Err(CoinError::Bip137NotSupportedForTaproot.into()),
    }
}

impl MessageSinger {
    pub fn sign_message(&self, input: BtcMessageInput) -> Result<BtcMessageOutput> {
        let data = utf8_or_hex_to_bytes(&input.message)?;
        let seg_wit = self.seg_wit.as_str();
        let sig_type = input.signature_type;

        let signature = match sig_type {
            t if t == BtcSignatureType::Standard as i32 || t == BtcSignatureType::Bip137 as i32 => {
                if seg_wit == "VERSION_1" {
                    return Err(CoinError::Bip137NotSupportedForTaproot.into());
                }
                let is_standard = t == BtcSignatureType::Standard as i32;
                self.sign_message_bip137(&data, is_standard)?
            }
            t if t == BtcSignatureType::Bip322 as i32 => match seg_wit {
                "VERSION_0" | "VERSION_1" => {
                    return Err(CoinError::Bip322DeviceProtocolUnavailable.into());
                }
                _ => {
                    return Err(CoinError::Bip322NotSupportedForAddressType.into());
                }
            },
            _ => return Err(CoinError::InvalidSignatureType.into()),
        };

        Ok(BtcMessageOutput { signature })
    }

    fn sign_message_bip137(&self, data: &[u8], is_standard: bool) -> Result<String> {
        let account_path = self
            .derivation_path
            .to_ascii_lowercase()
            .parse::<bitcoin::util::bip32::DerivationPath>()
            .map_err(|_| CoinError::ImkeySdkIllegalArgument)?;
        let path = format!("{}/0/0", account_path);
        let path = path.as_bytes();
        if data.len() > MAX_MESSAGE_BYTES || path.len() + 3 > TRANSACTION_CHUNK_BYTES {
            return Err(CoinError::ImkeySdkIllegalArgument.into());
        }

        let mut body = Vec::with_capacity(3 + path.len() + data.len());
        body.push(path.len() as u8);
        body.extend_from_slice(path);
        body.extend_from_slice(&(data.len() as u16).to_be_bytes());
        body.extend_from_slice(data);

        ensure_transaction_preview_version(&get_btc_apple_version()?)?;
        let key_manager = KEY_MANAGER.lock();
        let chunks = body.chunks(TRANSACTION_CHUNK_BYTES);
        let last = chunks.len() - 1;
        let mut sign_bytes = Vec::new();
        for (index, fragment) in chunks.enumerate() {
            let phase = if index == last { 0x80 } else { 0 };
            let apdu = authenticated_transaction_chunk(
                BTC_MSG_SIGN_INS,
                index as u8,
                phase,
                fragment,
                &key_manager.pri_key,
            )?;
            let response = if index == last {
                send_apdu_timeout(apdu, TIMEOUT_LONG)?
            } else {
                send_apdu(apdu)?
            };
            let decoded = hex::decode(&response)?;
            if decoded.len() < 2 {
                return Err(CoinError::MissingSignature.into());
            }
            ApduCheck::check_response(&response)?;
            if index == last {
                if decoded.len() != 68 {
                    return Err(CoinError::MissingSignature.into());
                }
                sign_bytes.extend_from_slice(&decoded[1..66]);
            } else if decoded.len() != 2 {
                return Err(CoinError::MissingSignature.into());
            }
        }

        let r = &sign_bytes[0..32];
        let s = &sign_bytes[32..64];
        let v = sign_bytes[64];
        if v > 3 {
            return Err(CoinError::MissingSignature.into());
        }

        // BIP-62 low-S normalization
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(r);
        compact[32..].copy_from_slice(s);
        let mut sig = EcdsaSignature::from_compact(&compact)?;
        sig.normalize_s();
        let final_compact = sig.serialize_compact();
        let s_changed = final_compact[32..] != compact[32..];
        let final_v = if s_changed { v ^ 1 } else { v };

        // Standard format always uses legacy-compatible flag base (31)
        let flag_base = if is_standard {
            31
        } else {
            flag_base_for_bip137(&self.seg_wit)?
        };

        let mut result_sig = vec![flag_base + final_v];
        result_sig.extend_from_slice(&final_compact);

        Ok(base64::encode(&result_sig))
    }

    // Retained as a reference for the dedicated device protocol.
    #[allow(dead_code)]
    fn sign_message_bip322_simple(&self, data: &[u8]) -> Result<String> {
        let path = format!("{}/0/0", self.derivation_path);
        let pub_key = BtcAddress::get_pub_key(&path)?;
        let network = network_convert(&self.network);
        let address = BtcAddress::from_public_key(&pub_key, network, &self.seg_wit)?;
        let script_pubkey = Address::from_str(&address)?.script_pubkey();
        let tx_id = get_spend_tx_id(data, script_pubkey.clone())?;

        select_btc_applet()?;

        let mut psbt = create_to_sign_empty(tx_id, script_pubkey)?;
        let mut psbt_signer =
            PsbtSigner::new(&mut psbt, &self.derivation_path, true, network, true)?;

        psbt_signer.prevouts()?;
        let pub_keys = psbt_signer.get_pub_key()?;
        psbt_signer.calc_tx_hash()?;
        psbt_signer.get_preview_info()?;
        psbt_signer.tx_preview(network)?;
        psbt_signer.sign(&pub_keys)?;

        if let Some(witness) = &psbt.inputs[0].final_script_witness {
            Ok(base64::encode(witness_to_vec(witness.to_vec())))
        } else {
            Err(CoinError::MissingSignature.into())
        }
    }

    #[allow(dead_code)]
    fn sign_message_bip322_full(&self, data: &[u8]) -> Result<String> {
        let path = format!("{}/0/0", self.derivation_path);
        let pub_key = BtcAddress::get_pub_key(&path)?;
        let network = network_convert(&self.network);
        let address = BtcAddress::from_public_key(&pub_key, network, &self.seg_wit)?;
        let script_pubkey = Address::from_str(&address)?.script_pubkey();
        let tx_id = get_spend_tx_id(data, script_pubkey.clone())?;

        select_btc_applet()?;

        let mut psbt = create_to_sign_empty(tx_id, script_pubkey)?;
        let mut psbt_signer =
            PsbtSigner::new(&mut psbt, &self.derivation_path, true, network, true)?;

        psbt_signer.prevouts()?;
        let pub_keys = psbt_signer.get_pub_key()?;
        psbt_signer.calc_tx_hash()?;
        psbt_signer.get_preview_info()?;
        psbt_signer.tx_preview(network)?;
        psbt_signer.sign(&pub_keys)?;

        let tx = psbt.extract_tx();
        let serialized = btc_serialize(&tx);
        Ok(base64::encode(serialized))
    }
}

const UTXO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TAG: &str = "BIP0322-signed-message";

fn get_spend_tx_id(data: &[u8], script_pub_key: Script) -> Result<Txid> {
    let tag_hash = sha256_hash(&TAG.as_bytes().to_vec());
    let mut to_sign = Vec::new();
    to_sign.extend(tag_hash.clone());
    to_sign.extend(tag_hash);
    to_sign.extend(data);

    let hash = sha256_hash(&to_sign);
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
        value: 0,
        script_pubkey: script_pub_key,
    }];

    let tx = Transaction {
        version: 0,
        lock_time: PackedLockTime::ZERO,
        input: ins,
        output: outs,
    };

    Ok(tx.txid())
}

fn create_to_sign_empty(txid: Txid, script_pub_key: Script) -> Result<PartiallySignedTransaction> {
    let ins = vec![TxIn {
        previous_output: OutPoint { txid, vout: 0 },
        script_sig: Script::new(),
        sequence: Sequence(0),
        witness: Witness::new(),
    }];

    let outs = vec![TxOut {
        value: 0,
        script_pubkey: Script::from(Vec::<u8>::from_hex("6a")?),
    }];

    let tx = Transaction {
        version: 0,
        lock_time: PackedLockTime::ZERO,
        input: ins,
        output: outs,
    };

    let mut psbt = PartiallySignedTransaction::from_unsigned_tx(tx)?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: 0,
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

#[cfg(test)]
mod tests {
    use crate::btcapi::{BtcMessageInput, BtcSignatureType};
    use crate::message::MessageSinger;
    use ikc_device::device_binding::bind_test;

    fn make_signer(seg_wit: &str, path: &str) -> MessageSinger {
        MessageSinger {
            derivation_path: path.to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: seg_wit.to_string(),
        }
    }

    fn sign(signer: &MessageSinger, sig_type: BtcSignatureType) -> String {
        signer
            .sign_message(BtcMessageInput {
                message: "hello world".to_string(),
                signature_type: sig_type as i32,
            })
            .unwrap()
            .signature
    }

    fn sign_err(signer: &MessageSinger, sig_type: BtcSignatureType) -> String {
        signer
            .sign_message(BtcMessageInput {
                message: "hello world".to_string(),
                signature_type: sig_type as i32,
            })
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn test_incompatible_combinations() {
        bind_test();

        // BIP-322 not supported for Legacy
        assert!(sign_err(
            &make_signer("NONE", "m/44'/0'/0'"),
            BtcSignatureType::Bip322
        )
        .contains("bip322_not_supported"));

        // BIP-322 not supported for Nested SegWit
        assert!(sign_err(
            &make_signer("P2WPKH", "m/49'/0'/0'"),
            BtcSignatureType::Bip322
        )
        .contains("bip322_not_supported"));

        // BIP-137 not supported for Taproot
        assert!(sign_err(
            &make_signer("VERSION_1", "m/86'/0'/0'"),
            BtcSignatureType::Bip137
        )
        .contains("bip137_not_supported_for_taproot"));

        // Standard not supported for Taproot
        assert!(sign_err(
            &make_signer("VERSION_1", "m/86'/0'/0'"),
            BtcSignatureType::Standard
        )
        .contains("bip137_not_supported_for_taproot"));
    }

    // Cross-validation test: expected values are identical to token-core because
    // both use the same mnemonic. BIP-137/Standard signatures are deterministic
    // (ECDSA RFC 6979).
    #[test]
    fn test_cross_validation_sign_message() {
        bind_test();

        // ── Legacy (P2PKH) ──
        let legacy = make_signer("NONE", "m/44'/0'/0'");
        let legacy_expected = "IMQsiVqUfCWA4lplLb8VJ32ZvpSP/OLM3BDt0HBca+LmZZ/fQ41SnSutgLjqYAgbfTBUa0+jAZfIS303iytBTM0=";
        assert_eq!(sign(&legacy, BtcSignatureType::Standard), legacy_expected);
        assert_eq!(sign(&legacy, BtcSignatureType::Bip137), legacy_expected);

        // ── Nested SegWit (P2SH-P2WPKH) ──
        let nested = make_signer("P2WPKH", "m/49'/0'/0'");
        assert_eq!(
            sign(&nested, BtcSignatureType::Standard),
            "H9vMHPmn2idEnSPXJGxdufLsusIMyiSl3OixtZKChxksbE0lp3QYONulcETq/tCOS171QF4aJnupvbCcGXRDxRo="
        );
        assert_eq!(
            sign(&nested, BtcSignatureType::Bip137),
            "I9vMHPmn2idEnSPXJGxdufLsusIMyiSl3OixtZKChxksbE0lp3QYONulcETq/tCOS171QF4aJnupvbCcGXRDxRo="
        );

        // ── Native SegWit (P2WPKH) ──
        let native = make_signer("VERSION_0", "m/84'/0'/0'");
        assert_eq!(
            sign(&native, BtcSignatureType::Standard),
            "IAoVnrHx8t+bNFeX5bbPUMsR6Wud/2OLEsk7NUvnkG6wHA8RkmcNZzFOhuHFzKVEa3f7sfKphiqnGLIFM2aCp5c="
        );
        assert_eq!(
            sign(&native, BtcSignatureType::Bip137),
            "KAoVnrHx8t+bNFeX5bbPUMsR6Wud/2OLEsk7NUvnkG6wHA8RkmcNZzFOhuHFzKVEa3f7sfKphiqnGLIFM2aCp5c="
        );
    }

    #[test]
    fn bip322_requires_dedicated_device_protocol() {
        for (seg_wit, path) in [("VERSION_0", "m/84'/0'/0'"), ("VERSION_1", "m/86'/0'/0'")] {
            assert_eq!(
                sign_err(&make_signer(seg_wit, path), BtcSignatureType::Bip322),
                "bip322_signing_requires_a_dedicated_device_protocol"
            );
        }
    }
}
