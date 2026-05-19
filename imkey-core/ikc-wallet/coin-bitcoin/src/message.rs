use crate::address::BtcAddress;
use crate::btcapi::{BtcMessageInput, BtcMessageOutput, BtcSignatureType};
use crate::common::select_btc_applet;
use crate::psbt::PsbtSigner;
use crate::Result;
use bitcoin::consensus::serialize as btc_serialize;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{
    Address, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use hex::FromHex;
use ikc_common::apdu::{ApduCheck, BtcApdu};
use ikc_common::constants::TIMEOUT_LONG;
use ikc_common::error::{CoinError, CommonError};
use ikc_common::utility::{
    hex_to_bytes, network_convert, secp256k1_sign, sha256_hash, utf8_or_hex_to_bytes,
    version_at_least,
};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_btc_apple_version;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::ecdsa::Signature as EcdsaSignature;
use std::str::FromStr;

/// INS byte for the BTC message signing single-instruction protocol.
///
/// All chunks of the wire payload share this INS; phases are distinguished by
/// the P2 byte (`0x00` to stage, `0x80` to commit + sign).
const BTC_MSG_SIGN_INS: u8 = 0x51;

/// Outer TLV tags carried in the prep payload.
const TAG_SIGNATURE: u8 = 0x00;
const TAG_RAW_DATA: u8 = 0x01;

/// Inner sub-TLV tags carried inside the Raw Data TLV value.
///
/// The applet covers both sub-TLVs under the host ECDSA signature so the BIP32
/// path is bound to the request alongside the message digest.
const PRE_TAG_TXHASH: u8 = 0xA6;
const PRE_TAG_PATH: u8 = 0xA7;

pub struct MessageSinger {
    pub derivation_path: String,
    pub chain_type: String,
    pub network: String,
    pub seg_wit: String,
}

fn bip137_message_hash(message: &[u8]) -> Vec<u8> {
    let prefix = b"\x18Bitcoin Signed Message:\n";
    let varint = bitcoin::VarInt(message.len() as u64);
    let mut data = Vec::new();
    data.extend_from_slice(prefix);
    bitcoin::consensus::encode::Encodable::consensus_encode(&varint, &mut data).unwrap();
    data.extend_from_slice(message);
    sha256_hash(&sha256_hash(&data))
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
                "NONE" | "P2WPKH" => {
                    return Err(CoinError::Bip322NotSupportedForAddressType.into());
                }
                "VERSION_0" => self.sign_message_bip322_simple(&data)?,
                "VERSION_1" => self.sign_message_bip322_full(&data)?,
                _ => {
                    return Err(CoinError::Bip322NotSupportedForAddressType.into());
                }
            },
            _ => return Err(CoinError::InvalidSignatureType.into()),
        };

        Ok(BtcMessageOutput { signature })
    }

    fn sign_message_bip137(&self, data: &[u8], is_standard: bool) -> Result<String> {
        let btc_version = get_btc_apple_version()?;
        if !version_at_least(&btc_version, (1, 6, 11)) {
            return Err(CommonError::UpgradeApplet.into());
        }

        let msg_hash = bip137_message_hash(data);
        let path = format!("{}/0/0", self.derivation_path);
        let path_bytes = path.as_bytes();

        // Inner sub-TLVs carried inside the Raw Data TLV value. Putting the BIP32
        // path here (rather than on a separate sign APDU as legacy BTC sign flows
        // do) pulls it under the host ECDSA signature, closing the path-swap
        // window between prepare and sign APDUs.
        //
        //   [PRE_TAG_TXHASH(0xA6) | 0x20 | 32-byte BIP-137 digest]
        //   [PRE_TAG_PATH(0xA7)   | path_len | path bytes]
        let mut raw_data_value = Vec::with_capacity(2 + msg_hash.len() + 2 + path_bytes.len());
        raw_data_value.push(PRE_TAG_TXHASH);
        raw_data_value.push(msg_hash.len() as u8);
        raw_data_value.extend_from_slice(&msg_hash);
        raw_data_value.push(PRE_TAG_PATH);
        raw_data_value.push(path_bytes.len() as u8);
        raw_data_value.extend_from_slice(path_bytes);

        // Raw Data TLV: [tag=0x01][len][raw_data_value]
        let mut raw_data_tlv = Vec::with_capacity(2 + raw_data_value.len());
        raw_data_tlv.push(TAG_RAW_DATA);
        raw_data_tlv.push(raw_data_value.len() as u8);
        raw_data_tlv.extend_from_slice(&raw_data_value);

        // Host signs the full Raw Data TLV bytes (tag | len | value); the applet
        // verifies the resulting DER signature against the same byte range,
        // binding both the message hash and the derivation path to this request.
        let key_manager_obj = KEY_MANAGER.lock();
        let host_sig = secp256k1_sign(&key_manager_obj.pri_key, &raw_data_tlv)?;
        drop(key_manager_obj);

        // Final wire payload: [Signature TLV: 0x00 | len | DER_sig] || [Raw Data TLV]
        let mut prep_data = Vec::with_capacity(2 + host_sig.len() + raw_data_tlv.len());
        prep_data.push(TAG_SIGNATURE);
        prep_data.push(host_sig.len() as u8);
        prep_data.extend_from_slice(&host_sig);
        prep_data.extend_from_slice(&raw_data_tlv);

        select_btc_applet()?;

        // Single-INS protocol: all chunks share INS=BTC_MSG_SIGN (0x51), P1=0x00.
        //   P2=0x00 → buffer chunk and return SW=9000
        //   P2=0x80 → append final chunk, then in the same APDU the applet runs
        //             host-sig verify → inner TLV parse → user confirmation →
        //             RFC-6979 ECDSA sign → return 66-byte [len|R|S|V] result.
        //
        // btc_prepare already emits the 0x00.../0x80 sequence for us; the final
        // APDU response carries the signature, so no follow-up sign APDU is sent.
        let apdus = BtcApdu::btc_prepare(BTC_MSG_SIGN_INS, 0x00, &prep_data);
        let last_idx = apdus.len() - 1;
        let mut sign_result = String::new();
        for (i, apdu) in apdus.into_iter().enumerate() {
            if i == last_idx {
                sign_result = send_apdu_timeout(apdu, TIMEOUT_LONG)?;
                ApduCheck::check_response(&sign_result)?;
            } else {
                ApduCheck::check_response(&send_apdu(apdu)?)?;
            }
        }

        // Response wire format: [length_byte(1) | R(32) | S(32) | V(1)] + SW(2)
        let sign_bytes = hex_to_bytes(&sign_result[2..(sign_result.len() - 4)])?;
        if sign_bytes.len() != 65 {
            return Err(CoinError::MissingSignature.into());
        }

        let r = &sign_bytes[0..32];
        let s = &sign_bytes[32..64];
        let v = sign_bytes[64];

        // BIP-62 low-S normalization
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(r);
        compact[32..].copy_from_slice(s);
        let mut sig = EcdsaSignature::from_compact(&compact)?;
        sig.normalize_s();
        let final_compact = sig.serialize_compact();
        let s_changed = final_compact[32..] != compact[32..];
        let final_v = if s_changed { 1 - v } else { v };

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
    // (ECDSA RFC 6979). BIP-322 Native SegWit (ECDSA) is also deterministic.
    // Taproot BIP-322 Full uses Schnorr (BIP-340) with random nonces, so only
    // structural correctness is verified.
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
        assert_eq!(
            sign(&native, BtcSignatureType::Bip322),
            "AkgwRQIhAIaZgqlIItOUWUuHrV0dlriw6TtYgPPayR/Cr1O1bBIfAiBi1AyhrTFQPhtwSinfHE5+824+HBCCQ/xT6ESEBY0hJgEhAyR3j5NKIKnKBs7D+3F2zLwFQni51dfwoQd1gjZ6+S51"
        );

        // ── Taproot (P2TR) BIP-322 Full ──
        let taproot = make_signer("VERSION_1", "m/86'/0'/0'");
        let bip322_sig = sign(&taproot, BtcSignatureType::Bip322);
        let decoded = base64::decode(&bip322_sig).unwrap();
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&decoded).expect("valid serialized tx");
        assert_eq!(tx.version, 0);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert!(!tx.input[0].witness.is_empty());
        let schnorr_sig = &tx.input[0].witness.to_vec()[0];
        assert_eq!(schnorr_sig.len(), 64);
    }
}
