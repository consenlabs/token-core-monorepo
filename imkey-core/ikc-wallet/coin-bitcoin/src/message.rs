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
use ikc_common::error::CoinError;
use ikc_common::utility::{network_convert, sha256_hash, utf8_or_hex_to_bytes};
use std::str::FromStr;

pub struct MessageSinger {
    pub derivation_path: String,
    pub chain_type: String,
    pub network: String,
    pub seg_wit: String,
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
                return Err(CoinError::Bip137RequiresAppletUpgrade.into());
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

    #[test]
    fn test_bip322_p2wpkh_base64() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/44'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_0".to_string(),
        };
        let input = BtcMessageInput {
            message: "hello world".to_string(),
            signature_type: BtcSignatureType::Bip322 as i32,
        };
        let output = singer.sign_message(input).unwrap();
        let decoded = base64::decode(&output.signature).unwrap();
        assert!(!decoded.is_empty());
    }

    #[test]
    fn test_bip322_p2tr_full() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/86'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
        };
        let input = BtcMessageInput {
            message: "Sign this message to log in to https://www.subber.xyz // 200323342"
                .to_string(),
            signature_type: BtcSignatureType::Bip322 as i32,
        };
        let output = singer.sign_message(input).unwrap();
        let decoded = base64::decode(&output.signature).unwrap();
        assert!(!decoded.is_empty());
    }

    #[test]
    fn test_bip137_returns_applet_upgrade_error() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/44'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let input = BtcMessageInput {
            message: "hello world".to_string(),
            signature_type: BtcSignatureType::Bip137 as i32,
        };
        let result = singer.sign_message(input);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("bip137_requires_applet_upgrade"));
    }

    #[test]
    fn test_standard_returns_applet_upgrade_error() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/44'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let input = BtcMessageInput {
            message: "hello world".to_string(),
            signature_type: BtcSignatureType::Standard as i32,
        };
        let result = singer.sign_message(input);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("bip137_requires_applet_upgrade"));
    }

    #[test]
    fn test_bip322_not_supported_for_legacy() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/44'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let input = BtcMessageInput {
            message: "hello world".to_string(),
            signature_type: BtcSignatureType::Bip322 as i32,
        };
        let result = singer.sign_message(input);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("bip322_not_supported"));
    }

    #[test]
    fn test_bip137_not_supported_for_taproot() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/86'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
        };
        let input = BtcMessageInput {
            message: "hello world".to_string(),
            signature_type: BtcSignatureType::Bip137 as i32,
        };
        let result = singer.sign_message(input);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("bip137_not_supported_for_taproot"));
    }
}
