use crate::address::{AddressTrait, BtcAddress};
use crate::btcapi::{BtcMessageInput, BtcMessageOutput};
use crate::common::select_btc_applet;
use crate::psbt::PsbtSigner;
use crate::Result;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{
    Address, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_hashes::hex::ToHex;
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

        let path = format!("{}/0/0", self.derivation_path);

        let pub_key = BtcAddress::get_pub_key(&path)?;

        let network = network_convert(&self.network);
        let address = BtcAddress::from_public_key(&pub_key, network, &self.seg_wit)?;
        let script_pubkey = Address::from_str(&address)?.script_pubkey();
        let tx_id = get_spend_tx_id(&data, script_pubkey.clone())?;

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
            Ok(BtcMessageOutput {
                signature: witness_to_vec(witness.to_vec()).to_hex(),
            })
        } else {
            if let Some(script_sig) = &psbt.inputs[0].final_script_sig {
                Ok(BtcMessageOutput {
                    signature: format!("02{}", script_sig.to_hex()),
                })
            } else {
                Err(CoinError::MissingSignature.into())
            }
        }
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

    //Tx ins
    let ins = vec![TxIn {
        previous_output: OutPoint {
            txid: UTXO.parse()?,
            vout: 0xFFFFFFFF,
        },
        script_sig: Script::from(script_sig),
        sequence: Sequence(0),
        witness: Witness::new(),
    }];

    //Tx outs
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
    //Tx ins
    let ins = vec![TxIn {
        previous_output: OutPoint { txid, vout: 0 },
        script_sig: Script::new(),
        sequence: Sequence(0),
        witness: Witness::new(),
    }];

    //Tx outs
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
    use crate::address::{AddressTrait, BtcAddress};
    use crate::btcapi::BtcMessageInput;
    use crate::message::MessageSinger;
    use bitcoin::{Address, Network};
    use ikc_common::SignParam;
    use ikc_device::device_binding::bind_test;
    use std::str::FromStr;

    #[test]
    fn test_to_spend_tx_id() {
        bind_test();

        let derivation_path = "m/44'/0'/0'/0/0";
        let pub_key = BtcAddress::get_pub_key(derivation_path).unwrap();
        let network = Network::Bitcoin;
        let seg_wit = "VERSION_0";
        let address = BtcAddress::from_public_key(&pub_key, Network::Testnet, seg_wit).unwrap();
        let address = Address::from_str(&address).unwrap();
        let message = "hello world";

        assert_eq!(
            super::get_spend_tx_id(message.as_bytes(), address.script_pubkey())
                .unwrap()
                .to_string(),
            "24bca2df5140bcf6a6aeafd141ad40b0595aa6998ca0fc733488d7131ca7763f"
        );
    }

    #[test]
    fn test_bip32_p2sh_p2wpkh() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/49'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
        };
        let input = BtcMessageInput {
            message: "hello world".to_string(),
        };

        let output = singer.sign_message(input).unwrap();
        assert_eq!(output.signature, "02473044022000ae3c9439681a4ba05e74d0805210f71c31f92130bcec28934d29beaf5f4f890220327cbf8a189eee4cb35a2599f6fd97b0774bec2e4191d74b3460f746732f8a03012103036695c5f3de2e2792b170f59679d4db88a8516728012eaa42a22ce6f8bf593b");
    }

    #[test]
    fn test_bip32_p2pkh() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/44'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let input = BtcMessageInput {
            message: "hello world".to_string(),
        };
        let output = singer.sign_message(input).unwrap();
        assert_eq!(output.signature, "02483045022100dbbdfedfb1902ca12c6cba14d4892a98f77c434daaa4f97fd35e618374c908f602206527ff2b1ce550c16c836c2ce3508bfae543fa6c11759d2f4966cc0d3552c4430121026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868");
    }

    #[test]
    fn test_bip322_p2wpkh() {
        bind_test();

        let singer = MessageSinger {
            derivation_path: "m/44'/0'/0'".to_string(),
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_0".to_string(),
        };
        let input = BtcMessageInput {
            message: "hello world".to_string(),
        };
        let output = singer.sign_message(input).unwrap();
        assert_eq!(output.signature, "024830450221009f003820d1db93bf78be08dafdd05b7dde7c31a73c9be36b705a15329bd3d0e502203eb6f1a34466995e4b9c281bf4a093a1f55a21b2ef961438c9ae284efab27dda0121026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868");
    }

    #[test]
    fn test_bip322_p2tr() {
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
        };
        let output = singer.sign_message(input).unwrap();
        // assert_eq!(output.signature, "0140a868e67a50f6dff3e25f6b015f595d89de54e330a6e1dfb4925269577730803e10a43562b25979a704f1d6c856e623681f292ce0ddf2281f42c033db013b4326");
    }
}
