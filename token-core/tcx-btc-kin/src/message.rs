use crate::psbt::PsbtSigner;
use crate::transaction::{BtcMessageInput, BtcMessageOutput};
use crate::{BtcKinAddress, Error, Result};
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{
    OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use tcx_common::{sha256, utf8_or_hex_to_bytes, FromHex, ToHex};
use tcx_constants::{CoinInfo, CurveType};
use tcx_keystore::{Address, Keystore, MessageSigner, SignatureParameters};

const UTXO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TAG: &str = "BIP0322-signed-message";

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

impl MessageSigner<BtcMessageInput, BtcMessageOutput> for Keystore {
    fn sign_message(
        &mut self,
        params: &SignatureParameters,
        message_input: &BtcMessageInput,
    ) -> tcx_keystore::Result<BtcMessageOutput> {
        let data = utf8_or_hex_to_bytes(&message_input.message)?;
        let path = format!("{}/0/0", params.derivation_path);

        let public_key = self.get_public_key(CurveType::SECP256k1, &path)?;
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: params.chain_type.to_string(),
            derivation_path: path.clone(),
            curve: CurveType::SECP256k1,
            network: params.network.to_string(),
            seg_wit: params.seg_wit.to_string(),
        };

        let address = BtcKinAddress::from_public_key(&public_key, &coin_info)?;

        let tx_id = get_spend_tx_id(&data, address.script_pubkey())?;
        let mut psbt = create_to_sign_empty(tx_id, address.script_pubkey())?;
        let mut psbt_signer = PsbtSigner::new(
            &mut psbt,
            self,
            &params.chain_type,
            &params.derivation_path,
            true,
        );

        psbt_signer.sign()?;

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
                Err(Error::MissingSignature.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{sample_hd_keystore, wif_keystore};
    use crate::BtcKinAddress;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{Address, MessageSigner};

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
        };

        let account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
        let address = BtcKinAddress::from_public_key(&account.public_key, &coin_info).unwrap();

        assert_eq!(
            super::get_spend_tx_id(message.as_bytes(), address.script_pubkey())
                .unwrap()
                .to_string(),
            "24bca2df5140bcf6a6aeafd141ad40b0595aa6998ca0fc733488d7131ca7763f"
        );
    }

    #[test]
    fn test_bip32_p2sh_p2wpkh() {
        let message = "hello world";
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/49'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
        };

        let account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
        let address = BtcKinAddress::from_public_key(&account.public_key, &coin_info).unwrap();

        let params = tcx_keystore::SignatureParameters {
            curve: CurveType::SECP256k1,
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
            derivation_path: "m/49'/0'/0'".to_string(),
        };

        let output = ks
            .sign_message(
                &params,
                &super::BtcMessageInput {
                    message: message.to_string(),
                },
            )
            .unwrap();

        assert_eq!(output.signature, "02473044022000ae3c9439681a4ba05e74d0805210f71c31f92130bcec28934d29beaf5f4f890220327cbf8a189eee4cb35a2599f6fd97b0774bec2e4191d74b3460f746732f8a03012103036695c5f3de2e2792b170f59679d4db88a8516728012eaa42a22ce6f8bf593b");
    }

    #[test]
    fn test_bip32_p2pkh() {
        let message = "hello world";
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };

        let account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
        println!("{}", account.address);
        let address = BtcKinAddress::from_public_key(&account.public_key, &coin_info).unwrap();

        let params = tcx_keystore::SignatureParameters {
            curve: CurveType::SECP256k1,
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            derivation_path: "m/44'/0'/0'".to_string(),
        };

        let output = ks
            .sign_message(
                &params,
                &super::BtcMessageInput {
                    message: message.to_string(),
                },
            )
            .unwrap();

        assert_eq!(output.signature, "02483045022100dbbdfedfb1902ca12c6cba14d4892a98f77c434daaa4f97fd35e618374c908f602206527ff2b1ce550c16c836c2ce3508bfae543fa6c11759d2f4966cc0d3552c4430121026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868");
    }

    #[test]
    fn test_bip322_p2wpkh() {
        let message = "hello world";
        let mut ks = sample_hd_keystore();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_0".to_string(),
        };

        let account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
        let address = BtcKinAddress::from_public_key(&account.public_key, &coin_info).unwrap();

        let params = tcx_keystore::SignatureParameters {
            curve: CurveType::SECP256k1,
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_0".to_string(),
            derivation_path: "m/44'/0'/0'".to_string(),
        };

        let output = ks
            .sign_message(
                &params,
                &super::BtcMessageInput {
                    message: message.to_string(),
                },
            )
            .unwrap();

        assert_eq!(output.signature, "024830450221009f003820d1db93bf78be08dafdd05b7dde7c31a73c9be36b705a15329bd3d0e502203eb6f1a34466995e4b9c281bf4a093a1f55a21b2ef961438c9ae284efab27dda0121026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868");
    }

    #[test]
    fn test_bip322_p2tr() {
        let message = "Sign this message to log in to https://www.subber.xyz // 200323342";
        let mut ks = wif_keystore("L4F5BYm82Bck6VEY64EbqQkoBXqkegq9X9yc6iLTV3cyJoqUasnY");
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/86'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
        };

        let account = ks.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
        let address = BtcKinAddress::from_public_key(&account.public_key, &coin_info).unwrap();

        let params = tcx_keystore::SignatureParameters {
            curve: CurveType::SECP256k1,
            chain_type: "BITCOIN".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
            derivation_path: "m/86'/0'/0'".to_string(),
        };

        let output = ks
            .sign_message(
                &params,
                &super::BtcMessageInput {
                    message: message.to_string(),
                },
            )
            .unwrap();

        //        assert_eq!(output.signature, "0140717dbc46e9d816d7c9e26b5a5f6153c1fceb734489afaaee4ed80bc7c119a39af44de7f6d66c30e530c7c696a25d45bab052cc55012fc57ef6cb24313b31014b");
    }
}
