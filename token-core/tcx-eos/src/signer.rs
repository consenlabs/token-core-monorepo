use crate::transaction::{EosTxInput, EosTxOutput, SigData};
use base58::ToBase58;
use tcx_chain::{ChainSigner, Keystore, Result, TransactionSigner as TraitTransactionSigner};

use tcx_crypto::{hash, hex};

fn serial_eos_sig(sig: &[u8]) -> String {
    let to_hash = [sig, "K1".as_bytes()].concat();
    let hashed = hash::ripemd160(&to_hash);
    let data = [sig, &hashed[0..4]].concat();
    format!("SIG_K1_{}", data.to_base58())
}

impl TraitTransactionSigner<EosTxInput, EosTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &EosTxInput,
    ) -> Result<EosTxOutput> {
        //        let mut raw = tx.raw.clone();
        let chain_id_bytes = hex::hex_to_bytes(&tx.chain_id)?;
        let zero_padding = [0u8; 32];
        let mut eos_sigs = vec![];
        for tx_hex in &tx.tx_hexs {
            let tx_bytes = hex::hex_to_bytes(&tx_hex)?;
            let tx_hash = hash::sha256(&tx_bytes);
            let tx_with_chain_id = [
                chain_id_bytes.as_slice(),
                tx_bytes.as_slice(),
                &zero_padding,
            ]
            .concat();
            let hashed_tx = hash::sha256(&tx_with_chain_id);
            let sign_result =
                self.sign_recoverable_hash(hashed_tx.as_slice(), symbol, address, None)?;
            // EOS need v r s
            let eos_sig = [sign_result[64..].to_vec(), sign_result[..64].to_vec()].concat();
            eos_sigs.push(SigData {
                signature: serial_eos_sig(&eos_sig),
                hash: hex::bytes_to_hex(&tx_hash),
            });
        }
        Ok(EosTxOutput { sig_data: eos_sigs })
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::address::AtomAddress;

//     use tcx_chain::{HdKeystore, Keystore, KeystoreGuard, Metadata};
//     use tcx_constants::{CoinInfo, TEST_PASSWORD};
//     use tcx_constants::{CurveType, TEST_MNEMONIC};
//     use tcx_primitive::{PrivateKey, Secp256k1PrivateKey};

//     #[test]
//     fn sign_transaction() -> core::result::Result<(), failure::Error> {
//         let tx = AtomTxInput {
//             raw_data: "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201".to_string()
//         };

//         let meta = Metadata::default();
//         let mut keystore =
//             Keystore::Hd(HdKeystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, meta).unwrap());

//         let coin_info = CoinInfo {
//             coin: "COSMOS".to_string(),
//             derivation_path: "m/44'/118'/0'/0/0".to_string(),
//             curve: CurveType::SECP256k1,
//             network: "".to_string(),
//             seg_wit: "".to_string(),
//         };
//         let mut guard = KeystoreGuard::unlock_by_password(&mut keystore, TEST_PASSWORD).unwrap();

//         let ks = guard.keystore_mut();

//         let account = ks.derive_coin::<AtomAddress>(&coin_info).unwrap().clone();

//         let signed_tx: AtomTxOutput = ks.sign_transaction("Atom", &account.address, &tx)?;

//         assert_eq!(signed_tx.signature, "355fWQ00dYitAZj6+EmnAgYEX1g7QtUrX/kQIqCbv05TCz0dfsWcMgXWVnr1l/I2hrjjQkiLRMoeRrmnqT2CZA==");

//         Ok(())
//     }
// }
