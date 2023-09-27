use crate::transaction::{AtomTxInput, AtomTxOutput};
use tcx_chain::{ChainSigner, Keystore, Result, TransactionSigner as TraitTransactionSigner};

use tcx_crypto::{hash, hex};

use base64;
use failure::format_err;

const SIG_LEN: usize = 64;

impl TraitTransactionSigner<AtomTxInput, AtomTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &AtomTxInput,
    ) -> Result<AtomTxOutput> {
        let data = hex::hex_to_bytes(&tx.raw_data)?;
        let hash = hash::sha256(&data);

        let sign_result = self.sign_recoverable_hash(&hash[..], symbol, address, None)?;

        Ok(AtomTxOutput {
            signature: (base64::encode(&sign_result[..SIG_LEN])),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::AtomAddress;

    use tcx_chain::{HdKeystore, Keystore, KeystoreGuard, Metadata};
    use tcx_constants::{CoinInfo, TEST_PASSWORD};
    use tcx_constants::{CurveType, TEST_MNEMONIC};

    #[test]
    fn sign_transaction() -> core::result::Result<(), failure::Error> {
        let tx = AtomTxInput {
            raw_data: "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201".to_string()
        };

        let meta = Metadata::default();
        let mut keystore =
            Keystore::Hd(HdKeystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, meta).unwrap());

        let coin_info = CoinInfo {
            coin: "COSMOS".to_string(),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };
        let mut guard = KeystoreGuard::unlock_by_password(&mut keystore, TEST_PASSWORD).unwrap();

        let ks = guard.keystore_mut();

        let account = ks.derive_coin::<AtomAddress>(&coin_info).unwrap().clone();

        let signed_tx: AtomTxOutput = ks.sign_transaction("COSMOS", &account.address, &tx)?;

        assert_eq!(signed_tx.signature, "355fWQ00dYitAZj6+EmnAgYEX1g7QtUrX/kQIqCbv05TCz0dfsWcMgXWVnr1l/I2hrjjQkiLRMoeRrmnqT2CZA==");

        Ok(())
    }
}
