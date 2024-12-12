use tcx_common::sha256;
use tcx_common::{FromHex, ToHex as OtherToHex};
use tcx_constants::Result;
use tcx_keystore::{
    Keystore, SignatureParameters, Signer, TransactionSigner as TraitTransactionSigner,
};

use crate::transaction::{TonRawTxIn, TonTxOut};

impl TraitTransactionSigner<TonRawTxIn, TonTxOut> for Keystore {
    fn sign_transaction(
        &mut self,
        params: &SignatureParameters,
        tx: &TonRawTxIn,
    ) -> Result<TonTxOut> {
        let raw_data = Vec::from_hex_auto(&tx.raw_data)?;
        let hash = sha256(&raw_data);

        let sig = self.ed25519_sign(&hash.to_vec(), &params.derivation_path)?;

        Ok(TonTxOut {
            signature: sig.to_0x_hex(),
        })
    }
}

#[cfg(test)]
mod test_super {
    use tcx_common::ToHex;
    use tcx_constants::{CoinInfo, CurveType, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{HdKeystore, Keystore, Metadata, SignatureParameters, TransactionSigner};

    use crate::transaction::TonRawTxIn;

    #[test]
    fn test_nacl_sign() {
        let hd =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let path = "m/44'/607'/0'/0'/0'".to_string();
        let coin = CoinInfo {
            coin: "TON".to_string(),
            // todo: the ton path is not official
            derivation_path: "m/44'/607'/0'/0'/0'".to_string(),
            curve: CurveType::ED25519,
            network: "".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
        };

        let mut keystore = Keystore::Hd(hd);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!(
            "EQCKJfmBlnFiINcL1MoCjuyxULXaOEA-k5iHcr4L18RuhQHo",
            acc.address
        );
        let sec_key = keystore.get_private_key(CurveType::ED25519, &path).unwrap();
        assert_eq!(
            sec_key.to_bytes().to_hex(),
            "34815c96ad2434988d86a01e4b639acf41e8ecac7eeb260635b8a47028bbefd3"
        );

        let tx_in = TonRawTxIn {
            raw_data: "".to_string(),
        };

        let param = SignatureParameters {
            curve: CurveType::ED25519,
            derivation_path: path.to_string(),
            chain_type: "TON".to_string(),
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
        };

        let sign_ret = keystore.sign_transaction(&param, &tx_in).unwrap();
        assert_eq!(sign_ret.signature, "");
    }
}
