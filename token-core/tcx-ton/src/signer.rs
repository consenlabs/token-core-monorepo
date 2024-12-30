use crate::transaction::{TonRawTxIn, TonTxOut};
use anyhow::anyhow;
use tcx_common::{FromHex, ToHex as OtherToHex};
use tcx_constants::Result;
use tcx_keystore::{
    Keystore, SignatureParameters, Signer, TransactionSigner as TraitTransactionSigner,
};

impl TraitTransactionSigner<TonRawTxIn, TonTxOut> for Keystore {
    fn sign_transaction(
        &mut self,
        params: &SignatureParameters,
        tx: &TonRawTxIn,
    ) -> Result<TonTxOut> {
        if tx.hash.is_empty() {
            return Err(anyhow!("invalid_sign_hash"));
        }

        let path_parts = params.derivation_path.split('/').collect::<Vec<_>>();
        if path_parts.len() < 4 || path_parts[2] != "607'" {
            return Err(anyhow!("invalid_sign_path"));
        }

        let hash = Vec::from_hex_auto(&tx.hash)?;
        let sig = self.ed25519_sign(&hash.to_vec(), &params.derivation_path)?;

        Ok(TonTxOut {
            signature: sig.to_0x_hex(),
        })
    }
}

#[cfg(test)]
mod test_super {
    use crate::transaction::TonRawTxIn;
    use tcx_constants::{CoinInfo, CurveType, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{HdKeystore, Keystore, Metadata, SignatureParameters, TransactionSigner};

    #[test]
    fn test_ton_sign() {
        let hd =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let path = "m/44'/607'/0'".to_string();
        let coin = CoinInfo {
            coin: "TON".to_string(),
            derivation_path: path.clone(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            contract_code: "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=".to_string(),
        };

        let mut keystore = Keystore::Hd(hd);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!(
            "UQDBKGsYs49NgdqM4gMoiVMV9Re5hM-yy3nvR_4XB0ZbUMd7",
            acc.address
        );

        let tx_in = TonRawTxIn {
            hash: "0xd356774c21d6a6e2c651a5255f3f876fa973f1cfb7dce941c14ecabc2b1511d0".to_string(),
        };

        let param = SignatureParameters {
            curve: CurveType::ED25519,
            derivation_path: path.clone(),
            chain_type: "TON".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };

        let sign_ret = keystore.sign_transaction(&param, &tx_in).unwrap();
        assert_eq!(sign_ret.signature, "0x9771c1bf4c69630b69cc0f0ae38db635f4ff1d161badc0f70b257b5a8f6a387cd75b72361ebf67fc5803feccdbb22ade85d053d766ed3b7c7029509363990c02");
    }

    #[test]
    fn test_exception_case() {
        let hd =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let mut keystore = Keystore::Hd(hd);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();

        let tx_in = TonRawTxIn {
            hash: "".to_string(),
        };

        let param = SignatureParameters {
            curve: CurveType::ED25519,
            derivation_path: "m/44'/607'/0'".to_string(),
            chain_type: "TON".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };

        let sign_ret = keystore.sign_transaction(&param, &tx_in);
        assert!(sign_ret.is_err());

        let param = SignatureParameters {
            curve: CurveType::ED25519,
            derivation_path: "m/44'/607/0'".to_string(),
            chain_type: "TON".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };
        let tx_in = TonRawTxIn {
            hash: "0xd356774c21d6a6e2c651a5255f3f876fa973f1cfb7dce941c14ecabc2b1511d0".to_string(),
        };
        let sign_ret = keystore.sign_transaction(&param, &tx_in);
        assert!(sign_ret.is_err());
    }
}
