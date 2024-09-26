use crate::transaction::{TonRawTxIn, TonTxOut};
use tonlib_core::cell::CellParser;
// use crate::{PAYLOAD_HASH_THRESHOLD, SIGNATURE_TYPE_SR25519};
// use sp_core::blake2_256;

use tcx_common::{FromHex, ToHex};
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
        let raw_data_bytes = if tx.raw_data.starts_with("0x") {
            tx.raw_data[2..].to_string()
        } else {
            tx.raw_data.clone()
        };
        let raw_data_bytes = Vec::from_hex(raw_data_bytes)?;
        // CellParser::new()

        let sig = self.sr25519_sign(&hash, &params.derivation_path)?;

        let sig_with_type = [vec![SIGNATURE_TYPE_SR25519], sig].concat();

        let tx_out = TonTxOut {
            signature: sig_with_type.to_0x_hex(),
        };
        Ok(tx_out)
    }
}

#[cfg(test)]
mod test_super {
    use super::*;
    use tcx_common::ToHex;

    #[test]
    fn test_payload_hash() {
        let test_cases = vec![
            ("imToken", "696d546f6b656e"),
            ("super long sentence: 0x891D85380A227e5a8443bd0f39bDedBB6DA798830x891D85380A227e5a8443bd0f39bDedBB6DA798830x891D85380A227e5a8443bd0f39bDedBB6DA798830x891D85380A227e5a8443bd0f39bDedBB6DA798830x891D85380A227e5a8443bd0f39bDedBB6DA79883 0x891D85380A227e5a8443bd0f39bDedBB6DA798830x891D85380A227e5a8443bd0f39bDedBB6DA798830x891D85380A227e5a8443bd0f39bDedBB6DA798830x891D85380A227e5a8443bd0f39bDedBB6DA798830x891D85380A227e5a8443bd0f39bDedBB6DA79883", "32c9e41866cb31a30fa2caf28f1b35b1cc8f526bb5765b54f410c68bd59ee7a2"),
        ];
        for case in test_cases {
            let hash = hash_unsigned_payload(case.0.as_bytes()).unwrap();
            assert_eq!(case.1, hash.to_hex());
        }
    }
}
