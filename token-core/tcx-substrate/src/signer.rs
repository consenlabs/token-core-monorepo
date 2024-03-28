use crate::transaction::{SubstrateRawTxIn, SubstrateTxOut};
use crate::{PAYLOAD_HASH_THRESHOLD, SIGNATURE_TYPE_SR25519};
use sp_core::blake2_256;

use tcx_common::{FromHex, ToHex};
use tcx_constants::Result;
use tcx_keystore::{
    Keystore, SignatureParameters, Signer, TransactionSigner as TraitTransactionSigner,
};

// Ref: https://github.com/paritytech/txwrapper-core/blob/8c7c9e16ab877f0247e547ee6368e22e5579b492/packages/txwrapper-core/src/core/construct/createSigningPayload.ts#L37-L42
pub(crate) fn hash_unsigned_payload(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > PAYLOAD_HASH_THRESHOLD {
        Ok(blake2_256(payload).to_vec())
    } else {
        Ok(payload.to_vec())
    }
}

impl TraitTransactionSigner<SubstrateRawTxIn, SubstrateTxOut> for Keystore {
    fn sign_transaction(
        &mut self,
        params: &SignatureParameters,
        tx: &SubstrateRawTxIn,
    ) -> Result<SubstrateTxOut> {
        let raw_data_bytes = if tx.raw_data.starts_with("0x") {
            tx.raw_data[2..].to_string()
        } else {
            tx.raw_data.clone()
        };
        let raw_data_bytes = Vec::from_hex(raw_data_bytes)?;
        let hash = hash_unsigned_payload(&raw_data_bytes)?;

        let sig = self.sr25519_sign(&hash, &params.derivation_path)?;

        let sig_with_type = [vec![SIGNATURE_TYPE_SR25519], sig].concat();

        let tx_out = SubstrateTxOut {
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
