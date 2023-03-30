use crate::bls_to_execution_change::{compute_domain, BLSToExecutionRequest};
use crate::transaction::{
    BlsToExecutionChangeMessage, SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult,
    SignedBlsToExecutionChange,
};
use ssz_rs::{Deserialize, Vector};
use tcx_chain::{
    ChainSigner, Keystore, KeystoreGuard, TransactionSigner as TraitTransactionSigner,
};

impl SignBlsToExecutionChangeParam {
    pub fn sign_bls_to_execution_change(
        &self,
        keystore: &mut Keystore,
    ) -> tcx_constants::Result<SignBlsToExecutionChangeResult> {
        let mut blsToExecutionRequest = BLSToExecutionRequest {
            genesis_fork_version: self.genesis_fork_version.to_string(),
            genesis_validators_root: self.genesis_validators_root.to_string(),
            validator_index: 0,
            from_bls_pubkey: self.from_bls_pub_key.to_string(),
            to_execution_address: self.eth1_withdrawal_address.to_string(),
        };
        let mut signeds = vec![];
        for validator_index in &self.validator_index {
            blsToExecutionRequest.validator_index = *validator_index;
            let message = blsToExecutionRequest.generate_bls_to_execution_change_hash()?;

            let signature = keystore.sign_hash(
                hex::decode(message)?.as_slice(),
                "ETHEREUM2",
                self.from_bls_pub_key.as_str(),
                None,
            )?;
            let blsToExecutionChangeMessage = BlsToExecutionChangeMessage {
                validator_index: *validator_index,
                from_bls_pubkey: self.from_bls_pub_key.to_string(),
                to_execution_address: self.eth1_withdrawal_address.to_string(),
            };
            let signedBlsToExecutionChange = SignedBlsToExecutionChange {
                message: Some(blsToExecutionChangeMessage),
                signature: hex::encode(signature),
            };
            signeds.push(signedBlsToExecutionChange);
        }

        let signBlsToExecutionChangeResult = SignBlsToExecutionChangeResult { signeds };
        Ok(signBlsToExecutionChangeResult)
    }
}

#[cfg(test)]
mod test {
    use crate::transaction::SignBlsToExecutionChangeParam;
    use tcx_chain::Keystore;

    #[test]
    fn test() {
        let signBlsToExecutionChangeParam = SignBlsToExecutionChangeParam{
            id: "import_result.id".to_string(),
            password: "TEST_PASSWORD".to_string(),
            genesis_fork_version: "0x03000000".to_string(),
            genesis_validators_root: "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_string(),
            validator_index: vec![100],
            from_bls_pub_key: "0x8478fed8676e9e5d0376c2da97a9e2d67ff5aa11b312aca7856b29f595fcf2c5909c8bafce82f46d9888cd18f780e302".to_string(),
            eth1_withdrawal_address: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F".to_string()
        };
        // signBlsToExecutionChangeParam.sign_bls_to_execution_change2();
    }
}
