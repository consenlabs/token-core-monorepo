use crate::bls_to_execution_change::{compute_domain, BLSToExecutionRequest};
use crate::transaction::{
    BlsToExecutionChangeMessage, SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult,
    SignedBlsToExecutionChange,
};
use crate::{hex_to_bytes, Error, Result};
use ssz_rs::{Deserialize, Vector};
use tcx_chain::{
    ChainSigner, Keystore, KeystoreGuard, TransactionSigner as TraitTransactionSigner,
};

impl SignBlsToExecutionChangeParam {
    pub fn sign_bls_to_execution_change(
        &self,
        keystore: &mut Keystore,
    ) -> Result<SignBlsToExecutionChangeResult> {
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
