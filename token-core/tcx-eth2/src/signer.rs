use crate::bls_to_execution_change::BLSToExecutionRequest;
use crate::transaction::{
    BlsToExecutionChangeMessage, SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult,
    SignedBlsToExecutionChange,
};
use crate::Error;
use keccak_hash;
use regex::Regex;
use tcx_common::{FromHex, ToHex};
use tcx_constants::CoinInfo;
use tcx_eth::address::EthAddress;
use tcx_keystore::{Address, Keystore, Result, Signer};

impl SignBlsToExecutionChangeParam {
    pub fn sign_bls_to_execution_change(
        &self,
        keystore: &mut Keystore,
    ) -> Result<SignBlsToExecutionChangeResult> {
        let valid_result =
            EthAddress::is_valid(self.eth1_withdrawal_address.as_str(), &CoinInfo::default());
        if !valid_result {
            return Err(Error::InvalidEthAddress.into());
        }

        let mut bls_to_execution_request = BLSToExecutionRequest {
            genesis_fork_version: self.genesis_fork_version.to_string(),
            genesis_validators_root: self.genesis_validators_root.to_string(),
            validator_index: 0,
            from_bls_pubkey: self.from_bls_pub_key.to_string(),
            to_execution_address: self.eth1_withdrawal_address.to_string(),
        };
        let mut signeds = vec![];
        for validator_index in &self.validator_index {
            bls_to_execution_request.validator_index = *validator_index;
            let message = bls_to_execution_request.generate_bls_to_execution_change_hash()?;

            let signature = keystore.bls_sign(
                Vec::from_hex_auto(&message)?.as_slice(),
                "m/12381/3600/0/0",
                "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
            )?;
            let bls_to_execution_change_message = BlsToExecutionChangeMessage {
                validator_index: *validator_index,
                from_bls_pubkey: self.from_bls_pub_key.to_string(),
                to_execution_address: self.eth1_withdrawal_address.to_string(),
            };
            signeds.push(SignedBlsToExecutionChange {
                message: Some(bls_to_execution_change_message),
                signature: signature.to_hex(),
            });
        }

        Ok(SignBlsToExecutionChangeResult { signeds })
    }
}
