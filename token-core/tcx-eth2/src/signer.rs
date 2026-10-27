use crate::bls_to_execution_change::BLSToExecutionRequest;
use crate::transaction::{
    BlsToExecutionChangeMessage, SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult,
    SignedBlsToExecutionChange,
};
use crate::Error;
use tcx_common::{FromHex, ToHex};
use tcx_constants::{CoinInfo, CurveType};
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

        let signing_pubkey = keystore.get_public_key(CurveType::BLS, "m/12381/3600/0/0")?;
        if Vec::from_hex_auto(&self.from_bls_pub_key)? != signing_pubkey.to_bytes() {
            return Err(anyhow::anyhow!("public_key_mismatch"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::Metadata;

    #[test]
    fn withdrawal_change_binds_claimed_pubkey_to_signing_key() {
        let mut keystore =
            Keystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let actual = keystore
            .get_public_key(CurveType::BLS, "m/12381/3600/0/0")
            .unwrap();
        let mut params = SignBlsToExecutionChangeParam {
            genesis_fork_version: "00000000".to_string(),
            genesis_validators_root: "00".repeat(32),
            validator_index: vec![1, 2],
            from_bls_pub_key: actual.to_bytes().to_hex(),
            eth1_withdrawal_address: "0x0000000000000000000000000000000000000001".to_string(),
            ..Default::default()
        };
        assert_eq!(
            params
                .sign_bls_to_execution_change(&mut keystore)
                .unwrap()
                .signeds
                .len(),
            2
        );
        params.from_bls_pub_key = keystore
            .get_public_key(CurveType::BLS, "m/12381/3600/1/0")
            .unwrap()
            .to_bytes()
            .to_hex();
        assert_eq!(
            params
                .sign_bls_to_execution_change(&mut keystore)
                .unwrap_err()
                .to_string(),
            "public_key_mismatch"
        );
        params.from_bls_pub_key = "00".repeat(48);
        assert_eq!(
            params
                .sign_bls_to_execution_change(&mut keystore)
                .unwrap_err()
                .to_string(),
            "public_key_mismatch"
        );
    }
}
