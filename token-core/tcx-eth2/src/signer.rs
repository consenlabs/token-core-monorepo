use crate::bls_to_execution_change::BLSToExecutionRequest;
use crate::transaction::{
    BlsToExecutionChangeMessage, SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult,
    SignedBlsToExecutionChange,
};
use crate::Error;
use keccak_hash;
use regex::Regex;
use tcx_common::{FromHex, ToHex};
use tcx_keystore::{Keystore, Result, Signer};

impl SignBlsToExecutionChangeParam {
    pub fn sign_bls_to_execution_change(
        &self,
        keystore: &mut Keystore,
    ) -> Result<SignBlsToExecutionChangeResult> {
        let valid_result = is_valid_address(self.eth1_withdrawal_address.as_str())?;
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

fn is_valid_address(address: &str) -> Result<bool> {
    if address.is_empty() || address.len() != 42 || !address.starts_with("0x") {
        return Ok(false);
    }

    let eth_addr_regex = Regex::new(r"^(0x)?[0-9a-fA-F]{40}$").unwrap();
    if !eth_addr_regex.is_match(address.as_ref()) {
        return Ok(false);
    }

    let address_temp = &address[2..];
    let lower_address_bytes = address_temp.to_lowercase();
    let mut hash = [0u8; 32];
    keccak_hash::keccak_256(lower_address_bytes.as_bytes(), &mut hash);
    let hash_str = hash.to_hex();

    for (i, c) in address_temp.chars().enumerate() {
        let char_int = u8::from_str_radix(&hash_str.chars().nth(i).unwrap().to_string(), 16)?;
        if (c.is_uppercase() && char_int <= 7) || (c.is_lowercase() && char_int > 7) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod test {
    use crate::signer::is_valid_address;

    #[test]
    fn test_is_valid_address() {
        let eth_address = "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(true, result);

        let eth_address = "0x52908400098527886E0F7030069857D2E4169EE7";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(true, result);

        let eth_address = "0xde709f2102306220921060314715629080e2fb77";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(true, result);

        let eth_address = "0x8C1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(false, result);

        let eth_address = "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac1500";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(false, result);

        let eth_address = "8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(false, result);

        let eth_address = "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac1*";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(false, result);

        let eth_address = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(true, result);

        let eth_address = "0x80427Ae1f55bCf60ee4CD2db7549b8BC69a74303";
        let result = is_valid_address(eth_address).unwrap();
        assert_eq!(true, result);
    }
}
