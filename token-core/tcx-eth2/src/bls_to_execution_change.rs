use lazy_static::lazy_static;
use ssz_rs::prelude::*;
use ssz_rs::{Node, Vector};
use std::convert::TryFrom;
use tcx_common::FromHex;

const DOMAIN_LEN: usize = 32;
const DOMAIN_TYPE_LEN: usize = 4;
const BLS_PUBKEY_LEN: usize = 48;
const EXECUTION_ADDR_LEN: usize = 20;
type DomainType = Vector<u8, DOMAIN_TYPE_LEN>;
type Domain = Vector<u8, DOMAIN_LEN>;
type Version = Vector<u8, 4>;
type BLSPubkey = Vector<u8, BLS_PUBKEY_LEN>;
type ExecutionAddress = Vector<u8, EXECUTION_ADDR_LEN>;

lazy_static! {
    static ref DOMAIN_BLS_TO_EXECUTION_CHANGE: DomainType =
        Vector::<u8, DOMAIN_TYPE_LEN>::deserialize(&[0x0A, 0, 0, 0])
            .expect("failed to deserialize");
}

impl BLSToExecutionRequest {
    pub fn generate_bls_to_execution_change_hash(&self) -> tcx_constants::Result<String> {
        let to_execution_address_bytes = Vec::from_hex_auto(&self.to_execution_address)?;
        let to_execution_address =
            Vector::<u8, EXECUTION_ADDR_LEN>::deserialize(to_execution_address_bytes.as_ref())?;
        let from_bls_pubkey_bytes = Vec::from_hex_auto(&self.from_bls_pubkey)?;
        let from_bls_pubkey =
            Vector::<u8, BLS_PUBKEY_LEN>::deserialize(from_bls_pubkey_bytes.as_ref())?;
        let validator_index = self.validator_index;
        let message = BLSToExecutionChange {
            validator_index,
            from_bls_pubkey,
            to_execution_address,
        };

        let fork_version = Vector::<u8, DOMAIN_TYPE_LEN>::deserialize(
            Vec::from_hex_auto(&self.genesis_fork_version)?.as_slice(),
        )?;
        let validator_root =
            Node::try_from(Vec::from_hex_auto(&self.genesis_validators_root)?.as_slice())?;
        let domain = compute_domain(
            &DOMAIN_BLS_TO_EXECUTION_CHANGE,
            fork_version,
            &validator_root,
        )?;
        let signing_root = compute_signing_root(message.clone(), domain)?;
        let message = format!("{:x}", signing_root);
        Ok(message)
    }
}

pub fn compute_domain(
    domain_type: &DomainType,
    fork_version: Version,
    genesis_validators_root: &Node,
) -> Result<Domain, MerkleizationError> {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)?;
    let mut bytes = Vec::new();
    domain_type.serialize(&mut bytes)?;
    fork_data_root.serialize(&mut bytes)?;
    Ok(Vector::deserialize(&bytes[0..DOMAIN_LEN]).expect("invalid domain data"))
}

pub fn compute_fork_data_root(
    current_version: Version,
    genesis_validators_root: &Node,
) -> Result<Node, MerkleizationError> {
    ForkData {
        current_version,
        genesis_validators_root: genesis_validators_root.to_owned(),
    }
    .hash_tree_root()
}

pub fn compute_signing_root<T: SimpleSerialize>(
    mut ssz_object: T,
    domain: Domain,
) -> Result<Node, MerkleizationError> {
    SigningData {
        object_root: ssz_object.hash_tree_root()?,
        domain,
    }
    .hash_tree_root()
}

#[derive(SimpleSerialize, Default)]
pub struct ForkData {
    current_version: Version,
    genesis_validators_root: Node,
}

#[derive(SimpleSerialize, Default)]
pub struct SigningData {
    object_root: Node,
    domain: Domain,
}

#[derive(SimpleSerialize, Default, Clone, Debug)]
pub struct BLSToExecutionChange {
    validator_index: u32,
    from_bls_pubkey: BLSPubkey,
    to_execution_address: ExecutionAddress,
}

#[derive(Clone)]
pub struct BLSToExecutionRequest {
    pub genesis_fork_version: String,
    pub genesis_validators_root: String,
    pub validator_index: u32,
    pub from_bls_pubkey: String,
    pub to_execution_address: String,
}

#[cfg(test)]
mod test {
    use crate::bls_to_execution_change::BLSToExecutionRequest;

    #[test]
    fn test_generate_bls_to_execution_change_hash() {
        let bls_to_execution_request = BLSToExecutionRequest {
            genesis_fork_version: "0x03000000".to_string(),
            genesis_validators_root: "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_string(),
            validator_index: 0,
            from_bls_pubkey: "0x99b1f1d84d76185466d86c34bde1101316afddae76217aa86cd066979b19858c2c9d9e56eebc1e067ac54277a61790db".to_string(),
            to_execution_address: "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15".to_string(),
        };
        let ret_data = bls_to_execution_request
            .generate_bls_to_execution_change_hash()
            .expect("generate_bls_to_execution_change_hash_error");
        assert_eq!(
            ret_data,
            "23ba0fe9dc5d2fae789f31fdccb4e28e74b89aec26bafdd6c96ced598542f53e"
        );
    }
}
