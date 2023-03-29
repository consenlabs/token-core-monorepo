use lazy_static::lazy_static;
use ssz_rs::prelude::*;
use ssz_rs::{Node, Vector};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

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
    static ref CAPELLA_FORK_VERSION: Version =
        Vector::<u8, DOMAIN_TYPE_LEN>::deserialize(&[0x03, 0, 0, 0])
            .expect("failed to deserialize");
    static ref GENESIS_VALIDATORS_ROOT: [u8; 32] =
        "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".as_bytes()[0..32]
            .try_into()
            .expect("could not wrap genesis validators root");
    // FIXME: use the real testnet genesis_validators_root
    static ref GENESIS_VALIDATORS_ROOT_STUB: [u8; 32] =
        "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".as_bytes()[0..32]
            .try_into()
            .expect("could not wrap genesis validators root");
    static ref GENESIS_VALIDATOR_ROOT: HashMap<String, Node> = HashMap::from([
        (
            "mainnet".to_owned(),
            Node::from_bytes(GENESIS_VALIDATORS_ROOT.to_owned())
        ),
        (
            "prater".to_owned(),
            Node::from_bytes(GENESIS_VALIDATORS_ROOT_STUB.to_owned())
        ),
        (
            "goerli".to_owned(),
            Node::from_bytes(GENESIS_VALIDATORS_ROOT_STUB.to_owned())
        ),
    ]);
}

impl BLSToExecutionRequest {
    pub fn generate_bls_to_execution_change_hash(&self) -> tcx_constants::Result<String> {
        let to_execution_address_bytes = hex::decode(&self.to_execution_address)?;
        let to_execution_address =
            Vector::<u8, EXECUTION_ADDR_LEN>::deserialize(to_execution_address_bytes.as_ref())?;
        let from_bls_pubkey_bytes = hex::decode(&self.from_bls_pubkey)?;
        let from_bls_pubkey =
            Vector::<u8, BLS_PUBKEY_LEN>::deserialize(from_bls_pubkey_bytes.as_ref())?;
        let validator_index = self.validator_index;
        println!(
            "to_execution_address-->{}",
            hex::encode(to_execution_address.clone())
        );
        println!("from_bls_pubkey-->{}", hex::encode(from_bls_pubkey.clone()));
        println!("validator_index-->{}", validator_index);
        let message = BLSToExecutionChange {
            validator_index,
            from_bls_pubkey,
            to_execution_address,
        };
        let fork_version = Vector::<u8, DOMAIN_TYPE_LEN>::deserialize(
            hex::decode(&self.genesis_fork_version.strip_prefix("0x").unwrap())?.as_slice(),
        )?;
        // hex::decode(&self.genesis_validators_root)?.as_slice();
        let validator_root =
            Node::try_from(hex::decode(&self.genesis_validators_root)?.as_slice())?;
        // let validator_root = self.genesis_validators_root.as_bytes()[0..32].try_into()?;
        // let domain = compute_domain(
        //     &DOMAIN_BLS_TO_EXECUTION_CHANGE,
        //     fork_version,
        //     &validator_root,
        // )?;
        let domain = Domain::try_from(hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )?)?;
        println!("domain-->{}", hex::encode(domain.clone().as_ref()));
        let signing_root = compute_signing_root(message.clone(), domain)?;
        println!("signing_root-->{}", hex::encode(signing_root.as_bytes()));
        let message = signing_root.as_bytes();
        Ok(hex::encode(message))
    }
}

pub fn compute_domain(
    domain_type: &DomainType,
    fork_version: Version,
    genesis_validators_root: &Node,
) -> Result<Domain, MerkleizationError> {
    if domain_type.len() != 4 {
        //todo
    }
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
    println!("message-->{}", hex::encode(ssz_object.hash_tree_root()?));
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
