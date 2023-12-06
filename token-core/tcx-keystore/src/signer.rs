use crate::{Keystore, Result};
use tcx_constants::CurveType;

#[derive(Debug, Clone, PartialEq)]
pub struct SignatureParameters {
    pub curve: CurveType,
    pub derivation_path: String,
    pub chain_type: String,
    pub network: String,
    pub seg_wit: String,
}

impl Default for SignatureParameters {
    fn default() -> Self {
        SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "".to_string(),
            chain_type: "".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        }
    }
}

pub trait TransactionSigner<Input, Output> {
    fn sign_transaction(&mut self, params: &SignatureParameters, tx: &Input) -> Result<Output>;
}

//pub trait Message: Sized {}
//pub trait SignedMessage: Sized {}
pub trait MessageSigner<Input, Output> {
    fn sign_message(&mut self, params: &SignatureParameters, message: &Input) -> Result<Output>;
}

// The ec_sign
pub trait HashSigner {
    fn sign(&self, ks: &mut Keystore, symbol: &str, address: &str, hash: &[u8]) -> Result<Vec<u8>>;
}

pub trait Signer {
    fn sign_hash(
        &mut self,
        hash: &[u8],
        derivation_path: &str,
        curve: &str,
        sig_alg: &str,
    ) -> Result<Vec<u8>>;

    fn secp256k1_ecdsa_sign_recoverable(
        &mut self,
        hash: &[u8],
        derivation_path: &str,
    ) -> Result<Vec<u8>>;

    fn bls_sign(&mut self, hash: &[u8], derivation_path: &str) -> Result<Vec<u8>>;

    fn bls_sign_specified_alg(
        &mut self,
        hash: &[u8],
        derivation_path: &str,
        sig_alg: &str,
    ) -> Result<Vec<u8>>;

    fn schnorr_sign(&mut self, hash: &[u8], derivation_path: &str) -> Result<Vec<u8>>;
}

pub trait ChainSigner {
    fn sign_recoverable_hash(
        &mut self,
        data: &[u8],
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<Vec<u8>>;

    fn sign_hash(
        &mut self,
        data: &[u8],
        curve: CurveType,
        derivation_path: &str,
    ) -> Result<Vec<u8>>;

    fn sign_specified_hash(
        &mut self,
        data: &[u8],
        curve: CurveType,
        derivation_path: &str,
        dst: &str,
    ) -> Result<Vec<u8>>;
}
