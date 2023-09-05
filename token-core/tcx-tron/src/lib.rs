pub mod address;
pub mod signer;
pub mod transaction;

pub use crate::address::TronAddress;

use sha3::{Digest, Keccak256};

pub fn keccak(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub mod tron {
    use tcx_chain::{Account, Keystore};
    use tcx_constants::{CoinInfo, CurveType};

    pub const CHAINS: [&'static str; 1] = ["TRON"];

    pub type Address = crate::address::TronAddress;
    pub type TransactionInput = crate::transaction::TronTxInput;
    pub type TransactionOutput = crate::transaction::TronTxOutput;

    pub type MessageInput = crate::transaction::TronMessageInput;

    pub type MessageOutput = crate::transaction::TronMessageOutput;

    pub fn enable_account(
        coin: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<Address>(&[CoinInfo {
            coin: "TRON".to_string(),
            derivation_path: "m/44'/195'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        }])
    }
}
