pub mod address;
pub mod signer;
pub mod transaction;

pub use crate::address::TronAddress;

pub mod tron {
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{Account, Keystore};

    pub const CHAINS: [&'static str; 1] = ["TRON"];

    pub type Address = crate::address::TronAddress;
    pub type TransactionInput = crate::transaction::TronTxInput;
    pub type TransactionOutput = crate::transaction::TronTxOutput;

    pub type MessageInput = crate::transaction::TronMessageInput;

    pub type MessageOutput = crate::transaction::TronMessageOutput;

    pub fn enable_account(
        _: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<Address>(&[CoinInfo {
            coin: "TRON".to_string(),
            derivation_path: format!("m/44'/195'/{}'/0/0", index),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        }])
    }
}
