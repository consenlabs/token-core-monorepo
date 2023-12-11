pub mod address;
pub mod signer;
pub mod transaction;

pub use crate::address::TronAddress;

pub mod tron {

    pub const CHAINS: [&'static str; 1] = ["TRON"];

    pub type Address = crate::address::TronAddress;
    pub type TransactionInput = crate::transaction::TronTxInput;
    pub type TransactionOutput = crate::transaction::TronTxOutput;

    pub type MessageInput = crate::transaction::TronMessageInput;

    pub type MessageOutput = crate::transaction::TronMessageOutput;
}
