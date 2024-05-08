pub mod address;
pub mod signer;
pub mod transaction_types;

pub mod transaction;

use core::result;

pub type Result<T> = result::Result<T, anyhow::Error>;

pub mod ethereum {
    use crate::address::EthAddress;

    pub const CHAINS: [&str; 1] = ["ETHEREUM"];

    pub type Address = EthAddress;
    pub type TransactionInput = crate::transaction::EthTxInput;
    pub type TransactionOutput = crate::transaction::EthTxOutput;
    pub type MessageInput = crate::transaction::EthMessageInput;
    pub type MessageOutput = crate::transaction::EthMessageOutput;
}
