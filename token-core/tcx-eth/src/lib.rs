pub mod address;
pub mod signer;
pub mod transaction;

pub mod api;

use core::result;

pub type Result<T> = result::Result<T, failure::Error>;

pub mod ethereum {
    use crate::address::EthAddress;

    pub const CHAINS: [&str; 1] = ["ETHEREUM"];

    pub type Address = EthAddress;
    pub type TransactionInput = crate::api::EthTxInput;
    pub type TransactionOutput = crate::api::EthTxOutput;
    pub type MessageInput = crate::api::EthMessageInput;
    pub type MessageOutput = crate::api::EthMessageOutput;
}
