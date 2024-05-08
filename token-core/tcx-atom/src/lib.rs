pub mod address;
pub mod signer;
pub mod transaction;

pub mod cosmos {
    pub const CHAINS: [&str; 1] = ["COSMOS"];

    pub type Address = crate::address::AtomAddress;
    pub type TransactionInput = crate::transaction::AtomTxInput;
    pub type TransactionOutput = crate::transaction::AtomTxOutput;
}
