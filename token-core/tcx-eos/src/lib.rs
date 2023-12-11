pub mod address;
pub mod chain_factory;
pub mod signer;
pub mod transaction;
pub use chain_factory::EosChainFactory;

pub mod eos {

    pub const CHAINS: [&'static str; 1] = ["EOS"];

    pub type Address = crate::address::EosAddress;
    pub type TransactionInput = crate::transaction::EosTxInput;
    pub type TransactionOutput = crate::transaction::EosTxOutput;

    pub type MessageInput = crate::transaction::EosMessageInput;

    pub type MessageOutput = crate::transaction::EosMessageOutput;
}
