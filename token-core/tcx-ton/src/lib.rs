pub mod address;
pub mod signer;
pub mod transaction;

pub mod ton {
    pub const CHAINS: [&str; 1] = ["TON"];

    pub type Address = crate::address::TonAddress;
    pub type TransactionInput = crate::transaction::TonRawTxIn;
    pub type TransactionOutput = crate::transaction::TonTxOut;
}
