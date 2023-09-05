pub mod address;
pub mod chain_factory;
pub mod signer;
pub mod transaction;
pub use chain_factory::EosChainFactory;

pub mod eos {
    use tcx_chain::{Account, Keystore};
    use tcx_constants::{CoinInfo, CurveType};

    pub const CHAINS: [&'static str; 1] = ["EOS"];

    pub type Address = crate::address::EosAddress;
    pub type TransactionInput = crate::transaction::EosTxInput;
    pub type TransactionOutput = crate::transaction::EosTxOutput;

    pub type MessageInput = crate::transaction::EosMessageInput;

    pub type MessageOutput = crate::transaction::EosMessageOutput;

    pub fn enable_account(
        _: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<Address>(&[CoinInfo {
            coin: "EOS".to_string(),
            derivation_path: format!("m/44'/194'/{}'/0/0", index),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        }])
    }
}
