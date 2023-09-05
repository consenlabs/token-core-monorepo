pub mod address;
pub mod signer;
pub mod transaction;

pub mod cosmos {
    use tcx_chain::{Account, Keystore};
    use tcx_constants::{CoinInfo, CurveType};

    pub const CHAINS: [&'static str; 1] = ["COSMOS"];

    pub type Address = crate::address::AtomAddress;
    pub type TransactionInput = crate::transaction::AtomTxInput;
    pub type TransactionOutput = crate::transaction::AtomTxOutput;

    pub fn enable_account(
        _: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<crate::address::AtomAddress>(&[CoinInfo {
            coin: "COSMOS".to_string(),
            derivation_path: format!("m/44'/118'/{}'/0/0", index),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        }])
    }
}
