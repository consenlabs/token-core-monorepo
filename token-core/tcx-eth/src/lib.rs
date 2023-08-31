pub mod address;
pub mod migration;
pub mod signer;
pub mod transaction;

use core::result;

pub type Result<T> = result::Result<T, failure::Error>;

pub mod ethereum {
    use crate::address::EthAddress;
    use tcx_chain::{Account, Keystore};
    use tcx_constants::{CoinInfo, CurveType};

    pub const CHAINS: [&'static str; 1] = ["ETHEREUM"];

    pub type Address = EthAddress;
    //   pub type TransactionInput = crate::transaction::EthTxInput;
    //  pub type TransactionOutput = crate::transaction::EthTxOutput;

    pub fn enable_account(
        _: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<EthAddress>(&[CoinInfo {
            coin: "ETHEREUM".to_string(),
            derivation_path: format!("m/44'/60'/{}'/0/0", index),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        }])
    }
}
