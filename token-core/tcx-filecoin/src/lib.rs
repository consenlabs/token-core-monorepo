use failure::Fail;

mod address;
mod key_info;
mod signer;
mod transaction;
mod utils;

pub use crate::address::FilecoinAddress;
pub use crate::key_info::KeyInfo;
pub use crate::transaction::{SignedMessage, UnsignedMessage};
#[macro_use]
extern crate failure;

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_curve_type")]
    InvalidCurveType,

    #[fail(display = "cannot_found_account")]
    CannotFoundAccount,

    #[fail(display = "invalid_address")]
    InvalidAddress,

    #[fail(display = "invalid_format")]
    InvalidFormat,

    #[fail(display = "invalid_param")]
    InvalidParam,

    #[fail(display = "invalid_number")]
    InvalidNumber,
}

pub mod filecoin {
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{Account, Keystore};

    pub static CHAINS: [&'static str; 1] = ["FILECOIN"];

    pub type Address = crate::FilecoinAddress;

    pub type TransactionInput = crate::UnsignedMessage;

    pub type TransactionOutput = crate::SignedMessage;

    pub fn enable_account(
        _: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<Address>(&[
            CoinInfo {
                coin: "FILECOIN".to_string(),
                derivation_path: format!("m/44'/461'/{}'/0/0", index),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "FILECOIN".to_string(),
                derivation_path: "m/44'/461'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
            },
        ])
    }
}
