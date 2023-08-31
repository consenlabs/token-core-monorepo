#![feature(let_chains)]

pub mod address;

pub mod bip143_with_forkid;
pub mod network;
pub mod signer;
pub mod transaction;

use core::result;
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate failure;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;

#[macro_use]
extern crate tcx_chain;
extern crate core;

pub type Result<T> = result::Result<T, failure::Error>;

pub use address::{BtcKinAddress, ScriptPubkey, WIFDisplay};
pub use network::BtcKinNetwork;
pub use transaction::{BtcKinTxInput, BtcKinTxOutput, OmniTxInput, Utxo};

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "decrypt_xpub_error")]
    DecryptXPubError,
    #[fail(display = "unsupported_chain")]
    UnsupportedChain,
    #[fail(display = "missing_network")]
    MissingNetwork,
    #[fail(display = "invalid_utxo")]
    InvalidUtxo,
    #[fail(display = "invalid_address")]
    InvalidAddress,
}

pub mod bitcoin {
    use tcx_chain::{Account, Keystore};
    use tcx_constants::CoinInfo;

    pub const CHAINS: [&'static str; 2] = ["BITCOIN", "LITECOIN"];

    pub type Address = crate::BtcKinAddress;
    pub type TransactionInput = crate::transaction::BtcKinTxInput;
    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;

    pub fn enable_account(
        coin: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        let coin_type = match coin {
            "BITCOIN" => 0,
            "LITECOIN" => 2,
            _ => 1,
        };

        let all_coin_infos = |coin_type: u32| {
            let network = if coin_type == 1 { "TESTNET" } else { "MAINNET" };

            vec![
                CoinInfo {
                    coin: coin.to_string(),
                    derivation_path: format!("m/44'/{}'/{}'/0/0", coin_type, index),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: network.to_string(),
                    seg_wit: "NONE".to_string(),
                },
                CoinInfo {
                    coin: coin.to_string(),
                    derivation_path: format!("m/46'/{}'/{}'/0/0", coin_type, index),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: network.to_string(),
                    seg_wit: "P2WPKH".to_string(),
                },
                CoinInfo {
                    coin: coin.to_string(),
                    derivation_path: format!("m/84'/{}'/{}'/0/0", coin_type, index),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: network.to_string(),
                    seg_wit: "SEGWIT".to_string(),
                },
                CoinInfo {
                    coin: coin.to_string(),
                    derivation_path: format!("m/86'/{}'/{}'/0/0", coin_type, index),
                    curve: tcx_constants::CurveType::SECP256k1,
                    network: network.to_string(),
                    seg_wit: "P2TR".to_string(),
                },
            ]
        };

        let mut accounts =
            keystore.derive_coins::<crate::BtcKinAddress>(&all_coin_infos(coin_type))?;
        accounts
            .extend_from_slice(&keystore.derive_coins::<crate::BtcKinAddress>(&all_coin_infos(1))?);

        Ok(accounts)
    }
}

pub mod omni {
    pub static CHAINS: [&'static str; 1] = ["OMNI"];

    pub type Address = crate::BtcKinAddress;

    pub type TransactionInput = crate::transaction::OmniTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}
