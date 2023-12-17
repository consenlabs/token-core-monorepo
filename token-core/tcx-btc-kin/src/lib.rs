#![feature(let_chains)]

pub mod address;
pub mod bch_address;
mod bitcoin_cash_sighash;
mod sighash;

pub mod network;
pub mod signer;
pub mod transaction;

use core::result;

#[macro_use]
extern crate failure;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;

#[macro_use]
extern crate tcx_keystore;
extern crate core;

pub type Result<T> = result::Result<T, failure::Error>;

pub use address::{BtcKinAddress, WIFDisplay};
pub use bch_address::BchAddress;
pub use network::BtcKinNetwork;
use tcx_constants::{CoinInfo, CurveType};
use tcx_keystore::Address;
use tcx_primitive::{Bip32DeterministicPublicKey, Derive, DeterministicPublicKey, TypedPublicKey};
pub use transaction::{BtcKinTxInput, BtcKinTxOutput, OmniTxInput, Utxo};

pub const BITCOIN: &'static str = "BITCOIN";
pub const BITCOINCASH: &'static str = "BITCOINCASH";

pub const LITECOIN: &'static str = "LITECOIN";

pub const OMNI: &'static str = "OMNI";

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
    #[fail(display = "bch_convert_to_legacy_address_failed# address: {}", _0)]
    ConvertToLegacyAddressFailed(String),
    #[fail(display = "bch_convert_to_cash_address_failed# address: {}", _0)]
    ConvertToCashAddressFailed(String),
    #[fail(display = "construct_bch_address_failed# address: {}", _0)]
    ConstructBchAddressFailed(String),
    #[fail(display = "unsupported_taproot")]
    UnsupportedTaproot,
}

pub fn derive_sub_accounts(
    seg_wit: &str,
    network: &str,
    relative_paths: &Vec<String>,
    xpub: &Bip32DeterministicPublicKey,
) -> Result<Vec<String>> {
    // let acc_path = get_account_path(path)?;
    // let change_path = format!("{}/{}", acc_path, relative_path);
    // TODO: test derive from relative path?
    let coin = CoinInfo {
        coin: BITCOIN.to_string(),
        derivation_path: "".to_string(),
        curve: CurveType::SECP256k1,
        network: network.to_string(),
        seg_wit: seg_wit.to_string(),
    };

    let addresses_ret: Vec<Result<String>> = relative_paths
        .iter()
        .map(|path| {
            let public_key = xpub.derive(path)?.public_key();
            let typed_pk = TypedPublicKey::Secp256k1(public_key);

            let addr = BtcKinAddress::from_public_key(&typed_pk, &coin)?.to_string();
            Ok(addr)
        })
        .collect();
    let addresses: Result<Vec<String>> = addresses_ret.into_iter().collect();

    addresses
}

pub mod bitcoin {
    use crate::{BITCOIN, LITECOIN};
    pub const CHAINS: [&'static str; 2] = [BITCOIN, LITECOIN];
    pub type Address = crate::BtcKinAddress;
    pub type TransactionInput = crate::transaction::BtcKinTxInput;
    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}

pub mod bitcoincash {
    use crate::BITCOINCASH;

    pub static CHAINS: [&'static str; 1] = [BITCOINCASH];

    pub type Address = crate::BchAddress;

    pub type TransactionInput = crate::transaction::BtcKinTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}

pub mod omni {
    use crate::OMNI;

    pub static CHAINS: [&'static str; 1] = [OMNI];

    pub type Address = crate::BtcKinAddress;

    pub type TransactionInput = crate::transaction::OmniTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}
