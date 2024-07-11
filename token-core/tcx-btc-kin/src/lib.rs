#![feature(let_chains)]

pub mod address;
pub mod bch_address;
mod bch_sighash;
mod sighash;

pub mod network;
pub mod signer;
pub mod transaction;

mod message;
mod psbt;

use core::result;
use thiserror::Error;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;

#[macro_use]
extern crate tcx_keystore;

pub type Result<T> = result::Result<T, anyhow::Error>;

pub use address::{BtcKinAddress, WIFDisplay};
pub use bch_address::BchAddress;
pub use network::BtcKinNetwork;
pub use psbt::sign_psbt;
pub use transaction::{BtcKinTxInput, BtcKinTxOutput, OmniTxInput, Utxo};

pub const BITCOIN: &str = "BITCOIN";
pub const BITCOINCASH: &str = "BITCOINCASH";

pub const LITECOIN: &str = "LITECOIN";

pub const OMNI: &str = "OMNI";

#[derive(Error, Debug)]
pub enum Error {
    #[error("decrypt_xpub_error")]
    DecryptXPubError,
    #[error("unsupported_chain")]
    UnsupportedChain,
    #[error("missing_network")]
    MissingNetwork,
    #[error("invalid_utxo")]
    InvalidUtxo,
    #[error("invalid_address")]
    InvalidAddress,
    #[error("bch_convert_to_legacy_address_failed# address: {0}")]
    ConvertToLegacyAddressFailed(String),
    #[error("bch_convert_to_cash_address_failed# address: {0}")]
    ConvertToCashAddressFailed(String),
    #[error("construct_bch_address_failed# address: {0}")]
    ConstructBchAddressFailed(String),
    #[error("unsupported_taproot")]
    UnsupportedTaproot,

    #[error("missing_signature")]
    MissingSignature,
}

pub mod bitcoin {
    use crate::{BITCOIN, LITECOIN};
    pub const CHAINS: [&str; 2] = [BITCOIN, LITECOIN];
    pub type Address = crate::BtcKinAddress;
    pub type TransactionInput = crate::transaction::BtcKinTxInput;
    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;

    pub type MessageInput = crate::transaction::BtcMessageInput;

    pub type MessageOutput = crate::transaction::BtcMessageOutput;
}

pub mod bitcoincash {
    use crate::BITCOINCASH;

    pub static CHAINS: [&str; 1] = [BITCOINCASH];

    pub type Address = crate::BchAddress;

    pub type TransactionInput = crate::transaction::BtcKinTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;

    pub type MessageInput = crate::transaction::BtcMessageInput;

    pub type MessageOutput = crate::transaction::BtcMessageOutput;
}

pub mod omni {
    use crate::OMNI;

    pub static CHAINS: [&str; 1] = [OMNI];

    pub type Address = crate::BtcKinAddress;

    pub type TransactionInput = crate::transaction::OmniTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}

#[cfg(test)]
mod tests {
    use tcx_common::ToHex;
    use tcx_constants::{CurveType, TEST_MNEMONIC, TEST_PASSWORD, TEST_WIF};
    use tcx_keystore::{Keystore, Metadata};
    use tcx_primitive::{PrivateKey, Secp256k1PrivateKey};

    pub fn hd_keystore(mnemonic: &str) -> Keystore {
        let mut keystore =
            Keystore::from_mnemonic(mnemonic, TEST_PASSWORD, Metadata::default()).unwrap();
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        keystore
    }

    pub fn private_keystore(wif: &str) -> Keystore {
        let sec_key = Secp256k1PrivateKey::from_wif(wif).unwrap();
        let mut keystore = Keystore::from_private_key(
            &sec_key.to_bytes().to_hex(),
            TEST_PASSWORD,
            CurveType::SECP256k1,
            Metadata::default(),
            None,
        )
        .unwrap();
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        keystore
    }

    pub fn sample_hd_keystore() -> Keystore {
        hd_keystore(TEST_MNEMONIC)
    }

    pub fn hex_keystore(hex: &str) -> Keystore {
        let mut keystore = Keystore::from_private_key(
            hex,
            TEST_PASSWORD,
            CurveType::SECP256k1,
            Metadata::default(),
            None,
        )
        .unwrap();
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        keystore
    }

    pub fn wif_keystore(wif: &str) -> Keystore {
        let hex = Secp256k1PrivateKey::from_wif(wif)
            .unwrap()
            .to_bytes()
            .to_hex();

        hex_keystore(&hex)
    }

    pub fn sample_wif_keystore() -> Keystore {
        wif_keystore(TEST_WIF)
    }
}
