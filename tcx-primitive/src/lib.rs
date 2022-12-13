#[macro_use]
extern crate failure;

mod bip32;
mod bls;
mod bls_derive;
mod constant;
mod derive;
mod ecc;
mod ed25519;
mod ed25519_bip32;
mod rand;
mod secp256k1;
mod sr25519;
mod subkey;

use core::result;

pub type Result<T> = result::Result<T, failure::Error>;

pub use crate::bip32::{Bip32DeterministicPrivateKey, Bip32DeterministicPublicKey};
pub use crate::derive::{get_account_path, Derive, DeriveJunction, DerivePath};
pub use crate::ecc::{
    DeterministicPrivateKey, DeterministicPublicKey, PrivateKey, PublicKey,
    TypedDeterministicPrivateKey, TypedDeterministicPublicKey, TypedPrivateKey,
    TypedPrivateKeyDisplay, TypedPublicKey,
};
pub use crate::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
pub use crate::rand::generate_mnemonic;
pub use crate::secp256k1::{
    private_key_without_version, verify_private_key, Secp256k1PrivateKey, Secp256k1PublicKey,
};
pub use crate::sr25519::{Sr25519PrivateKey, Sr25519PublicKey};

/// Key that can be encoded to/from SS58.
pub trait Ss58Codec: Sized {
    /// Some if the string is a properly encoded SS58Check address.
    fn from_ss58check(s: &str) -> Result<Self> {
        let (parsed, _) = Self::from_ss58check_with_version(s)?;
        Ok(parsed)
    }
    /// Some if the string is a properly encoded SS58Check address.
    fn from_ss58check_with_version(s: &str) -> Result<(Self, Vec<u8>)>;

    /// Return the ss58-check string for this key.
    fn to_ss58check_with_version(&self, version: &[u8]) -> String;
}

pub trait ToHex: Sized {
    fn to_hex(&self) -> String;
}

pub trait FromHex: Sized {
    fn from_hex(hex: &str) -> Result<Self>;
}
