//! TokenCore Chain
//! This is an abstract package to define basic chain data structures.
#[cfg_attr(tarpaulin, skip)]
#[macro_use]
mod macros {
    #[macro_export]
    macro_rules! tcx_ensure {
        ($cond:expr, $e:expr) => {
            if !($cond) {
                return Err($e.into());
            }
        };
    }
}

use core::result;

#[macro_use]
extern crate failure;
extern crate regex;

pub mod keystore;
mod signer;

pub use keystore::{
    key_hash_from_mnemonic, key_hash_from_private_key, Account, Address, HdKeystore, Keystore,
    KeystoreGuard, Metadata, PrivateKeystore, Source,
};

pub use signer::{ChainSigner, HashSigner, MessageSigner, TransactionSigner};

pub type Result<T> = result::Result<T, failure::Error>;

pub trait PublicKeyEncoder {
    fn encode(&self, public_key: &[u8]) -> Result<String>;
}

pub struct HexPublicKeyEncoder();

impl PublicKeyEncoder for HexPublicKeyEncoder {
    fn encode(&self, public_key: &[u8]) -> Result<String> {
        Ok(hex::encode(public_key))
    }
}

pub trait PrivateKeyEncoder {
    fn encode(&self, private_key: &[u8]) -> Result<String>;
    fn decode(&self, private_key_str: &str) -> Result<Vec<u8>>;
}

pub struct HexPrivateKeyEncoder();

impl PrivateKeyEncoder for HexPrivateKeyEncoder {
    fn encode(&self, private_key: &[u8]) -> Result<String> {
        Ok(tcx_crypto::hex::bytes_to_hex(private_key))
    }

    fn decode(&self, private_key_str: &str) -> Result<Vec<u8>> {
        tcx_crypto::hex::hex_to_bytes(private_key_str)
    }
}

pub trait ChainFactory {
    fn create_public_key_encoder(&self) -> Box<dyn PublicKeyEncoder>;
    fn create_hash_signer(&self) -> Box<dyn HashSigner> {
        unimplemented!()
    }
}
