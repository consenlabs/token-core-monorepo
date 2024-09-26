use anyhow::anyhow;
use core::str::FromStr;
use tonlib_core::mnemonic::KeyPair;
use tonlib_core::wallet::{TonWallet, WalletVersion};

// use bech32::{FromBase32, ToBase32, Variant};
use tcx_common::{ripemd160, sha256};
use tcx_constants::CoinInfo;
use tcx_keystore::{Address, Result};
use tcx_primitive::TypedPublicKey;

// size of address
pub const LENGTH: usize = 20;

#[derive(PartialEq, Eq, Clone)]
pub struct TonAddress(String);

impl Address for TonAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self> {
        let pub_key_bytes = public_key.to_bytes();
        let key_pair = KeyPair {
            public_key: pub_key_bytes.clone(),
            secret_key: Vec::new(),
        };

        let wallet = TonWallet::derive_default(WalletVersion::V4R2, &key_pair)?;
        // wallet.sign_external_body()

        Ok(TonAddress(wallet.address.to_string()))
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        tonlib_core::TonAddress::from_str(address).is_ok()
    }
}

impl FromStr for TonAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(TonAddress(s.to_string()))
    }
}

impl ToString for TonAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}
