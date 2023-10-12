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
use tcx_keystore::{Address, Keystore};
use tcx_primitive::{
    Bip32DeterministicPublicKey, Derive, DeterministicPublicKey, FromHex, TypedPublicKey,
};
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

pub mod bitcoin {
    use crate::{BtcKinAddress, BITCOIN, LITECOIN};
    use tcx_constants::CoinInfo;
    use tcx_keystore::{Account, Keystore};

    pub const CHAINS: [&'static str; 2] = [BITCOIN, LITECOIN];

    pub type Address = crate::BtcKinAddress;
    pub type TransactionInput = crate::transaction::BtcKinTxInput;
    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;

    pub fn enable_account(
        coin: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        let coin_type = match coin {
            BITCOIN => 0,
            LITECOIN => 2,
            _ => Err(format_err!("unsupported coin"))?,
        };

        keystore.derive_coins::<BtcKinAddress>(&[
            CoinInfo {
                coin: coin.to_string(),
                derivation_path: format!("m/44'/{}'/{}'/0/0", coin_type, index),
                curve: tcx_constants::CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: coin.to_string(),
                derivation_path: format!("m/49'/{}'/{}'/0/0", coin_type, index),
                curve: tcx_constants::CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            },
            CoinInfo {
                coin: coin.to_string(),
                derivation_path: format!("m/84'/{}'/{}'/0/0", coin_type, index),
                curve: tcx_constants::CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "SEGWIT".to_string(),
            },
            CoinInfo {
                coin: coin.to_string(),
                derivation_path: format!("m/86'/{}'/{}'/0/0", coin_type, index),
                curve: tcx_constants::CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "P2TR".to_string(),
            },
            CoinInfo {
                coin: coin.to_string(),
                derivation_path: format!("m/44'/1'/{}'/0/0", index),
                curve: tcx_constants::CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: coin.to_string(),
                derivation_path: format!("m/49'/1'/{}'/0/0", index),
                curve: tcx_constants::CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            },
            CoinInfo {
                coin: coin.to_string(),
                derivation_path: format!("m/84'/1'/{}'/0/0", index),
                curve: tcx_constants::CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "SEGWIT".to_string(),
            },
            CoinInfo {
                coin: coin.to_string(),
                derivation_path: format!("m/86'/1'/{}'/0/0", coin_type),
                curve: tcx_constants::CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "P2TR".to_string(),
            },
        ])
    }
}

pub fn calc_btc_change_address(
    ks: &Keystore,
    seg_wit: &str,
    network: &str,
    external_idx: u32,
) -> Result<(String, String)> {
    let account = ks
        .accounts()
        .iter()
        .find(|x| x.coin == "BITCOIN" && x.seg_wit == seg_wit && x.network == network);
    let Some(acc) = account else {
        return Err(format_err!("wallet_not_found"));
    };

    let xpub = acc.ext_pub_key.to_string();
    let acc_path = acc.derivation_path.to_string();
    let external_path = format!("0/{}", external_idx);
    let change_path = format!("{}/{}", acc_path, external_path);
    let account_xpub = Bip32DeterministicPublicKey::from_hex(&xpub)?;
    let public_key = account_xpub.derive(&change_path)?.public_key();
    let typed_pk = TypedPublicKey::Secp256k1(public_key);
    let address = BtcKinAddress::from_public_key(&typed_pk, &acc.coin_info())?;
    Ok((address.to_string(), external_path))
}

pub mod bitcoincash {
    use crate::BITCOINCASH;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{Account, Keystore};

    pub static CHAINS: [&'static str; 1] = [BITCOINCASH];

    pub type Address = crate::BchAddress;

    pub type TransactionInput = crate::transaction::BtcKinTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;

    pub fn enable_account(
        _: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<crate::BchAddress>(&[
            CoinInfo {
                coin: BITCOINCASH.to_string(),
                derivation_path: format!("m/44'/145'/{}'/0/0", index),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: BITCOINCASH.to_string(),
                derivation_path: format!("m/44'/1'/{}'/0/0", index),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
        ])
    }
}

pub mod omni {
    use crate::OMNI;

    pub static CHAINS: [&'static str; 1] = [OMNI];

    pub type Address = crate::BtcKinAddress;

    pub type TransactionInput = crate::transaction::OmniTxInput;

    pub type TransactionOutput = crate::transaction::BtcKinTxOutput;
}

#[cfg(test)]
mod tests {
    use crate::BchAddress;

    use serde_json::Value;

    use tcx_constants::CurveType;
    use tcx_constants::{CoinInfo, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::KeystoreGuard;
    use tcx_keystore::{HdKeystore, Keystore, Metadata};

    const BIP_PATH: &str = "m/44'/145'/0'";

    #[test]
    fn bch_create() {
        let mut meta = Metadata::default();
        meta.name = "CreateTest".to_string();

        let mut keystore = Keystore::Hd(HdKeystore::new(TEST_PASSWORD, meta));

        let bch_coin = CoinInfo {
            coin: "BITCOINCASH".to_string(),
            derivation_path: BIP_PATH.to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let mut guard = KeystoreGuard::unlock_by_password(&mut keystore, TEST_PASSWORD).unwrap();

        let _ = guard
            .keystore_mut()
            .derive_coin::<BchAddress>(&bch_coin)
            .unwrap();

        let json_str = guard.keystore_mut().to_json();
        let v: Value = serde_json::from_str(&json_str).unwrap();

        let active_accounts = v["activeAccounts"].as_array().unwrap();
        assert_eq!(1, active_accounts.len());
        let account = active_accounts.first().unwrap();
        let address = account["address"].as_str().unwrap();
        assert!(!address.is_empty());
        let path = account["derivationPath"].as_str().unwrap();
        assert_eq!(BIP_PATH, path);
        let coin = account["coin"].as_str().unwrap();
        assert_eq!("BITCOINCASH", coin);
    }

    #[test]
    fn bch_recover() {
        let mut meta = Metadata::default();
        meta.name = "RecoverTest".to_string();

        let mut keystore =
            Keystore::Hd(HdKeystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, meta).unwrap());

        let bch_coin = CoinInfo {
            coin: "BITCOINCASH".to_string(),
            derivation_path: BIP_PATH.to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };

        let mut guard = KeystoreGuard::unlock_by_password(&mut keystore, TEST_PASSWORD).unwrap();

        let _ = guard
            .keystore_mut()
            .derive_coin::<BchAddress>(&bch_coin)
            .unwrap();
        let json_str = guard.keystore_mut().to_json();
        let v: Value = serde_json::from_str(&json_str).unwrap();

        let active_accounts = v["activeAccounts"].as_array().unwrap();
        assert_eq!(1, active_accounts.len());
        let account = active_accounts.first().unwrap();
        let address = account["address"].as_str().unwrap();

        assert_eq!("qqyta3mqzeaxe8hqcdsgpy4srwd4f0fc0gj0njf885", address);

        let path = account["derivationPath"].as_str().unwrap();
        assert_eq!(BIP_PATH, path);
        let coin = account["coin"].as_str().unwrap();
        assert_eq!("BITCOINCASH", coin);
    }
}
