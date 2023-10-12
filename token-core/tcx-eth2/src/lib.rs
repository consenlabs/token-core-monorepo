extern crate core;

pub mod address;
mod bls_to_execution_change;
pub mod signer;
pub mod transaction;
use failure::Fail;
use tcx_keystore::Result;

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_hex_value")]
    InvalidHexValue,
    #[fail(display = "invalid_eth_address")]
    InvalidEthAddress,
}

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    let result = if value.starts_with("0x") || value.starts_with("0X") {
        hex::decode(&value[2..])
    } else {
        hex::decode(&value[..])
    };
    result.map_err(|_| Error::InvalidHexValue.into())
}

pub mod ethereum2 {
    use crate::address::Eth2Address;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{Account, Keystore};

    pub const CHAINS: [&'static str; 1] = ["ETHEREUM2"];

    pub type Address = Eth2Address;
    //   pub type TransactionInput = crate::transaction::EthTxInput;
    //  pub type TransactionOutput = crate::transaction::EthTxOutput;

    pub fn enable_account(
        _: &str,
        _: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<Address>(&[
            CoinInfo {
                coin: "ETHEREUM2".to_string(),
                derivation_path: format!("m/12381/3600/0/0"),
                curve: CurveType::BLS,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "ETHEREUM2".to_string(),
                derivation_path: format!("m/12381/3600/0/0"),
                curve: CurveType::BLS,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
            },
        ])
    }
}
