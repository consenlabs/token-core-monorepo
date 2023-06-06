use crate::Error;
use crate::Result;

//chain type definition
pub const CHAIN_TYPE_ETHEREUM: &str = "ETHEREUM";
pub const CHAIN_TYPE_BITCOIN: &str = "BITCOIN";
pub const CHAIN_TYPE_EOS: &str = "EOS";
pub const CHAIN_TYPE_COSMOS: &str = "COSMOS";

pub fn validate(chain_type: &str) -> Result<()> {
    if !CHAIN_TYPE_ETHEREUM.eq_ignore_ascii_case(chain_type)
        && !CHAIN_TYPE_BITCOIN.eq_ignore_ascii_case(chain_type)
        && !CHAIN_TYPE_EOS.eq_ignore_ascii_case(chain_type)
        && !CHAIN_TYPE_COSMOS.eq_ignore_ascii_case(chain_type)
    {
        return Err(Error::NetworkParamsInvalid.into());
    };
    Ok(())
}

//BIP44 path constants
pub const BITCOIN_MAINNET_PATH: &str = "m/44'/0'/0'";
pub const BITCOIN_TESTNET_PATH: &str = "m/44'/1'/0'";
pub const BITCOIN_SEGWIT_MAIN_PATH: &str = "m/49'/0'/0'";
pub const BITCOIN_SEGWIT_TESTNET_PATH: &str = "m/49'/1'/0'";
pub const ETHEREUM_PATH: &str = "m/44'/60'/0'/0/0";
pub const EOS_PATH: &str = "m/44'/194'";
pub const EOS_SLIP48: &str = "m/48'/4'/0'/0'/0',m/48'/4'/1'/0'/0'";
pub const EOS_LEDGER: &str = "m/44'/194'/0'/0/0";
pub const COSMOS_PATH: &str = "m/44'/118'/0'/0/0";
