use std::{fmt, str::FromStr};

use crate::curve::CurveType;
use crate::Result;
use failure::format_err;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub enum Coin {
    Ethereum { path: String, chain_id: i32 },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainType {
    Bitcoin,
    Omni,
    Ethereum,
    Eos,
    Cosmos,
    Polkadot,
    Kusama,
    Tezos,
    Tron,
    Nervos,
    BitcoinCash,
    LiteCoin,
    FileCoin,
}

impl FromStr for ChainType {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<ChainType, Self::Err> {
        match input {
            "BITCOIN" => Ok(ChainType::Bitcoin),
            "OMNI" => Ok(ChainType::Omni),
            "ETHEREUM" => Ok(ChainType::Ethereum),
            "EOS" => Ok(ChainType::Eos),
            "COSMOS" => Ok(ChainType::Cosmos),
            "POLKADOT" => Ok(ChainType::Polkadot),
            "KUSAMA" => Ok(ChainType::Kusama),
            "TEZOS" => Ok(ChainType::Tezos),
            "TRON" => Ok(ChainType::Tron),
            "NERVOS" => Ok(ChainType::Nervos),
            "BITCOINCASH" => Ok(ChainType::BitcoinCash),
            "LITECOIN" => Ok(ChainType::LiteCoin),
            "FILECOIN" => Ok(ChainType::FileCoin),
            _ => Err(format_err!("unknown_chain_type")),
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let chain_type_str = match self {
            ChainType::Bitcoin => "BITCOIN",
            ChainType::Omni => "OMNI",
            ChainType::Ethereum => "ETHEREUM",
            ChainType::Eos => "EOS",
            ChainType::Cosmos => "COSMOS",
            ChainType::Polkadot => "POLKADOT",
            ChainType::Kusama => "KUSAMA",
            ChainType::Tezos => "TEZOS",
            ChainType::Tron => "TRON",
            ChainType::Nervos => "NERVOS",
            ChainType::BitcoinCash => "BITCOINCASH",
            ChainType::LiteCoin => "LITECOIN",
            ChainType::FileCoin => "FILECOIN",
        };
        write!(f, "{}", chain_type_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DerivationPath {
    BitcoinLegacy,
    BitcoinLegacyTestnet,
    BitcoinP2wpkh,
    BitcoinP2wpkhTestnet,
    BitcoinSegWit,
    BitcoinSegWitTestnet,
    BitcoinP2tr,
    BitcoinP2trTestnet,
    Ethereum,
    Eos,
    Cosmos,
    Polkadot,
    Kusama,
    Tezos,
    Tron,
    Nervos,
    BitcoinCash,
    LiteCoin,
    LiteCoinP2wpkh,
    FileCoin,
    FileCoinBls,
    Custom(String),
}

impl FromStr for DerivationPath {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<DerivationPath, Self::Err> {
        match input {
            "m/44'/0'/0'/0/0" => Ok(DerivationPath::BitcoinLegacy),
            "m/44'/1'/0'/0/0" => Ok(DerivationPath::BitcoinLegacyTestnet),
            "m/49'/0'/0'/0/0" => Ok(DerivationPath::BitcoinP2wpkh),
            "m/49'/1'/0'/0/0" => Ok(DerivationPath::BitcoinP2wpkhTestnet),
            "m/84'/0'/0'/0/0" => Ok(DerivationPath::BitcoinSegWit),
            "m/84'/1'/0'/0/0" => Ok(DerivationPath::BitcoinSegWitTestnet),
            "m/86'/0'/0'/0/0" => Ok(DerivationPath::BitcoinP2tr),
            "m/86'/1'/0'/0/0" => Ok(DerivationPath::BitcoinP2trTestnet),
            "m/44'/145'/0'/0/0" => Ok(DerivationPath::BitcoinCash),
            "m/44'/2'/0'/0/0" => Ok(DerivationPath::LiteCoin),
            "m/44'/195'/0'/0/0" => Ok(DerivationPath::Tron),
            "m/44'/309'/0'/0/0" => Ok(DerivationPath::Nervos),
            "//polkadot//imToken/0" => Ok(DerivationPath::Polkadot),
            "//kusama//imToken/0" => Ok(DerivationPath::Kusama),
            "m/44'/1729'/0'/0'" => Ok(DerivationPath::Tezos),
            "m/44'/461'/0'/0/0" => Ok(DerivationPath::FileCoin),
            "m/2334/461/0/0" => Ok(DerivationPath::FileCoinBls),
            "m/44'/60'/0'/0/0" => Ok(DerivationPath::Ethereum),
            "m/44'/118'/0'/0/0" => Ok(DerivationPath::Cosmos),
            "m/44'/194'/0'/0/0" => Ok(DerivationPath::Eos),
            path => Ok(DerivationPath::Custom(path.to_string())),
        }
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let derivation_path_str = match self {
            DerivationPath::BitcoinLegacy => "m/44'/0'/0'/0/0",
            DerivationPath::BitcoinLegacyTestnet => "m/44'/1'/0'/0/0",
            DerivationPath::BitcoinP2wpkh => "m/49'/0'/0'/0/0",
            DerivationPath::BitcoinP2wpkhTestnet => "m/49'/1'/0'/0/0",
            DerivationPath::BitcoinSegWit => "m/84'/0'/0'/0/0",
            DerivationPath::BitcoinSegWitTestnet => "m/84'/1'/0'/0/0",
            DerivationPath::BitcoinP2tr => "m/86'/0'/0'/0/0",
            DerivationPath::BitcoinP2trTestnet => "m/86'/1'/0'/0/0",
            DerivationPath::BitcoinCash => "m/44'/145'/0'/0/0",
            DerivationPath::LiteCoin => "m/44'/2'/0'/0/0",
            DerivationPath::LiteCoinP2wpkh => "m/49'/2'/0'/0/0",
            DerivationPath::Tron => "m/44'/195'/0'/0/0",
            DerivationPath::Nervos => "m/44'/309'/0'/0/0",
            DerivationPath::Polkadot => "//polkadot//imToken/0",
            DerivationPath::Kusama => "//kusama//imToken/0",
            DerivationPath::Tezos => "m/44'/1729'/0'/0'",
            DerivationPath::FileCoin => "m/44'/461'/0'/0/0",
            DerivationPath::FileCoinBls => "m/2334/461/0/0",
            DerivationPath::Ethereum => "m/44'/60'/0'/0/0",
            DerivationPath::Cosmos => "m/44'/118'/0'/0/0",
            DerivationPath::Eos => "m/44'/194'/0'/0/0",
            DerivationPath::Custom(path) => path,
        };
        write!(f, "{}", derivation_path_str)
    }
}

#[derive(Clone)]
pub struct CoinInfo {
    pub coin: ChainType,
    pub curve: CurveType,
    pub derivation_path: Option<DerivationPath>,
    pub network: Option<Network>,
    pub seg_wit: Option<SegWit>,
}

impl Default for CoinInfo {
    fn default() -> Self {
        CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::Custom("".to_string())),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::None),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Network {
    Mainnet,
    Testnet,
}

impl FromStr for Network {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<Network, Self::Err> {
        match input {
            "MAINNET" => Ok(Network::Mainnet),
            "TESTNET" => Ok(Network::Testnet),
            _ => Err(format_err!("unknown_source")),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Network::Mainnet => write!(f, "MAINNET"),
            Network::Testnet => write!(f, "TESTNET"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SegWit {
    None,
    P2wpkh,
    SegWit,
    P2tr,
}

impl FromStr for SegWit {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<SegWit, Self::Err> {
        match input {
            "NONE" => Ok(SegWit::None),
            "P2WPKH" => Ok(SegWit::P2wpkh),
            "SEGWIT" => Ok(SegWit::SegWit),
            "P2tr" => Ok(SegWit::P2tr),
            _ => Err(format_err!("unknown_seg_wit")),
        }
    }
}

impl fmt::Display for SegWit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SegWit::None => write!(f, "NONE"),
            SegWit::P2wpkh => write!(f, "P2WPKH"),
            SegWit::SegWit => write!(f, "SEGWIT"),
            SegWit::P2tr => write!(f, "P2TR"),
            _ => write!(f, "unknown_seg_wit"),
        }
    }
}

lazy_static! {
    static ref COIN_INFOS: RwLock<Vec<CoinInfo>> = {
        let mut coin_infos = Vec::new();
        // chain is bitcoin, coin is btc
        coin_infos.push(CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::BitcoinLegacy),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: Some(SegWit::None),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::BitcoinLegacyTestnet),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::None),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::BitcoinP2wpkh),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: Some(SegWit::P2wpkh),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::BitcoinP2wpkhTestnet),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::P2wpkh),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::BitcoinSegWit),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: Some(SegWit::SegWit),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::BitcoinSegWitTestnet),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::SegWit),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::BitcoinP2tr),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: Some(SegWit::P2tr),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Bitcoin,
            derivation_path: Some(DerivationPath::BitcoinP2trTestnet),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::P2tr),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::BitcoinCash,
            derivation_path: Some(DerivationPath::BitcoinCash),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: Some(SegWit::None),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::BitcoinCash,
            derivation_path: Some(DerivationPath::BitcoinLegacyTestnet),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::None),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::LiteCoin,
            derivation_path: Some(DerivationPath::LiteCoin),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: Some(SegWit::None),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::LiteCoin,
            derivation_path: Some(DerivationPath::BitcoinLegacyTestnet),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::None),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::LiteCoin,
            derivation_path: Some(DerivationPath::LiteCoinP2wpkh),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: Some(SegWit::P2wpkh),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::LiteCoin,
            derivation_path: Some(DerivationPath::BitcoinP2wpkhTestnet),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::P2wpkh),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Tron,
            derivation_path: Some(DerivationPath::Tron),
            curve: CurveType::SECP256k1,
            network: None,
            seg_wit: None,
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Nervos,
            derivation_path: Some(DerivationPath::Nervos),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: Some(SegWit::None),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Nervos,
            derivation_path: Some(DerivationPath::Nervos),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: Some(SegWit::None),
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Polkadot,
            derivation_path: Some(DerivationPath::Polkadot),
            curve: CurveType::SubSr25519,
            network: None,
            seg_wit: None,
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Kusama,
            derivation_path: Some(DerivationPath::Kusama),
            curve: CurveType::SubSr25519,
            network: None,
            seg_wit: None,
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Tezos,
            derivation_path: Some(DerivationPath::Tezos),
            curve: CurveType::ED25519,
            network: Some(Network::Mainnet),
            seg_wit: None,
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::FileCoin,
            derivation_path: Some(DerivationPath::FileCoin),
            curve: CurveType::SECP256k1,
            network: Some(Network::Mainnet),
            seg_wit: None,
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::FileCoin,
            derivation_path: Some(DerivationPath::FileCoin),
            curve: CurveType::SECP256k1,
            network: Some(Network::Testnet),
            seg_wit: None,
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::FileCoin,
            derivation_path: Some(DerivationPath::FileCoinBls),
            curve: CurveType::BLS,
            network: Some(Network::Mainnet),
            seg_wit: None,
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::FileCoin,
            derivation_path: Some(DerivationPath::FileCoinBls),
            curve: CurveType::BLS,
            network: Some(Network::Testnet),
            seg_wit: None,
        });
        coin_infos.push(CoinInfo {
            coin: ChainType::Ethereum,
            derivation_path: Some(DerivationPath::Ethereum),
            curve: CurveType::SECP256k1,
            network: None,
            seg_wit: None,
        });

        coin_infos.push(CoinInfo {
            coin: ChainType::Cosmos,
            derivation_path: Some(DerivationPath::Cosmos),
            curve: CurveType::SECP256k1,
            network: None,
            seg_wit: None,
        });

        coin_infos.push(CoinInfo {
            coin: ChainType::Eos,
            derivation_path: Some(DerivationPath::Eos),
            curve: CurveType::SECP256k1,
            network: None,
            seg_wit: None,
        });

        RwLock::new(coin_infos)
    };
}

pub fn coin_info_from_param(
    chain_type: &str,
    network: &str,
    seg_wit: &str,
    curve: &str,
) -> Result<CoinInfo> {
    let coin_infos = COIN_INFOS.read();
    let mut coins = coin_infos
        .iter()
        .filter(|x| {
            x.coin.to_string() == chain_type.to_uppercase()
                && (network.is_empty()
                    || x.network.and_then(|net| Some(net.to_string()))
                        == Some(network.to_uppercase()))
                && (seg_wit.is_empty()
                    || x.seg_wit.and_then(|seg_wit| Some(seg_wit.to_string()))
                        == Some(seg_wit.to_uppercase()))
                && (x.curve.to_string() == curve)
        })
        .map(|x| x.clone())
        .collect::<Vec<CoinInfo>>();

    if coins.is_empty() {
        Err(format_err!("unsupported_chain"))
    } else {
        Ok(coins.pop().expect("coin_info_from_param"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_str() {
        assert_ne!("Mainnet", Network::Mainnet.to_string());
        assert_eq!("MAINNET", Network::Mainnet.to_string());
    }
}
