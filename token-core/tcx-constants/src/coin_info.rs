use crate::curve::CurveType;
use crate::Result;
use failure::format_err;
use tcx_common::FromHex;

use parking_lot::RwLock;

pub fn get_xpub_prefix(network: &str, derivation_path: &str) -> Vec<u8> {
    if derivation_path.starts_with("m/49'") {
        if network == "MAINNET" {
            Vec::from_hex("049d7cb2").unwrap()
        } else {
            Vec::from_hex("044a5262").unwrap()
        }
    } else if derivation_path.starts_with("m/84'") {
        if network == "MAINNET" {
            Vec::from_hex("04b24746").unwrap()
        } else {
            Vec::from_hex("045f1cf6").unwrap()
        }
    } else {
        if network == "MAINNET" {
            Vec::from_hex("0488b21e").unwrap()
        } else {
            Vec::from_hex("043587cf").unwrap()
        }
    }
}
/// Blockchain basic config
#[derive(Clone)]
pub struct CoinInfo {
    pub coin: String,
    pub derivation_path: String,
    pub curve: CurveType,
    pub network: String,
    pub seg_wit: String,
}

impl Default for CoinInfo {
    fn default() -> Self {
        CoinInfo {
            coin: "".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        }
    }
}

lazy_static! {
    static ref COIN_INFOS: RwLock<Vec<CoinInfo>> = {
        let coin_infos = vec![
            CoinInfo {
                coin: "BITCOIN".to_string(),
                derivation_path: "m/44'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "BITCOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "BITCOIN".to_string(),
                derivation_path: "m/49'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            },
            CoinInfo {
                coin: "BITCOIN".to_string(),
                derivation_path: "m/49'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            },
            CoinInfo {
                coin: "BITCOIN".to_string(),
                derivation_path: "m/84'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
            },
            CoinInfo {
                coin: "BITCOIN".to_string(),
                derivation_path: "m/84'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
            },
            CoinInfo {
                coin: "BITCOIN".to_string(),
                derivation_path: "m/86'/0'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
            },
            CoinInfo {
                coin: "BITCOIN".to_string(),
                derivation_path: "m/86'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
            },
            CoinInfo {
                coin: "BITCOINCASH".to_string(),
                derivation_path: "m/44'/145'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "BITCOINCASH".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "LITECOIN".to_string(),
                derivation_path: "m/44'/2'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "LITECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "LITECOIN".to_string(),
                derivation_path: "m/49'/2'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            },
            CoinInfo {
                coin: "LITECOIN".to_string(),
                derivation_path: "m/49'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            },
            CoinInfo {
                coin: "TRON".to_string(),
                derivation_path: "m/44'/195'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "NERVOS".to_string(),
                derivation_path: "m/44'/309'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "NERVOS".to_string(),
                derivation_path: "m/44'/309'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "POLKADOT".to_string(),
                derivation_path: "//polkadot//imToken/0".to_string(),
                curve: CurveType::SR25519,
                network: "".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "KUSAMA".to_string(),
                derivation_path: "//kusama//imToken/0".to_string(),
                curve: CurveType::SR25519,
                network: "".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "TEZOS".to_string(),
                derivation_path: "m/44'/1729'/0'/0'".to_string(),
                curve: CurveType::ED25519,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "FILECOIN".to_string(),
                derivation_path: "m/44'/461'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "FILECOIN".to_string(),
                derivation_path: "m/44'/461'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "FILECOIN".to_string(),
                derivation_path: "m/2334/461/0/0".to_string(),
                curve: CurveType::BLS,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "FILECOIN".to_string(),
                derivation_path: "m/2334/461/0/0".to_string(),
                curve: CurveType::BLS,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "ETHEREUM".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "ETHEREUM".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "COSMOS".to_string(),
                derivation_path: "m/44'/118'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "EOS".to_string(),
                derivation_path: "m/44'/194'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
        ];

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
            x.coin.as_str() == chain_type
                && (x.network.as_str() == network || network.is_empty())
                && (x.seg_wit.as_str() == seg_wit || seg_wit.is_empty())
                && (x.curve.as_str() == curve || curve.is_empty())
        })
        .cloned()
        .collect::<Vec<CoinInfo>>();

    if coins.is_empty() {
        Err(format_err!("unsupported_chain"))
    } else {
        Ok(coins.pop().expect("coin_info_from_param"))
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_coin_info_default() {
        let coin_info = super::CoinInfo::default();
        assert_eq!(coin_info.coin, "");
        assert_eq!(coin_info.derivation_path, "");
        assert_eq!(coin_info.curve, super::CurveType::SECP256k1);
        assert_eq!(coin_info.network, "");
        assert_eq!(coin_info.seg_wit, "");
    }

    #[test]
    fn test_coin_info_from_param_unsupported_chain() {
        let coin_info = super::coin_info_from_param("TEST", "MAINNET", "NONE", "secp256k1");
        assert_eq!(coin_info.err().unwrap().to_string(), "unsupported_chain");
    }

    #[test]
    fn test_coin_info_from_param() {
        let coin_info =
            super::coin_info_from_param("BITCOIN", "MAINNET", "NONE", "secp256k1").unwrap();

        assert_eq!(coin_info.coin, "BITCOIN");
        assert_eq!(coin_info.derivation_path, "m/44'/0'/0'/0/0");
        assert_eq!(coin_info.curve, super::CurveType::SECP256k1);
        assert_eq!(coin_info.network, "MAINNET");
        assert_eq!(coin_info.seg_wit, "NONE");
    }
}
