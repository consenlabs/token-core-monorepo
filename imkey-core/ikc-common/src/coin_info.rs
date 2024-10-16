use crate::curve::CurveType;
use crate::Result;
use anyhow::anyhow;
use parking_lot::RwLock;

/// Blockchain basic config
///
/// NOTE: Unique key field is `symbol`
#[derive(Clone)]
pub struct CoinInfo {
    pub coin: String,
    pub derivation_path: String,
    pub curve: CurveType,
    pub network: String,
    pub seg_wit: String,
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
                derivation_path: "m/44'/354'/0'/0/0".to_string(),
                curve: CurveType::ED25519,
                network: "".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "KUSAMA".to_string(),
                derivation_path: "m/44'/434'/0'/0/0".to_string(),
                curve: CurveType::ED25519,
                network: "".to_string(),
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
                coin: "ETHEREUM2".to_string(),
                derivation_path: "m/12381/3600/0/0".to_string(),
                curve: CurveType::BLS,
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "ETHEREUM2".to_string(),
                derivation_path: "m/12381/3600/0/0".to_string(),
                curve: CurveType::BLS,
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
            CoinInfo {
                coin: "COSMOS".to_string(),
                derivation_path: "m/44'/118'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "EOS".to_string(),
                derivation_path: "m/44'/194'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
            },
            CoinInfo {
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/3'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            },
            CoinInfo {
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/49'/3'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            },
            CoinInfo {
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/49'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            },
            CoinInfo {
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/84'/3'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
            },
            CoinInfo {
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/84'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
            },
            CoinInfo {
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/86'/3'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
            },
            CoinInfo {
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/86'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
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
        .map(|x| x.clone())
        .collect::<Vec<CoinInfo>>();

    if coins.is_empty() {
        Err(anyhow!("unsupported_chain"))
    } else {
        Ok(coins.pop().expect("coin_info_from_param"))
    }
}
