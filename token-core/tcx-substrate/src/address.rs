use anyhow::anyhow;
use sp_core::crypto::Ss58AddressFormat;
use sp_core::crypto::Ss58Codec;
use sp_core::sr25519::Public;
use std::str::FromStr;
use tcx_constants::{CoinInfo, Result};
use tcx_keystore::Address;
use tcx_primitive::{PublicKey, Sr25519PublicKey, TypedPublicKey};

#[derive(PartialEq, Eq, Clone)]
pub struct SubstrateAddress(String);

impl Address for SubstrateAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self> {
        let sr_pk = Sr25519PublicKey::from_slice(&public_key.to_bytes())?;
        let address = match coin.coin.as_str() {
            "KUSAMA" => sr_pk
                .0
                .to_ss58check_with_version(Ss58AddressFormat::custom(2)),
            "POLKADOT" => sr_pk
                .0
                .to_ss58check_with_version(Ss58AddressFormat::custom(0)),
            _ => return Err(anyhow!("wrong_coin_type")),
        };

        Ok(SubstrateAddress(address))
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        match Public::from_ss58check_with_version(address) {
            Ok((_addr, version)) => match coin.coin.as_str() {
                "KUSAMA" => version == Ss58AddressFormat::custom(2),
                "POLKADOT" => version == Ss58AddressFormat::custom(0),
                _ => false,
            },
            Err(_) => false,
        }
    }
}

impl FromStr for SubstrateAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(SubstrateAddress(s.to_string()))
    }
}

impl ToString for SubstrateAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
mod test_super {
    use super::*;
    use tcx_common::FromHex;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{PrivateKey, Sr25519PrivateKey};

    #[test]
    fn test_address_from_public() {
        let pub_key: Sr25519PublicKey = Sr25519PublicKey::from_hex(
            "50780547322a1ceba67ea8c552c9bc6c686f8698ac9a8cafab7cd15a1db19859",
        )
        .unwrap();
        let typed_key: TypedPublicKey = TypedPublicKey::SR25519(pub_key);

        let coin_infos = vec![
            (
                "12pWV6LvG4iAfNpFNTvvkWy3H9H8wtCkjiXupAzo2BCmPViM",
                CoinInfo {
                    chain_id: "".to_string(),
                    coin: "POLKADOT".to_string(),
                    derivation_path: "//imToken//polakdot/0".to_string(),
                    curve: CurveType::SR25519,
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                },
            ),
            (
                "EPq15Rj2eTcyVdBBXgyWKVta7Zj4FTo7beB3YHPwtPjxEkr",
                CoinInfo {
                    chain_id: "".to_string(),
                    coin: "KUSAMA".to_string(),
                    derivation_path: "//imToken//kusama/0".to_string(),
                    curve: CurveType::SR25519,
                    network: "".to_string(),
                    seg_wit: "".to_string(),
                },
            ),
        ];
        for addr_and_coin in coin_infos {
            let addr = SubstrateAddress::from_public_key(&typed_key, &addr_and_coin.1).unwrap();
            assert_eq!(addr.to_string(), addr_and_coin.0);
        }

        let sec_key_data = &Vec::<u8>::from_hex_auto("00ea01b0116da6ca425c477521fd49cc763988ac403ab560f4022936a18a4341016e7df1f5020068c9b150e0722fea65a264d5fbb342d4af4ddf2f1cdbddf1fd").unwrap();
        let sec_key = Sr25519PrivateKey::from_slice(&sec_key_data).unwrap();
        let pub_key = sec_key.public_key();
        let typed_key = TypedPublicKey::SR25519(pub_key);
        let mut kusama_coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "KUSAMA".to_string(),
            derivation_path: "//imToken//kusama/0".to_string(),
            curve: CurveType::SR25519,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };
        let addr = SubstrateAddress::from_public_key(&typed_key, &kusama_coin_info).unwrap();
        assert_eq!(
            addr.to_string(),
            "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS"
        );

        kusama_coin_info.coin = "ERROR_TYPE".to_string();
        let addr = SubstrateAddress::from_public_key(&typed_key, &kusama_coin_info);
        assert_eq!(addr.err().unwrap().to_string(), "wrong_coin_type");
    }

    #[test]
    fn test_address_is_valid() {
        let mut coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "KUSAMA".to_string(),
            derivation_path: "//imToken//kusama/0".to_string(),
            curve: CurveType::SR25519,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };
        let addresses = vec![
            "FwMF8FdFKxPtt9enzZ2Zf7dJCxiu4HqK6GhRAsKCvbNkSqx",
            "DksmaiRqSAXNqsWvGXDMdr1VqixoYUAALAgCEJ5cPYiwZeE",
            "GksmaDbSL6XX2z8VZzsiiGdEp6qZY4jKQRtTvyqu3T16cW1",
        ];
        for addr in addresses {
            assert!(SubstrateAddress::is_valid(addr, &coin_info));
        }

        coin_info.coin = "POLKADOT".to_string();
        coin_info.derivation_path = "//imToken//polkadot/0".to_string();
        let addresse = "16NhUkUTkYsYRjMD22Sop2DF8MAXUsjPcYtgHF3t1ccmohx1";
        assert!(SubstrateAddress::is_valid(addresse, &coin_info));

        coin_info.coin = "ERROR_COIN_TYPE".to_string();
        assert!(!SubstrateAddress::is_valid(addresse, &coin_info));
    }

    #[test]
    fn test_address_is_invalid() {
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "KUSAMA".to_string(),
            derivation_path: "//imToken//kusama/0".to_string(),
            curve: CurveType::SR25519,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };
        let addresses = vec![
            "3BMEXohjFLZJGBLkCbF9zreee1eJjoM3ZB",
            "17A16QmavnUfCW11DAApiJxp7ARnxN5pGX",
            "0x891D85380A227e5a8443bd0f39bDedBB6DA79883",
        ];
        for addr in addresses {
            assert!(!SubstrateAddress::is_valid(addr, &coin_info));
        }
    }
}
